//! Reading the passwd and group databases, probing for a shell, and the locked append.
//!
//! The parsing and the shell-ordering logic are pure functions over bytes, so they are tested
//! without a filesystem. Only [`append_locked`] and [`FsProbe`] actually touch one.
//!
//! The databases are scanned as **bytes**, never as `str`: nothing guarantees a passwd file is
//! UTF-8 (a Latin-1 GECOS field is common on older images), and refusing to start the container
//! over a comment field this binary never interprets would be the opposite of fail-open. Every
//! field compared here — names, UIDs, GIDs — is ASCII on our side, so a bytewise comparison is
//! exact.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;

use rustix::fs::{FlockOperation, flock};

/// The shells probed for, in order. The first that exists wins; if none do, the field is left
/// empty and `getpwnam` applies its own `/bin/sh` default.
pub const SHELL_CANDIDATES: [&str; 3] = ["/bin/bash", "/bin/zsh", "/bin/sh"];

/// Answers "does this path exist", so the shell ordering can be tested without a filesystem.
pub trait Probe {
    /// Whether `path` names something that exists.
    fn exists(&self, path: &str) -> bool;
}

/// The real probe: a `stat` on the path.
#[derive(Debug, Clone, Copy)]
pub struct FsProbe;

impl Probe for FsProbe {
    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
}

/// Pick the first candidate that exists, or the empty string when none do.
///
/// `PATH` is never consulted and the candidate list is never caller-supplied at runtime, so the
/// probe cannot be steered into naming a binary outside the fixed list.
pub fn resolve_shell(candidates: &[&str], probe: &impl Probe) -> String {
    candidates
        .iter()
        .find(|candidate| probe.exists(candidate))
        .map_or_else(String::new, |candidate| (*candidate).to_owned())
}

/// Whether `b` is whitespace as C's `isspace` sees it in the `C` locale — which, unlike
/// [`u8::is_ascii_whitespace`], includes vertical tab (`0x0B`).
const fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// Split one database line into its colon-separated fields, or `None` if it is blank or a comment.
///
/// Leading whitespace is skipped **before** the blank/comment test and the split, because that is
/// what glibc does: `nss_files`' `internal_getent` (`nss/nss_files/files-XXX.c`) runs
/// `while (isspace (*p)) ++p;` on every line, then ignores it if `*p` is `'\0'` or `'#'`, and
/// only then hands `p` to the field parser. So `"  root:x:0:…"` **is** `root` to `getpwnam`, and
/// `"  # note"` is a comment. Reading such a line any other way would make this binary disagree
/// with the resolver it exists to satisfy — e.g. miss that `root` is taken and append a second.
fn fields(line: &[u8]) -> Option<Vec<&[u8]>> {
    let mut trimmed = line;
    while let [first, rest @ ..] = trimmed
        && is_c_space(*first)
    {
        trimmed = rest;
    }
    while let [rest @ .., b'\r' | b'\n'] = trimmed {
        trimmed = rest;
    }
    if trimmed.is_empty() || trimmed.first() == Some(&b'#') {
        return None;
    }
    Some(trimmed.split(|&b| b == b':').collect())
}

/// Every non-blank, non-comment line of a database, split into fields.
fn records(contents: &[u8]) -> impl Iterator<Item = Vec<&[u8]>> {
    contents.split(|&b| b == b'\n').filter_map(fields)
}

/// A numeric field (UID or GID), or `None` if it is not a plain decimal `u32`.
fn number(field: &[u8]) -> Option<u32> {
    std::str::from_utf8(field).ok()?.parse().ok()
}

/// The login name a passwd database already gives `uid`, if any.
///
/// This is the single-shot check for the passwd file: it keys on the **UID**, not on the exact
/// line we would have written, so a re-run with a different `--home` or `--gecos` is refused
/// rather than appending a second, differing entry for the same UID.
pub fn passwd_name_for_uid(contents: &[u8], uid: u32) -> Option<String> {
    records(contents).find_map(|f| {
        // name:passwd:uid:gid:gecos:home:shell
        let name = *f.first()?;
        (number(f.get(2)?)? == uid).then(|| String::from_utf8_lossy(name).into_owned())
    })
}

/// Who already holds a login name in a passwd database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameOwner {
    /// An entry with this UID.
    Uid(u32),
    /// An entry whose UID field is not a plain decimal `u32` (or is missing). Carries the raw
    /// field, lossily decoded, for the log line.
    Unparseable(String),
}

impl std::fmt::Display for NameOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uid(uid) => write!(f, "uid {uid}"),
            Self::Unparseable(raw) => write!(f, "an entry with an unparseable uid field '{raw}'"),
        }
    }
}

/// The entry a passwd database already gives the login `name`, if any.
///
/// Used after [`passwd_name_for_uid`] found nothing for our own UID: a hit here means the name is
/// taken by **another** entry, and appending would produce two entries for one name — `getpwnam`
/// returning the other account, and `getpwuid` naming us after it.
///
/// The **name** match alone decides. An entry whose UID field does not parse still owns the name
/// as far as a duplicate is concerned — skipping it would append a second line for that name.
pub fn passwd_uid_for_name(contents: &[u8], name: &str) -> Option<NameOwner> {
    records(contents).find_map(|f| {
        if *f.first()? != name.as_bytes() {
            return None;
        }
        let raw = f.get(2).copied().unwrap_or_default();
        Some(number(raw).map_or_else(
            || NameOwner::Unparseable(String::from_utf8_lossy(raw).into_owned()),
            NameOwner::Uid,
        ))
    })
}

/// The passwd scan: is our UID already resolvable (nothing to do), is our login name already
/// taken by a different UID (refuse), or neither (append)?
///
/// A taken name is refused rather than worked around. Appending anyway would give one name two
/// UIDs — `getpwnam` keeps returning the other account, and `getpwuid` of ours names us after it
/// (`--name root` would make `whoami` print `root`). Picking another name would silently change
/// what `$USER` resolves to. Neither is a convenience shim's call to make, so it is the fail-open
/// path instead: nothing written, a `WARN`, and exit `3` under `--strict`.
pub fn passwd_scan(contents: &[u8], uid: u32, name: &str) -> Scan {
    if let Some(found) = passwd_name_for_uid(contents, uid) {
        return Scan::Present(format!("uid {uid} to '{found}'"));
    }
    match passwd_uid_for_name(contents, name) {
        Some(other) => Scan::Conflict(format!(
            "name '{name}' is already taken by {other}, refusing to give it to uid {uid} too"
        )),
        None => Scan::Absent,
    }
}

/// Whether a group database already carries `name`, or already uses `gid`.
///
/// Either match is enough to skip the group append: both would make the new line a duplicate of
/// something already resolvable.
pub fn group_has(contents: &[u8], name: &str, gid: u32) -> bool {
    records(contents).any(|f| {
        // name:passwd:gid:members
        if f.first() == Some(&name.as_bytes()) {
            return true;
        }
        f.get(2).and_then(|g| number(g)) == Some(gid)
    })
}

/// What scanning a database, under the lock, concluded about the line we would append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan {
    /// Nothing resolves this identity yet: append.
    Absent,
    /// The identity already resolves; nothing to do. Carries the detail for the log line.
    Present(String),
    /// Appending would collide with a **different** identity already in the database (our login
    /// name, owned by another UID). Nothing is written. Carries the detail for the log line.
    Conflict(String),
}

/// Why an append could not even be attempted.
///
/// Split from the fail-open outcomes deliberately. [`Outcome::NotWritable`] means "this file is
/// not ours to change", which the RFC's *Failure mode* answers by warning and continuing; this
/// type means the system underneath is broken, which the RFC's exit code `1` answers by stopping.
#[derive(Debug)]
pub enum AppendError {
    /// The file could not be opened, locked or read — so we cannot even tell whether the entry
    /// is already there. Exit `1`.
    Prepare(io::Error),
    /// The file was open, locked and scanned, and the write itself failed. Fail-open, or exit
    /// `3` under `--strict`.
    Write(io::Error),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prepare(err) => write!(f, "cannot open, lock or read it: {err}"),
            Self::Write(err) => write!(f, "the append failed: {err}"),
        }
    }
}

impl std::error::Error for AppendError {}

/// What one append attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The line was written.
    Appended,
    /// The database already resolved this identity; nothing was written. Carries whatever the
    /// scan found, so the log line can name it.
    AlreadyPresent(String),
    /// Appending would have collided with a different identity; nothing was written. See
    /// [`Scan::Conflict`].
    Conflict(String),
    /// The file could not be opened for writing; nothing was written.
    NotWritable,
}

/// Append `line` to `path` under an exclusive `flock`, unless `scan` says not to.
///
/// `scan` is handed the file's raw contents and returns [`Scan::Absent`] to append, or
/// [`Scan::Present`]/[`Scan::Conflict`] with whatever the caller wants in the log line.
///
/// The scan happens **inside** the lock, deliberately. Steps "is it there" and "append it" are
/// check-then-act, and check-then-act without a lock is not idempotent — it only looks idempotent
/// when nothing runs concurrently. Scanning before taking the lock would reintroduce exactly the
/// window the lock exists to close.
///
/// The trailing-newline fix and the entry are written in one `write_all`, so the whole thing is a
/// single `O_APPEND` write, far under `PIPE_BUF`.
///
/// # Errors
///
/// [`AppendError::Prepare`] when the file cannot be opened, locked or read, and
/// [`AppendError::Write`] when only the write failed. The difference is the exit code.
pub fn append_locked(
    path: &Path,
    line: &str,
    scan: impl Fn(&[u8]) -> Scan,
) -> Result<Outcome, AppendError> {
    let mut file = match OpenOptions::new().read(true).append(true).open(path) {
        Ok(file) => file,
        // "Not ours to change" and "not there" are the same answer for this binary: decline and
        // say so. Turning a missing /etc/group into a container that will not start would be the
        // opposite of what the fail-open default is for.
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::ReadOnlyFilesystem
                    | io::ErrorKind::NotFound
                    | io::ErrorKind::IsADirectory
            ) =>
        {
            return Ok(Outcome::NotWritable);
        }
        Err(err) => return Err(AppendError::Prepare(err)),
    };

    flock(&file, FlockOperation::LockExclusive)
        .map_err(|errno| AppendError::Prepare(errno.into()))?;

    // Bytes, not `read_to_string`: a non-UTF-8 GECOS elsewhere in the file must not turn into an
    // exit `1` and a container that will not start.
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(AppendError::Prepare)?;

    // The lock is released when `file` drops.
    match scan(&contents) {
        Scan::Present(detail) => return Ok(Outcome::AlreadyPresent(detail)),
        Scan::Conflict(detail) => return Ok(Outcome::Conflict(detail)),
        Scan::Absent => {}
    }

    let mut buf = String::with_capacity(line.len() + 2);
    // No rule says a database ends in a newline. When it does not, `>>` welds the new entry onto
    // the previous line and corrupts both.
    if contents.last().is_some_and(|&b| b != b'\n') {
        buf.push('\n');
    }
    buf.push_str(line);
    buf.push('\n');

    file.write_all(buf.as_bytes()).map_err(AppendError::Write)?;
    file.flush().map_err(AppendError::Write)?;

    Ok(Outcome::Appended)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed unwrap is the test failing"
)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct FakeProbe(HashSet<&'static str>);

    impl Probe for FakeProbe {
        fn exists(&self, path: &str) -> bool {
            self.0.contains(path)
        }
    }

    fn probe(present: &[&'static str]) -> FakeProbe {
        FakeProbe(present.iter().copied().collect())
    }

    #[test]
    fn shell_probe_prefers_the_first_candidate_that_exists() {
        let all = probe(&["/bin/bash", "/bin/zsh", "/bin/sh"]);
        assert_eq!(resolve_shell(&SHELL_CANDIDATES, &all), "/bin/bash");

        let no_bash = probe(&["/bin/zsh", "/bin/sh"]);
        assert_eq!(resolve_shell(&SHELL_CANDIDATES, &no_bash), "/bin/zsh");

        let only_sh = probe(&["/bin/sh"]);
        assert_eq!(resolve_shell(&SHELL_CANDIDATES, &only_sh), "/bin/sh");
    }

    #[test]
    fn shell_probe_yields_an_empty_field_when_nothing_exists() {
        assert_eq!(resolve_shell(&SHELL_CANDIDATES, &probe(&[])), "");
    }

    #[test]
    fn finds_the_name_for_a_uid_already_in_the_database() {
        let db = "root:x:0:0:root:/root:/bin/bash\n\
                  user:x:1000730000:0:user user:/home/user:/bin/bash\n";
        assert_eq!(
            passwd_name_for_uid(db.as_bytes(), 1_000_730_000).as_deref(),
            Some("user")
        );
        assert_eq!(
            passwd_name_for_uid(db.as_bytes(), 0).as_deref(),
            Some("root")
        );
        assert_eq!(passwd_name_for_uid(db.as_bytes(), 1234), None);
    }

    #[test]
    fn database_scanning_skips_blank_lines_and_comments() {
        let db = "# a comment\n\nroot:x:0:0:root:/root:/bin/bash\n";
        assert_eq!(
            passwd_name_for_uid(db.as_bytes(), 0).as_deref(),
            Some("root")
        );
        assert_eq!(passwd_name_for_uid(db.as_bytes(), 1000), None);
    }

    #[test]
    fn a_malformed_line_is_skipped_rather_than_panicking() {
        let db = "garbage\nnot:enough\nroot:x:0:0:root:/root:/bin/sh\n";
        assert_eq!(
            passwd_name_for_uid(db.as_bytes(), 0).as_deref(),
            Some("root")
        );
    }

    #[test]
    fn a_non_utf8_gecos_does_not_stop_the_scan() {
        // Latin-1 "Jos\xe9" in someone else's GECOS field.
        let db = b"root:x:0:0:root:/root:/bin/bash\n\
                   jose:x:1001:0:Jos\xe9:/home/jose:/bin/sh\n\
                   user:x:1000730000:0:user user:/home/user:/bin/bash\n";
        assert_eq!(
            passwd_name_for_uid(db, 1_000_730_000).as_deref(),
            Some("user")
        );
        assert_eq!(passwd_uid_for_name(db, "jose"), Some(NameOwner::Uid(1001)));
        assert_eq!(passwd_scan(db, 1234, "dev"), Scan::Absent);
    }

    #[test]
    fn a_non_utf8_name_is_reported_lossily_rather_than_failing() {
        let db = b"us\xe9r:x:1000:0::/home/u:/bin/sh\n";
        assert_eq!(
            passwd_name_for_uid(db, 1000).as_deref(),
            Some("us\u{fffd}r")
        );
    }

    #[test]
    fn crlf_line_endings_are_tolerated() {
        let db = b"root:x:0:0:root:/root:/bin/bash\r\nuser:x:1000:0::/home/user:\r\n";
        assert_eq!(passwd_uid_for_name(db, "user"), Some(NameOwner::Uid(1000)));
    }

    #[test]
    fn a_name_match_with_an_unparseable_uid_is_still_a_conflict() {
        for db in [
            &b"user:x:notanumber:0::/home/user:/bin/sh\n"[..],
            b"user:x::0::/home/user:/bin/sh\n",
            b"user:x:-1:0::/home/user:/bin/sh\n",
            b"user\n",
        ] {
            assert!(
                matches!(
                    passwd_uid_for_name(db, "user"),
                    Some(NameOwner::Unparseable(_))
                ),
                "{db:?}"
            );
            match passwd_scan(db, 1000, "user") {
                Scan::Conflict(detail) => assert!(detail.contains("unparseable"), "{detail}"),
                other => panic!("{db:?}: expected a conflict, got {other:?}"),
            }
        }
    }

    #[test]
    fn leading_whitespace_is_skipped_like_glibc_does() {
        // glibc's nss_files skips `isspace` before parsing, so this is `root` to getpwnam.
        let db = b"  root:x:0:0:root:/root:/bin/bash\n\t\x0buser:x:1000:0::/home/user:/bin/sh\n";
        assert_eq!(passwd_name_for_uid(db, 0).as_deref(), Some("root"));
        assert_eq!(passwd_uid_for_name(db, "user"), Some(NameOwner::Uid(1000)));
        assert!(matches!(passwd_scan(db, 1234, "root"), Scan::Conflict(_)));
        assert!(group_has(b"  wheel:x:10:\n", "wheel", 4242));

        // And an indented `#` is still a comment, as it is for glibc.
        let commented = b"   # root:x:0:0:root:/root:/bin/bash\n \n";
        assert_eq!(passwd_name_for_uid(commented, 0), None);
        assert_eq!(passwd_scan(commented, 1000, "root"), Scan::Absent);
    }

    #[test]
    fn our_uid_already_present_wins_over_a_name_check() {
        let db = b"user:x:1000:0::/home/user:/bin/sh\n";
        assert!(matches!(passwd_scan(db, 1000, "other"), Scan::Present(_)));
    }

    #[test]
    fn a_login_name_taken_by_another_uid_is_a_conflict_not_an_append() {
        let db = b"root:x:0:0:root:/root:/bin/bash\nuser:x:1000:0::/home/user:/bin/sh\n";
        match passwd_scan(db, 1_000_730_000, "user") {
            Scan::Conflict(detail) => assert!(detail.contains("uid 1000"), "{detail}"),
            other => panic!("expected a conflict, got {other:?}"),
        }
        // A name taken by root is the sharpest case: never become a second `root`.
        assert!(matches!(
            passwd_scan(db, 1_000_730_000, "root"),
            Scan::Conflict(_)
        ));
    }

    #[test]
    fn append_locked_handles_a_non_utf8_database_and_writes_nothing_on_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwd");
        let original = b"root:x:0:0:r\xf4ot:/root:/bin/bash".to_vec();
        std::fs::write(&path, &original).unwrap();

        let conflict = append_locked(&path, "root:x:1000:0::/h:", |c| {
            passwd_scan(c, 1000, "root")
        })
        .unwrap();
        assert!(matches!(conflict, Outcome::Conflict(_)));
        assert_eq!(std::fs::read(&path).unwrap(), original, "nothing written");

        let appended =
            append_locked(&path, "dev:x:1000:0::/h:", |c| passwd_scan(c, 1000, "dev")).unwrap();
        assert_eq!(appended, Outcome::Appended);
        let mut expected = original.clone();
        expected.extend_from_slice(b"\ndev:x:1000:0::/h:\n");
        assert_eq!(std::fs::read(&path).unwrap(), expected);
    }

    #[test]
    fn group_matches_on_either_the_name_or_the_gid() {
        let db = "root:x:0:\nuser:x:1000730000:\n";
        assert!(group_has(db.as_bytes(), "user", 4242), "name should match");
        assert!(
            group_has(db.as_bytes(), "other", 1_000_730_000),
            "gid should match"
        );
        assert!(!group_has(db.as_bytes(), "other", 4242));
    }
}
