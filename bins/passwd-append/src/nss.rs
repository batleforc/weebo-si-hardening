//! Reading the passwd and group databases, probing for a shell, and the locked append.
//!
//! The parsing and the shell-ordering logic are pure functions over text, so they are tested
//! without a filesystem. Only [`append_locked`] and [`FsProbe`] actually touch one.

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

/// Split one database line into its colon-separated fields, or `None` if it is blank or a comment.
fn fields(line: &str) -> Option<Vec<&str>> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    Some(trimmed.split(':').collect())
}

/// The login name a passwd database already gives `uid`, if any.
///
/// This is the single-shot check for the passwd file: it keys on the **UID**, not on the exact
/// line we would have written, so a re-run with a different `--home` or `--gecos` is refused
/// rather than appending a second, differing entry for the same UID.
pub fn passwd_name_for_uid(contents: &str, uid: u32) -> Option<String> {
    contents.lines().find_map(|line| {
        let f = fields(line)?;
        // name:passwd:uid:gid:gecos:home:shell
        let name = *f.first()?;
        let found: u32 = f.get(2)?.parse().ok()?;
        (found == uid).then(|| name.to_owned())
    })
}

/// Whether a group database already carries `name`, or already uses `gid`.
///
/// Either match is enough to skip the group append: both would make the new line a duplicate of
/// something already resolvable.
pub fn group_has(contents: &str, name: &str, gid: u32) -> bool {
    contents.lines().any(|line| {
        let Some(f) = fields(line) else {
            return false;
        };
        // name:passwd:gid:members
        if f.first() == Some(&name) {
            return true;
        }
        f.get(2).and_then(|g| g.parse::<u32>().ok()) == Some(gid)
    })
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
    /// The file could not be opened for writing; nothing was written.
    NotWritable,
}

/// Append `line` to `path` under an exclusive `flock`, unless `already` finds it redundant.
///
/// `already` is handed the file's contents and returns `Some(detail)` when the identity is
/// already resolvable — the detail being whatever the caller wants in the log line.
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
    already: impl Fn(&str) -> Option<String>,
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

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(AppendError::Prepare)?;

    if let Some(detail) = already(&contents) {
        // The lock is released when `file` drops.
        return Ok(Outcome::AlreadyPresent(detail));
    }

    let mut buf = String::with_capacity(line.len() + 2);
    // No rule says a database ends in a newline. When it does not, `>>` welds the new entry onto
    // the previous line and corrupts both.
    if !contents.is_empty() && !contents.ends_with('\n') {
        buf.push('\n');
    }
    buf.push_str(line);
    buf.push('\n');

    file.write_all(buf.as_bytes()).map_err(AppendError::Write)?;
    file.flush().map_err(AppendError::Write)?;

    Ok(Outcome::Appended)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a failed unwrap is the test failing")]
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
            passwd_name_for_uid(db, 1_000_730_000).as_deref(),
            Some("user")
        );
        assert_eq!(passwd_name_for_uid(db, 0).as_deref(), Some("root"));
        assert_eq!(passwd_name_for_uid(db, 1234), None);
    }

    #[test]
    fn database_scanning_skips_blank_lines_and_comments() {
        let db = "# a comment\n\nroot:x:0:0:root:/root:/bin/bash\n";
        assert_eq!(passwd_name_for_uid(db, 0).as_deref(), Some("root"));
        assert_eq!(passwd_name_for_uid(db, 1000), None);
    }

    #[test]
    fn a_malformed_line_is_skipped_rather_than_panicking() {
        let db = "garbage\nnot:enough\nroot:x:0:0:root:/root:/bin/sh\n";
        assert_eq!(passwd_name_for_uid(db, 0).as_deref(), Some("root"));
    }

    #[test]
    fn group_matches_on_either_the_name_or_the_gid() {
        let db = "root:x:0:\nuser:x:1000730000:\n";
        assert!(group_has(db, "user", 4242), "name should match");
        assert!(group_has(db, "other", 1_000_730_000), "gid should match");
        assert!(!group_has(db, "other", 4242));
    }
}
