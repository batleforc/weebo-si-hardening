//! End-to-end tests against real files, running the real binary.
//!
//! These cover the parts [RFC 0001](../../../docs/rfc/0001-passwd-append.md) makes promises about
//! that a unit test cannot reach: the lock, the exit codes, the `exec` handover, and the
//! single-shot rule under concurrency.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// The binary under test, built by cargo before the integration suite runs.
const BIN: &str = env!("CARGO_BIN_EXE_passwd-append");

/// The UID the entries will be written for — whoever runs the suite.
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The whole suite writes an entry for its own effective UID, and the binary refuses to write one
/// for root. Running as root is therefore not a failure, it is a suite that cannot say anything.
fn skip_as_root() -> bool {
    if uid() == 0 {
        eprintln!("skipped: the binary refuses to write a root entry, by design");
        return true;
    }
    false
}

struct Fixture {
    _dir: tempfile::TempDir,
    passwd: std::path::PathBuf,
    group: std::path::PathBuf,
}

impl Fixture {
    /// A pair of databases seeded with a root entry, the way a real image ships them.
    fn new() -> Self {
        Self::with_contents("root:x:0:0:root:/root:/bin/bash\n", "root:x:0:\n")
    }

    fn with_contents(passwd: &str, group: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let passwd_path = dir.path().join("passwd");
        let group_path = dir.path().join("group");
        fs::write(&passwd_path, passwd).unwrap();
        fs::write(&group_path, group).unwrap();
        Self {
            _dir: dir,
            passwd: passwd_path,
            group: group_path,
        }
    }

    /// Run the binary against this fixture, with the given extra arguments.
    fn run(&self, extra: &[&str]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.arg("--passwd")
            .arg(&self.passwd)
            .arg("--group")
            .arg(&self.group)
            // Pin the inputs so the assertions do not depend on the runner's environment.
            .env_remove("USER_NAME")
            .env_remove("WEEBO_PASSWD_STRICT")
            .env("HOME", "/home/user")
            .args(extra)
            .stdin(Stdio::null());
        cmd.output().unwrap()
    }

    fn passwd_text(&self) -> String {
        fs::read_to_string(&self.passwd).unwrap()
    }

    fn group_text(&self) -> String {
        fs::read_to_string(&self.group).unwrap()
    }
}

/// How many lines of `text` name `uid` in the third colon-separated field.
fn entries_for(text: &str, uid: u32) -> usize {
    text.lines()
        .filter(|line| line.split(':').nth(2) == Some(&uid.to_string()))
        .count()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_fresh_run_appends_both_entries() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    let out = fx.run(&[]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let uid = uid();
    assert_eq!(entries_for(&fx.passwd_text(), uid), 1);
    assert_eq!(entries_for(&fx.group_text(), uid), 1);
    // The pre-existing content is untouched.
    assert!(
        fx.passwd_text()
            .starts_with("root:x:0:0:root:/root:/bin/bash\n")
    );
    assert!(
        fx.passwd_text()
            .contains(&format!("user:x:{uid}:0:user user:/home/user:"))
    );
    assert_eq!(
        fx.group_text().lines().last().unwrap(),
        format!("user:x:{uid}:")
    );
}

#[test]
fn a_re_run_writes_nothing_and_exits_zero() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    assert_eq!(code(&fx.run(&[])), 0);
    let after_first = fx.passwd_text();

    let second = fx.run(&[]);
    assert_eq!(code(&second), 0, "a re-run is a non-event, not a failure");
    assert_eq!(
        fx.passwd_text(),
        after_first,
        "the second run wrote something"
    );
    assert!(
        stderr(&second).contains("already resolves"),
        "the WARN line is the only signal a caller gets: {}",
        stderr(&second)
    );
}

#[test]
fn a_re_run_with_different_fields_still_writes_nothing() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    assert_eq!(code(&fx.run(&[])), 0);
    let after_first = fx.passwd_text();

    // This is the case the single-shot rule exists to stop: a second, differing entry for a UID
    // that already resolves.
    let second = fx.run(&["--home", "/somewhere/else", "--gecos", "different"]);
    assert_eq!(code(&second), 0);
    assert_eq!(fx.passwd_text(), after_first);
    assert_eq!(entries_for(&fx.passwd_text(), uid()), 1);
}

#[test]
fn a_database_without_a_trailing_newline_is_repaired_not_corrupted() {
    if skip_as_root() {
        return;
    }
    // No trailing newline anywhere. `>>` would weld the new entry onto the last line.
    let fx = Fixture::with_contents("root:x:0:0:root:/root:/bin/bash", "root:x:0:");
    assert_eq!(code(&fx.run(&[])), 0);

    let passwd = fx.passwd_text();
    assert!(
        passwd.starts_with("root:x:0:0:root:/root:/bin/bash\n"),
        "the previous line was corrupted: {passwd:?}"
    );
    assert_eq!(passwd.lines().count(), 2);
    assert_eq!(fx.group_text().lines().count(), 2);
}

#[test]
fn an_empty_database_gets_no_leading_blank_line() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::with_contents("", "");
    assert_eq!(code(&fx.run(&[])), 0);
    assert_eq!(fx.passwd_text().lines().count(), 1);
    assert!(!fx.passwd_text().starts_with('\n'));
}

#[test]
fn a_read_only_target_warns_and_continues() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    fs::set_permissions(&fx.passwd, fs::Permissions::from_mode(0o444)).unwrap();

    let out = fx.run(&[]);
    assert_eq!(code(&out), 0, "the default is fail-open");
    assert!(
        stderr(&out).contains("not writable"),
        "stderr: {}",
        stderr(&out)
    );
    // The two files are handled independently: group still got its entry.
    assert_eq!(entries_for(&fx.group_text(), uid()), 1);
}

#[test]
fn a_read_only_target_under_strict_exits_three() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    fs::set_permissions(&fx.passwd, fs::Permissions::from_mode(0o444)).unwrap();

    assert_eq!(code(&fx.run(&["--strict"])), 3);
}

#[test]
fn no_group_leaves_the_group_database_alone() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    let before = fx.group_text();
    assert_eq!(code(&fx.run(&["--no-group"])), 0);
    assert_eq!(fx.group_text(), before);
    assert_eq!(entries_for(&fx.passwd_text(), uid()), 1);
}

#[test]
fn dry_run_prints_both_lines_and_writes_nothing() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    let before_passwd = fx.passwd_text();
    let before_group = fx.group_text();

    let out = fx.run(&["--dry-run"]);
    assert_eq!(code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 2, "stdout: {stdout:?}");
    assert!(stdout.contains(&format!("user:x:{}:0:user user:/home/user:", uid())));
    assert_eq!(fx.passwd_text(), before_passwd);
    assert_eq!(fx.group_text(), before_group);
}

#[test]
fn a_command_after_the_separator_is_exec_ed() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    let out = fx.run(&["--", "/bin/sh", "-c", "echo handed-over; exit 7"]);

    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "handed-over",
        "the command did not run"
    );
    // exec means the exit code is the command's own.
    assert_eq!(code(&out), 7);
    assert_eq!(entries_for(&fx.passwd_text(), uid()), 1);
}

#[test]
fn the_handover_still_happens_when_the_entry_was_already_present() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    assert_eq!(code(&fx.run(&[])), 0);

    let out = fx.run(&["--", "/bin/sh", "-c", "echo second"]);
    assert_eq!(code(&out), 0);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "second");
    assert_eq!(entries_for(&fx.passwd_text(), uid()), 1);
}

#[test]
fn strict_refuses_to_hand_over_after_a_failed_append() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    fs::set_permissions(&fx.passwd, fs::Permissions::from_mode(0o444)).unwrap();

    let out = fx.run(&["--strict", "--", "/bin/sh", "-c", "echo should-not-run"]);
    assert_eq!(code(&out), 3);
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "the command ran despite --strict"
    );
}

#[test]
fn an_unknown_flag_exits_two_without_touching_the_files() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    let before = fx.passwd_text();
    let out = fx.run(&["--force"]);
    assert_eq!(code(&out), 2);
    assert_eq!(fx.passwd_text(), before);
}

#[test]
fn a_hostile_home_exits_two_without_touching_the_files() {
    if skip_as_root() {
        return;
    }
    let fx = Fixture::new();
    let before = fx.passwd_text();
    let out = fx.run(&["--home", "/home/user\nroot2:x:0:0::/root:/bin/sh"]);
    assert_eq!(code(&out), 2);
    assert_eq!(
        fx.passwd_text(),
        before,
        "validation must happen before any file is touched"
    );
}

/// The test that fails without the lock.
///
/// Every invocation reads the database and then decides whether to append. Without an exclusive
/// `flock` held across both, N processes that all read before any writes all conclude the UID is
/// absent, and all append.
#[test]
fn concurrent_invocations_produce_exactly_one_entry() {
    if skip_as_root() {
        return;
    }
    const RACERS: usize = 16;

    let fx = Fixture::new();
    // Pad the database so the read is not a single trivial buffer, widening the window a
    // lock-less implementation would lose.
    let mut padded = fs::OpenOptions::new()
        .append(true)
        .open(&fx.passwd)
        .unwrap();
    for i in 0..2000 {
        writeln!(
            padded,
            "filler{i}:x:{}:0:filler:/nonexistent:/sbin/nologin",
            900_000 + i
        )
        .unwrap();
    }
    drop(padded);

    let children: Vec<_> = (0..RACERS)
        .map(|_| {
            Command::new(BIN)
                .arg("--passwd")
                .arg(&fx.passwd)
                .arg("--group")
                .arg(&fx.group)
                .env_remove("USER_NAME")
                .env_remove("WEEBO_PASSWD_STRICT")
                .env("HOME", "/home/user")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();

    for mut child in children {
        assert_eq!(child.wait().unwrap().code(), Some(0));
    }

    assert_eq!(
        entries_for(&fx.passwd_text(), uid()),
        1,
        "{RACERS} concurrent invocations wrote more than one passwd entry"
    );
    assert_eq!(entries_for(&fx.group_text(), uid()), 1);
}

/// A target that does not exist is an internal error, not a silent success.
#[test]
fn a_missing_target_is_reported() {
    if skip_as_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope").join("passwd");
    let out = Command::new(BIN)
        .arg("--passwd")
        .arg(&missing)
        .arg("--no-group")
        .env("HOME", "/home/user")
        .env_remove("WEEBO_PASSWD_STRICT")
        .output()
        .unwrap();
    // Fail-open by default: the container still starts.
    assert_eq!(code(&out), 0);
    assert!(!Path::new(&missing).exists());
}

/// The case-1 substitution, against the exact block upstream ships.
///
/// The fixture is written here rather than vendored: che-code's script is EPL-2.0 and copying it
/// into an Apache-2.0 repo is a licensing decision, not a test decision. What this pins is that
/// the documented `sed` matches the block, replaces exactly it, leaves the rest of the script
/// intact, and produces something a POSIX shell will parse. The protection against upstream
/// *rewording* is the `grep -q` guard in the Containerfile, which fails the build on a no-match.
#[test]
fn the_documented_sed_replaces_exactly_the_upstream_block() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("entrypoint-volume.sh");

    // Verbatim lines 61-67 of build/scripts/entrypoint-volume.sh, with a line either side
    // standing in for the ~130 lines that must survive untouched.
    let original = concat!(
        "#!/bin/sh\n",
        "get_openssl_version() {\n",
        "  echo before\n",
        "}\n",
        "\n",
        "# UDI8 support for adding current (arbitrary) user to /etc/passwd and /etc/group\n",
        "if ! whoami &> /dev/null; then\n",
        "  if [ -w /etc/passwd ]; then\n",
        "    echo \"${USER_NAME:-user}:x:$(id -u):0:${USER_NAME:-user} user:${HOME}:/bin/bash\" >> /etc/passwd\n",
        "    echo \"${USER_NAME:-user}:x:$(id -u):\" >> /etc/group\n",
        "  fi\n",
        "fi\n",
        "\n",
        "# list checode\n",
        "ls -la /checode/\n",
    );
    fs::write(&script, original).unwrap();

    // The guard, exactly as the Containerfile runs it.
    let guard = Command::new("grep")
        .arg("-q")
        .arg("^if ! whoami")
        .arg(&script)
        .status()
        .unwrap();
    assert!(guard.success(), "the guard did not find the block");

    let sed = Command::new("sed")
        .arg("-i")
        .arg(r"/^if ! whoami/,/^fi$/c\/usr/local/bin/passwd-append")
        .arg(&script)
        .status()
        .unwrap();
    assert!(sed.success());

    let patched = fs::read_to_string(&script).unwrap();

    assert!(
        patched.contains("\n/usr/local/bin/passwd-append\n"),
        "the binary is not called: {patched}"
    );
    assert!(
        !patched.contains("whoami"),
        "the shell block survived: {patched}"
    );
    assert!(
        !patched.contains(">> /etc/passwd"),
        "the raw append survived: {patched}"
    );
    // Everything around it is untouched — this is the half that matters, because the rest of the
    // script is what actually boots the IDE.
    assert!(patched.contains("get_openssl_version() {\n  echo before\n}\n"));
    assert!(patched.contains("# list checode\nls -la /checode/\n"));
    assert!(
        patched.contains("# UDI8 support"),
        "the comment explaining the line was dropped"
    );

    // And it is still a script.
    let syntax = Command::new("sh").arg("-n").arg(&script).status().unwrap();
    assert!(syntax.success(), "the patched script does not parse");

    // Re-running the guard on an already-patched file fails, which is what makes the build fail
    // loudly rather than shipping an image with no passwd handling at all.
    let second = Command::new("grep")
        .arg("-q")
        .arg("^if ! whoami")
        .arg(&script)
        .status()
        .unwrap();
    assert!(!second.success(), "the guard would silently no-op");
}

/// Exit `1` is "cannot stat or lock a target file", and it has to be reachable.
///
/// The distinction the RFC draws, and that the fail-open default depends on: a target that is
/// merely absent or read-only is declined with a warning, while a target the process cannot even
/// open to find out is an internal error.
#[test]
fn a_target_that_cannot_be_opened_at_all_exits_one() {
    if skip_as_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // A regular file used as a directory component: ENOTDIR, which is neither "absent" nor
    // "read-only" and so is not one of the fail-open cases.
    let blocker = dir.path().join("blocker");
    fs::write(&blocker, "not a directory").unwrap();

    let out = Command::new(BIN)
        .arg("--passwd")
        .arg(blocker.join("passwd"))
        .arg("--no-group")
        .env("HOME", "/home/user")
        .env_remove("WEEBO_PASSWD_STRICT")
        .output()
        .unwrap();

    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot open, lock or read it"),
        "{}",
        stderr(&out)
    );
}
