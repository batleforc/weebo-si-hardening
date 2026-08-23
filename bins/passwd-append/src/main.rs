//! `passwd-append` — give the container's arbitrary UID a real `/etc/passwd` and `/etc/group`
//! entry, then hand over to the real command.
//!
//! The design, and every decision this file only implements, is
//! [RFC 0001](../../../docs/rfc/0001-passwd-append.md). Three properties are worth restating
//! where the code is:
//!
//! - The entry is written **once per container and never twice**. There is no `--force`.
//! - It writes at most one passwd line and one group line, for its **own effective UID only**.
//! - With a command after `--` it `execvp`s rather than forking, so the real process keeps the
//!   parent's place in the process tree and the init above it signals that command directly.

mod entry;
mod nss;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use entry::{GroupEntry, InvalidField, PasswdEntry};
use nss::{FsProbe, Outcome, SHELL_CANDIDATES};

/// Everything after the program name, as the RFC's *Contract* spells it.
const USAGE: &str = "\
passwd-append — give the running UID a real passwd and group entry

usage: passwd-append [OPTIONS] [-- COMMAND [ARGS...]]

options:
  --name <NAME>     login and group name        (env USER_NAME, default: user)
  --home <PATH>     home directory field        (env HOME, default: /home/<name>)
  --shell <PATH>    shell field                 (default: first of /bin/bash /bin/zsh /bin/sh)
  --gecos <TEXT>    comment field               (default: \"<name> user\")
  --gid <GID>       primary GID in the entry    (default: 0)
  --passwd <PATH>   passwd file to append to    (env NSS_WRAPPER_PASSWD, default: /etc/passwd)
  --group <PATH>    group file to append to     (env NSS_WRAPPER_GROUP, default: /etc/group)
  --no-group        skip the group entry
  --strict          a failed append exits 3     (env WEEBO_PASSWD_STRICT)
  --dry-run         print the lines, write nothing
  -h, --help        this text

With `--`, the command is exec'd once the entries are in place. Without it, the binary exits.
";

/// Exit codes, per the RFC's *Contract*. Changing one needs a new RFC.
mod exit {
    /// Entries appended, already present, or `--dry-run`.
    pub const OK: u8 = 0;
    /// Cannot read our own UID, cannot stat or lock a target file.
    pub const INTERNAL: u8 = 1;
    /// Bad flag, or a field that failed validation.
    pub const USAGE: u8 = 2;
    /// An append failed and `--strict` was set.
    pub const STRICT: u8 = 3;
}

/// Emit one structured line on stderr, so a piped stdout stays clean.
macro_rules! log {
    ($level:literal, $($arg:tt)*) => {
        eprintln!("{:<5} passwd-append: {}", $level, format_args!($($arg)*))
    };
}

/// A failure that ends the process, carrying the exit code it maps to.
#[derive(Debug)]
enum Failure {
    /// A flag was unknown, malformed, or missing its value.
    Usage(String),
    /// A constructed field broke a validation rule.
    Field(InvalidField),
    /// Something the process cannot recover from.
    Internal(String),
}

impl Failure {
    const fn code(&self) -> u8 {
        match self {
            Self::Usage(_) | Self::Field(_) => exit::USAGE,
            Self::Internal(_) => exit::INTERNAL,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(msg) | Self::Internal(msg) => f.write_str(msg),
            Self::Field(err) => write!(f, "{err}"),
        }
    }
}

impl From<InvalidField> for Failure {
    fn from(err: InvalidField) -> Self {
        Self::Field(err)
    }
}

/// The flags, exactly as parsed — before any env or default is applied.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    name: Option<String>,
    home: Option<String>,
    shell: Option<String>,
    gecos: Option<String>,
    gid: Option<u32>,
    passwd: Option<String>,
    group: Option<String>,
    no_group: bool,
    strict: bool,
    dry_run: bool,
    help: bool,
    /// Everything after the first bare `--`.
    command: Vec<OsString>,
}

/// Parse the argument vector, stopping flag interpretation at the first bare `--`.
fn parse(argv: Vec<OsString>) -> Result<Args, Failure> {
    let mut args = Args::default();
    let mut it = argv.into_iter();

    while let Some(raw) = it.next() {
        if raw == "--" {
            args.command = it.collect();
            break;
        }

        let Some(flag) = raw.to_str() else {
            return Err(Failure::Usage(format!(
                "argument {} is not valid UTF-8",
                raw.to_string_lossy()
            )));
        };

        // A flag that takes a value: pull the next argument, or fail naming the flag.
        let value = |it: &mut std::vec::IntoIter<OsString>| -> Result<String, Failure> {
            let owned = flag.to_owned();
            it.next()
                .ok_or_else(|| Failure::Usage(format!("{owned} needs a value")))
                .and_then(|v| {
                    v.into_string().map_err(|bad| {
                        Failure::Usage(format!(
                            "value for {owned} is not valid UTF-8: {}",
                            bad.to_string_lossy()
                        ))
                    })
                })
        };

        match flag {
            "--name" => args.name = Some(value(&mut it)?),
            "--home" => args.home = Some(value(&mut it)?),
            "--shell" => args.shell = Some(value(&mut it)?),
            "--gecos" => args.gecos = Some(value(&mut it)?),
            "--passwd" => args.passwd = Some(value(&mut it)?),
            "--group" => args.group = Some(value(&mut it)?),
            "--gid" => {
                let raw = value(&mut it)?;
                args.gid = Some(
                    raw.parse()
                        .map_err(|_| Failure::Usage(format!("--gid {raw} is not a number")))?,
                );
            }
            "--no-group" => args.no_group = true,
            "--strict" => args.strict = true,
            "--dry-run" => args.dry_run = true,
            "-h" | "--help" => args.help = true,
            other => return Err(Failure::Usage(format!("unknown flag {other}"))),
        }
    }

    Ok(args)
}

/// The configuration after flag > env > default precedence has been applied.
#[derive(Debug, PartialEq, Eq)]
struct Resolved {
    passwd_entry: PasswdEntry,
    group_entry: Option<GroupEntry>,
    passwd_path: PathBuf,
    group_path: PathBuf,
    strict: bool,
    dry_run: bool,
}

/// Whether an environment variable is set to something other than the empty string.
fn env_flag(value: Option<String>) -> bool {
    value.is_some_and(|v| !v.is_empty())
}

/// Apply precedence, build the entries, and validate them — all before any file is touched, so a
/// bad field costs nothing.
fn resolve(
    args: &Args,
    uid: u32,
    env: impl Fn(&str) -> Option<String>,
    probe: &impl nss::Probe,
) -> Result<Resolved, Failure> {
    let name = args
        .name
        .clone()
        .or_else(|| env("USER_NAME"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "user".to_owned());

    let home = args
        .home
        .clone()
        .or_else(|| env("HOME"))
        .filter(|v| !v.is_empty())
        // The snippet writes an empty field when HOME is unset, which is how tools end up
        // writing into `/`. This fallback is a deliberate improvement, not a reproduction.
        .unwrap_or_else(|| format!("/home/{name}"));

    let shell = args
        .shell
        .clone()
        .unwrap_or_else(|| nss::resolve_shell(&SHELL_CANDIDATES, probe));

    let gecos = args
        .gecos
        .clone()
        // Reproduces `${USER_NAME:-user} user`, which yields "user user" by default. Odd-looking,
        // faithful, and nothing reads it.
        .unwrap_or_else(|| format!("{name} user"));

    // Hardcoded 0 rather than getegid(): on OpenShift they are the same value, but 0 is what is
    // deployed today and a drop-in replacement should not quietly emit something else.
    let gid = args.gid.unwrap_or(0);

    let passwd_path = args
        .passwd
        .clone()
        .or_else(|| env("NSS_WRAPPER_PASSWD"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/etc/passwd".to_owned());

    let group_path = args
        .group
        .clone()
        .or_else(|| env("NSS_WRAPPER_GROUP"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/etc/group".to_owned());

    let passwd_entry = PasswdEntry::new(&name, uid, gid, &gecos, &home, &shell)?;
    let group_entry = if args.no_group {
        None
    } else {
        Some(GroupEntry::new(&name, uid)?)
    };

    Ok(Resolved {
        passwd_entry,
        group_entry,
        passwd_path: PathBuf::from(passwd_path),
        group_path: PathBuf::from(group_path),
        strict: args.strict || env_flag(env("WEEBO_PASSWD_STRICT")),
        dry_run: args.dry_run,
    })
}

/// Append one entry, log what happened, and report whether it counts as a failed append.
///
/// # Errors
///
/// [`Failure::Internal`] when the file could not be opened, locked or read — exit `1`, per the
/// RFC's *Exit codes*. A failed **write** is not that: it is the fail-open case, reported as
/// `true` here and turned into exit `3` only under `--strict`.
fn apply(
    path: &std::path::Path,
    line: &str,
    already: impl Fn(&str) -> Option<String>,
) -> Result<bool, Failure> {
    match nss::append_locked(path, line, already) {
        Ok(Outcome::Appended) => {
            log!("INFO", "appended to {}: {line}", path.display());
            Ok(false)
        }
        Ok(Outcome::AlreadyPresent(detail)) => {
            // WARN and not INFO deliberately: the exit code cannot carry this, so the log line is
            // the only signal a caller gets that its call was a no-op.
            log!(
                "WARN",
                "{} already resolves {detail}, nothing to do",
                path.display()
            );
            Ok(false)
        }
        Ok(Outcome::NotWritable) => {
            log!(
                "WARN",
                "{} is not writable, leaving it unchanged",
                path.display()
            );
            Ok(true)
        }
        Err(nss::AppendError::Write(err)) => {
            log!("WARN", "{} could not be updated: {err}", path.display());
            Ok(true)
        }
        Err(err @ nss::AppendError::Prepare(_)) => {
            Err(Failure::Internal(format!("{}: {err}", path.display())))
        }
    }
}

fn run() -> Result<u8, Failure> {
    let args = parse(std::env::args_os().skip(1).collect())?;

    if args.help {
        print!("{USAGE}");
        return Ok(exit::OK);
    }

    let uid = rustix::process::geteuid().as_raw();
    let config = resolve(&args, uid, |key| std::env::var(key).ok(), &FsProbe)?;

    let passwd_line = config.passwd_entry.to_string();
    let group_line = config.group_entry.as_ref().map(ToString::to_string);

    if config.dry_run {
        println!("{passwd_line}");
        if let Some(line) = &group_line {
            println!("{line}");
        }
        return Ok(exit::OK);
    }

    let mut any_failed = apply(&config.passwd_path, &passwd_line, |contents| {
        nss::passwd_name_for_uid(contents, uid).map(|found| format!("uid {uid} to '{found}'"))
    })?;

    if let (Some(entry), Some(line)) = (config.group_entry.as_ref(), group_line.as_ref()) {
        // The two files are handled independently: a read-only /etc/group does not prevent the
        // passwd entry.
        let failed = apply(&config.group_path, line, |contents| {
            nss::group_has(contents, entry.name(), entry.gid_field())
                .then(|| format!("group '{}'", entry.name()))
        })?;
        any_failed = any_failed || failed;
    }

    if any_failed && config.strict {
        log!("ERROR", "an append failed and --strict is set");
        return Ok(exit::STRICT);
    }

    let Some((program, rest)) = config_command(&args) else {
        return Ok(exit::OK);
    };

    // execvp, not fork+wait: the obvious "run the command for me" implementation would put this
    // process between the init and the real command and quietly break graceful shutdown.
    use std::os::unix::process::CommandExt as _;
    let err = std::process::Command::new(program).args(rest).exec();
    Err(Failure::Internal(format!(
        "cannot exec {}: {err}",
        program.to_string_lossy()
    )))
}

/// The command to hand over to, if a `--` was given.
fn config_command(args: &Args) -> Option<(&OsString, &[OsString])> {
    args.command.split_first()
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            log!("ERROR", "{failure}");
            if matches!(failure, Failure::Usage(_)) {
                eprint!("{USAGE}");
            }
            ExitCode::from(failure.code())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a failed unwrap is the test failing")]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct AllShells;
    impl nss::Probe for AllShells {
        fn exists(&self, path: &str) -> bool {
            path == "/bin/bash"
        }
    }

    struct NoShell;
    impl nss::Probe for NoShell {
        fn exists(&self, _path: &str) -> bool {
            false
        }
    }

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn double_dash_splits_our_flags_from_the_command() {
        let args = parse(argv(&[
            "--name",
            "dev",
            "--",
            "/usr/local/bin/entrypoint",
            "--serve",
        ]))
        .unwrap();
        assert_eq!(args.name.as_deref(), Some("dev"));
        assert_eq!(
            args.command,
            argv(&["/usr/local/bin/entrypoint", "--serve"])
        );
    }

    #[test]
    fn a_second_double_dash_belongs_to_the_command() {
        let args = parse(argv(&["--", "sh", "-c", "--", "echo hi"])).unwrap();
        assert_eq!(args.command, argv(&["sh", "-c", "--", "echo hi"]));
    }

    #[test]
    fn no_command_means_standalone_mode() {
        let args = parse(argv(&["--dry-run"])).unwrap();
        assert!(args.command.is_empty());
        assert!(args.dry_run);
    }

    #[test]
    fn an_unknown_flag_is_a_usage_error() {
        let err = parse(argv(&["--force"])).unwrap_err();
        assert_eq!(err.code(), exit::USAGE);
        assert!(err.to_string().contains("--force"));
    }

    #[test]
    fn a_flag_missing_its_value_is_a_usage_error() {
        let err = parse(argv(&["--name"])).unwrap_err();
        assert_eq!(err.code(), exit::USAGE);
    }

    #[test]
    fn a_non_numeric_gid_is_a_usage_error() {
        let err = parse(argv(&["--gid", "wheel"])).unwrap_err();
        assert_eq!(err.code(), exit::USAGE);
    }

    #[test]
    fn precedence_is_flag_over_env_over_default() {
        let args = parse(argv(&["--name", "fromflag"])).unwrap();
        let env = env_of(&[("USER_NAME", "fromenv"), ("HOME", "/home/fromenv")]);
        let got = resolve(&args, 1000, &env, &AllShells).unwrap();
        assert_eq!(
            got.passwd_entry.to_string(),
            "fromflag:x:1000:0:fromflag user:/home/fromenv:/bin/bash"
        );
    }

    #[test]
    fn env_wins_over_the_default() {
        let args = parse(argv(&[])).unwrap();
        let env = env_of(&[("USER_NAME", "fromenv")]);
        let got = resolve(&args, 1000, &env, &AllShells).unwrap();
        // HOME unset, so the /home/<name> fallback applies rather than an empty field.
        assert_eq!(
            got.passwd_entry.to_string(),
            "fromenv:x:1000:0:fromenv user:/home/fromenv:/bin/bash"
        );
    }

    #[test]
    fn the_default_invocation_reproduces_the_upstream_line() {
        let args = parse(argv(&[])).unwrap();
        let env = env_of(&[("HOME", "/home/user")]);
        let got = resolve(&args, 1_000_730_000, &env, &AllShells).unwrap();
        assert_eq!(
            got.passwd_entry.to_string(),
            "user:x:1000730000:0:user user:/home/user:/bin/bash"
        );
        assert_eq!(got.group_entry.unwrap().to_string(), "user:x:1000730000:");
    }

    #[test]
    fn no_group_drops_the_group_entry() {
        let args = parse(argv(&["--no-group"])).unwrap();
        let got = resolve(&args, 1000, env_of(&[]), &AllShells).unwrap();
        assert!(got.group_entry.is_none());
    }

    #[test]
    fn an_image_without_a_shell_gets_an_empty_shell_field() {
        let args = parse(argv(&[])).unwrap();
        let got = resolve(&args, 1000, env_of(&[]), &NoShell).unwrap();
        assert!(got.passwd_entry.to_string().ends_with(':'));
    }

    #[test]
    fn strict_can_come_from_the_environment() {
        let args = parse(argv(&[])).unwrap();
        let got = resolve(
            &args,
            1000,
            env_of(&[("WEEBO_PASSWD_STRICT", "1")]),
            &AllShells,
        )
        .unwrap();
        assert!(got.strict);
        let unset = resolve(&args, 1000, env_of(&[]), &AllShells).unwrap();
        assert!(!unset.strict);
        // An empty value is not "set" — an unset var and an exported-but-empty one behave alike.
        let empty = resolve(
            &args,
            1000,
            env_of(&[("WEEBO_PASSWD_STRICT", "")]),
            &AllShells,
        )
        .unwrap();
        assert!(!empty.strict);
    }

    #[test]
    fn nss_wrapper_variables_redirect_the_targets() {
        let args = parse(argv(&[])).unwrap();
        let env = env_of(&[
            ("NSS_WRAPPER_PASSWD", "/tmp/passwd"),
            ("NSS_WRAPPER_GROUP", "/tmp/group"),
        ]);
        let got = resolve(&args, 1000, &env, &AllShells).unwrap();
        assert_eq!(got.passwd_path, PathBuf::from("/tmp/passwd"));
        assert_eq!(got.group_path, PathBuf::from("/tmp/group"));
    }

    #[test]
    fn a_hostile_home_is_rejected_before_any_file_is_touched() {
        let args = parse(argv(&["--home", "/home/user\nroot:x:0:0::/root:/bin/sh"])).unwrap();
        let err = resolve(&args, 1000, env_of(&[]), &AllShells).unwrap_err();
        assert_eq!(err.code(), exit::USAGE);
    }

    #[test]
    fn a_root_effective_uid_is_refused() {
        let args = parse(argv(&[])).unwrap();
        let err = resolve(&args, 0, env_of(&[]), &AllShells).unwrap_err();
        assert_eq!(err.code(), exit::USAGE);
    }
}
