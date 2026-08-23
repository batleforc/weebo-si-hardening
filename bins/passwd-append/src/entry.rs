//! Construction and validation of the `/etc/passwd` and `/etc/group` lines.
//!
//! Pure: nothing here touches the filesystem. Every validation rule
//! [RFC 0001](../../../docs/rfc/0001-passwd-append.md) states lives in this module, so the
//! security-relevant logic is table-testable without a filesystem — which is the 80% of
//! hexagonal's benefit the RFC buys at none of its cost.
//!
//! The formats reproduced here are the ones che-code's `entrypoint-volume.sh` writes:
//!
//! ```text
//! passwd:  <name>:x:<uid>:<gid>:<gecos>:<home>:<shell>
//! group:   <name>:x:<uid>:
//! ```
//!
//! Note the group line carries the **UID** in the GID field and an empty member list. That is
//! the upstream behaviour, reproduced deliberately; see the RFC's *Entry formats*.

use std::fmt;

/// The literal password placeholder both files carry: "the hash lives in the shadow file".
///
/// It is never anything else and there is no flag for it.
const PASSWORD_PLACEHOLDER: &str = "x";

/// Longest login name accepted, matching the `[a-zA-Z0-9._-]{1,32}` rule in the RFC.
const MAX_NAME_LEN: usize = 32;

/// Why a field was rejected.
///
/// Rejection is always a usage error (exit `2`), never a silent sanitisation: dropping a colon
/// out of a path produces a wrong home directory that nobody notices for a week.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Contains `:`, which would forge an extra field.
    Separator,
    /// Contains `\n` or `\r`, which would forge an entire extra entry.
    Newline,
    /// Contains a NUL byte.
    Nul,
    /// Empty where a value is required.
    Empty,
    /// Longer than [`MAX_NAME_LEN`].
    TooLong,
    /// Contains a character outside `[a-zA-Z0-9._-]`.
    BadCharacter,
    /// Starts with `-`, which reads as a flag to everything downstream.
    LeadingDash,
    /// Not an absolute path.
    NotAbsolute,
    /// UID `0`. This binary never writes an entry claiming to be root.
    RootUid,
}

impl Reason {
    /// A short human explanation, used in the error message and in the tests.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Separator => "contains ':'",
            Self::Newline => "contains a newline",
            Self::Nul => "contains a NUL byte",
            Self::Empty => "is empty",
            Self::TooLong => "is longer than 32 characters",
            Self::BadCharacter => "contains a character outside [a-zA-Z0-9._-]",
            Self::LeadingDash => "starts with '-'",
            Self::NotAbsolute => "is not an absolute path",
            Self::RootUid => "is 0, and this binary never writes a root entry",
        }
    }
}

/// A field that failed validation, naming both the field and the rule it broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidField {
    /// The field name as it appears in the CLI (`name`, `home`, `gecos`, …).
    pub field: &'static str,
    /// Why it was rejected.
    pub reason: Reason,
}

impl fmt::Display for InvalidField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.field, self.reason.as_str())
    }
}

impl std::error::Error for InvalidField {}

/// Reject the three characters that turn one line into two, or one field into two.
///
/// This is the rule that matters: `HOME` and `USER_NAME` are set by whoever authors the pod spec
/// or the devfile, and `>>` cannot tell a home directory from a second passwd entry.
fn reject_control(field: &'static str, value: &str) -> Result<(), InvalidField> {
    for ch in value.chars() {
        let reason = match ch {
            ':' => Reason::Separator,
            '\n' | '\r' => Reason::Newline,
            '\0' => Reason::Nul,
            _ => continue,
        };
        return Err(InvalidField { field, reason });
    }
    Ok(())
}

/// Validate a login name against `[a-zA-Z0-9._-]{1,32}`, additionally refusing a leading `-`.
fn validate_name(name: &str) -> Result<(), InvalidField> {
    let field = "name";
    if name.is_empty() {
        return Err(InvalidField {
            field,
            reason: Reason::Empty,
        });
    }
    if name.len() > MAX_NAME_LEN {
        return Err(InvalidField {
            field,
            reason: Reason::TooLong,
        });
    }
    if name.starts_with('-') {
        return Err(InvalidField {
            field,
            reason: Reason::LeadingDash,
        });
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(InvalidField {
            field,
            reason: Reason::BadCharacter,
        });
    }
    Ok(())
}

/// Validate an absolute path field, rejecting the control characters first.
fn validate_absolute(field: &'static str, value: &str) -> Result<(), InvalidField> {
    reject_control(field, value)?;
    if value.is_empty() {
        return Err(InvalidField {
            field,
            reason: Reason::Empty,
        });
    }
    if !value.starts_with('/') {
        return Err(InvalidField {
            field,
            reason: Reason::NotAbsolute,
        });
    }
    Ok(())
}

/// A validated `/etc/passwd` line.
///
/// Construction is the only way in, so a value of this type is always safe to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
    gecos: String,
    home: String,
    shell: String,
}

impl PasswdEntry {
    /// Build and validate a passwd entry.
    ///
    /// `shell` may be empty, which `getpwnam` treats as "use `/bin/sh`" — the same outcome as
    /// naming it, without asserting a path the shell probe could not verify.
    ///
    /// # Errors
    ///
    /// Returns the first field that broke a rule, with the rule it broke.
    pub fn new(
        name: &str,
        uid: u32,
        gid: u32,
        gecos: &str,
        home: &str,
        shell: &str,
    ) -> Result<Self, InvalidField> {
        validate_name(name)?;
        // The binary only ever writes its own effective UID, and refuses to claim root even if
        // something upstream of it went wrong. See the RFC's *Refusing UID 0*.
        if uid == 0 {
            return Err(InvalidField {
                field: "uid",
                reason: Reason::RootUid,
            });
        }
        reject_control("gecos", gecos)?;
        validate_absolute("home", home)?;
        if !shell.is_empty() {
            validate_absolute("shell", shell)?;
        }
        Ok(Self {
            name: name.to_owned(),
            uid,
            gid,
            gecos: gecos.to_owned(),
            home: home.to_owned(),
            shell: shell.to_owned(),
        })
    }
}

impl fmt::Display for PasswdEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}",
            self.name, PASSWORD_PLACEHOLDER, self.uid, self.gid, self.gecos, self.home, self.shell
        )
    }
}

/// A validated `/etc/group` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    name: String,
    uid: u32,
}

impl GroupEntry {
    /// Build and validate a group entry.
    ///
    /// # Errors
    ///
    /// Returns the first field that broke a rule.
    pub fn new(name: &str, uid: u32) -> Result<Self, InvalidField> {
        validate_name(name)?;
        if uid == 0 {
            return Err(InvalidField {
                field: "uid",
                reason: Reason::RootUid,
            });
        }
        Ok(Self {
            name: name.to_owned(),
            uid,
        })
    }

    /// The value written into the group line's GID field — the UID, per the upstream format.
    pub const fn gid_field(&self) -> u32 {
        self.uid
    }

    /// The group name this entry declares.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for GroupEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Trailing colon: the member list, deliberately empty, as upstream writes it.
        write!(f, "{}:{}:{}:", self.name, PASSWORD_PLACEHOLDER, self.uid)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a failed unwrap is the test failing")]
mod tests {
    use super::*;

    /// The golden case. This is the line
    /// [`entrypoint-volume.sh#L64`](https://github.com/che-incubator/che-code/blob/main/build/scripts/entrypoint-volume.sh#L64)
    /// produces for the documented inputs, byte for byte. If this ever needs relaxing that is a
    /// RFC amendment, not a fixture update.
    #[test]
    fn passwd_line_matches_upstream_byte_for_byte() {
        let entry = PasswdEntry::new(
            "user",
            1_000_730_000,
            0,
            "user user",
            "/home/user",
            "/bin/bash",
        )
        .unwrap();
        assert_eq!(
            entry.to_string(),
            "user:x:1000730000:0:user user:/home/user:/bin/bash"
        );
    }

    /// The companion line from `#L65`.
    #[test]
    fn group_line_matches_upstream_byte_for_byte() {
        let entry = GroupEntry::new("user", 1_000_730_000).unwrap();
        assert_eq!(entry.to_string(), "user:x:1000730000:");
    }

    #[test]
    fn empty_shell_is_allowed_and_renders_as_an_empty_field() {
        let entry = PasswdEntry::new("user", 1000, 0, "user user", "/home/user", "").unwrap();
        assert_eq!(entry.to_string(), "user:x:1000:0:user user:/home/user:");
    }

    /// One row of the rejection table: a case that is valid apart from the field it overrides.
    struct Case {
        label: &'static str,
        name: &'static str,
        uid: u32,
        gecos: &'static str,
        home: &'static str,
        shell: &'static str,
        field: &'static str,
        reason: Reason,
    }

    impl Case {
        /// The baseline every row starts from, so each row states only what it is testing.
        const fn valid() -> Self {
            Self {
                label: "",
                name: "user",
                uid: 1000,
                gecos: "user user",
                home: "/home/user",
                shell: "/bin/sh",
                field: "",
                reason: Reason::Empty,
            }
        }
    }

    /// Every rejection rule the RFC states, in one table.
    #[test]
    fn rejects_every_forbidden_field() {
        let cases = [
            Case {
                label: "colon in home forges a field",
                home: "/home/us:er",
                field: "home",
                reason: Reason::Separator,
                ..Case::valid()
            },
            Case {
                label: "newline in home forges an entire entry",
                home: "/home/user\nroot:x:0:0::/root:/bin/sh",
                field: "home",
                reason: Reason::Newline,
                ..Case::valid()
            },
            Case {
                label: "carriage return in gecos",
                gecos: "user\ruser",
                field: "gecos",
                reason: Reason::Newline,
                ..Case::valid()
            },
            Case {
                label: "NUL in gecos",
                gecos: "user\0user",
                field: "gecos",
                reason: Reason::Nul,
                ..Case::valid()
            },
            Case {
                label: "colon in gecos",
                gecos: "user:user",
                field: "gecos",
                reason: Reason::Separator,
                ..Case::valid()
            },
            Case {
                label: "relative home",
                home: "home/user",
                field: "home",
                reason: Reason::NotAbsolute,
                ..Case::valid()
            },
            Case {
                label: "empty home",
                home: "",
                field: "home",
                reason: Reason::Empty,
                ..Case::valid()
            },
            Case {
                label: "relative shell",
                shell: "bin/sh",
                field: "shell",
                reason: Reason::NotAbsolute,
                ..Case::valid()
            },
            Case {
                label: "empty name",
                name: "",
                field: "name",
                reason: Reason::Empty,
                ..Case::valid()
            },
            Case {
                label: "name starting with a dash reads as a flag downstream",
                name: "-user",
                field: "name",
                reason: Reason::LeadingDash,
                ..Case::valid()
            },
            Case {
                label: "name with a colon",
                name: "us:er",
                field: "name",
                reason: Reason::BadCharacter,
                ..Case::valid()
            },
            Case {
                label: "name with a space",
                name: "us er",
                field: "name",
                reason: Reason::BadCharacter,
                ..Case::valid()
            },
            Case {
                label: "name over 32 characters",
                name: "aaaaaaaaaabbbbbbbbbbccccccccccddd",
                field: "name",
                reason: Reason::TooLong,
                ..Case::valid()
            },
            Case {
                label: "uid 0 — this binary never claims to be root",
                uid: 0,
                field: "uid",
                reason: Reason::RootUid,
                ..Case::valid()
            },
        ];

        for case in &cases {
            let label = case.label;
            match PasswdEntry::new(case.name, case.uid, 0, case.gecos, case.home, case.shell) {
                Ok(entry) => unreachable!("{label}: accepted, and rendered as {entry}"),
                Err(err) => {
                    assert_eq!(err.field, case.field, "{label}: wrong field");
                    assert_eq!(err.reason, case.reason, "{label}: wrong reason");
                }
            }
        }
    }

    #[test]
    fn group_entry_applies_the_same_name_and_uid_rules() {
        assert_eq!(GroupEntry::new("-user", 1000).unwrap_err().field, "name");
        assert_eq!(
            GroupEntry::new("user", 0).unwrap_err().reason,
            Reason::RootUid
        );
    }

    #[test]
    fn a_name_at_exactly_the_limit_is_accepted() {
        let name = "a".repeat(MAX_NAME_LEN);
        assert!(GroupEntry::new(&name, 1000).is_ok());
    }

    #[test]
    fn dots_underscores_and_inner_dashes_are_accepted() {
        assert!(GroupEntry::new("a.b_c-d", 1000).is_ok());
    }
}
