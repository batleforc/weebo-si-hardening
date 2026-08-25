//! DevWorkspace Operator's automount vocabulary, and the one rule this brick applies to it.
//!
//! **The only module in this crate that knows DevWorkspace Operator exists.** Everything else
//! copies an opaque object from one namespace to another; this module is where the labels and
//! annotations that make that copy *mean* something live, so a change to that contract upstream
//! is a single-module change here (RFC 0007's *Operational considerations → Upgrade*).
//!
//! The contract is documented behaviour, not a versioned API — see
//! <https://github.com/devfile/devworkspace-operator/blob/main/docs/additional-configuration.adoc>.
//! Pinned at the version in use when this was written; RFC 0007's *Unresolved questions* asks for
//! the `mount-as` values and the default-when-absent to be reconfirmed against the running DWO,
//! which is exactly what [`MountAs::parse`] and [`admit`] below encode.

use std::collections::BTreeMap;
use std::fmt;

/// The label DevWorkspace Operator watches for. An object without it is copied nowhere useful:
/// it would land in the namespace and never reach a container.
pub const MOUNT_TO_DEVWORKSPACE_LABEL: &str = "controller.devfile.io/mount-to-devworkspace";

/// The annotation choosing *how* a mounted object reaches a container.
pub const MOUNT_AS_ANNOTATION: &str = "controller.devfile.io/mount-as";

/// The annotation choosing *where* a mounted object lands.
pub const MOUNT_PATH_ANNOTATION: &str = "controller.devfile.io/mount-path";

/// How DevWorkspace Operator delivers a mounted object into a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountAs {
    /// The object becomes a **directory** at `mount-path`, containing one file per key. DWO's
    /// default when the annotation is absent, and the shape behind the whole
    /// [`TemplateRefusal::MountShadowsPath`] rule: a `ConfigMap` mounted `file` at `/home/user`
    /// *replaces* the home directory.
    File,
    /// Each key is placed individually at `mount-path`, leaving the rest of the directory alone.
    /// What almost every entry in a real catalogue wants.
    Subpath,
    /// Each key becomes an environment variable. The one delivery that outranks a project-local
    /// configuration file — see RFC 0007's *Bypass*.
    Env,
    /// A value this brick does not recognise. Carried rather than rejected: DevWorkspace
    /// Operator owns this vocabulary, and a value added upstream should not make this operator
    /// refuse an object it would have handled correctly. Treated as *not* `File` by [`admit`],
    /// since the shadowing failure is specific to `file`'s directory semantics.
    Unknown,
}

impl MountAs {
    /// Read `mount-as` from an annotation map.
    ///
    /// **An absent annotation is [`MountAs::File`]**, matching DevWorkspace Operator's own
    /// default rather than the safer-looking `Subpath`. Encoding the real default is what makes
    /// [`admit`] refuse the template that would silently empty a home directory; encoding a
    /// convenient one would make this whole module report success on exactly that case.
    pub fn parse(annotations: &BTreeMap<String, String>) -> Self {
        match annotations
            .get(MOUNT_AS_ANNOTATION)
            .map(String::as_str)
            .map(str::trim)
        {
            None | Some("") | Some("file") => Self::File,
            Some("subpath") => Self::Subpath,
            Some("env") => Self::Env,
            Some(_) => Self::Unknown,
        }
    }
}

impl fmt::Display for MountAs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::File => "file",
            Self::Subpath => "subpath",
            Self::Env => "env",
            Self::Unknown => "<unknown>",
        })
    }
}

/// Why a template was refused before it was ever copied.
///
/// The complete list of content this brick inspects at all. Everything else about a template —
/// its `data`, its `type`, its other labels — travels verbatim and is never read, per RFC 0007's
/// *Guide-level explanation*: "This brick never reads `data`."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateRefusal {
    /// The template does not carry `controller.devfile.io/mount-to-devworkspace: "true"`, so
    /// copying it would put an object in a workspace namespace that reaches no container.
    /// Refused rather than copied, because a copy nobody mounts is indistinguishable from a
    /// working configuration until a build fails.
    NotAutomountable,
    /// The template would mount as a **directory** over a home or dot-directory, replacing it.
    ///
    /// The single most common way this goes wrong, and the reason this module exists: no shell
    /// history, no IDE settings and — depending on the image — no writable home, presenting as a
    /// broken image rather than a broken config.
    MountShadowsPath,
}

impl TemplateRefusal {
    /// The `reason` label on `weebo_si_registry_template_invalid_total`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotAutomountable => "not_automountable",
            Self::MountShadowsPath => "mount_shadows_path",
        }
    }
}

impl fmt::Display for TemplateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAutomountable => write!(
                f,
                "template carries no {MOUNT_TO_DEVWORKSPACE_LABEL} label, so a copy of it would \
                 never reach a container"
            ),
            Self::MountShadowsPath => write!(
                f,
                "template mounts as a directory over a home or dot-directory, which would \
                 replace it — set {MOUNT_AS_ANNOTATION}: subpath"
            ),
        }
    }
}

/// Whether an object carries the automount label with a value DevWorkspace Operator acts on.
///
/// `"true"` only. DWO reads the label's value, and anything else is an object it leaves alone —
/// so an entry whose template says `"True"` or `"yes"` is an entry that silently does nothing,
/// which is the failure this check exists to turn into a `Degraded` condition.
pub fn is_automountable(labels: &BTreeMap<String, String>) -> bool {
    labels
        .get(MOUNT_TO_DEVWORKSPACE_LABEL)
        .is_some_and(|value| value.trim() == "true")
}

/// Whether a mount at `path` would replace a directory a workspace depends on.
///
/// True for a home directory (`/`, `/home`, `/home/<user>`, `/root`, `/root/<anything>`) and for
/// any path whose final segment is a dot-directory (`/home/user/.config`, `/.cache`). Both are
/// directories whose *other* contents matter: replacing them wholesale is the failure, and
/// neither is something an admin ever means to do.
///
/// A path one level deeper than a home (`/home/user/mirror`) is fine — it is a directory this
/// object is entitled to own outright — and so is a path outside them entirely (`/etc/pip.conf`
/// is a *file* path DWO would create the parent of).
pub fn shadows_directory(path: &str) -> bool {
    let trimmed = path.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        // "" or "/" — the container's root. Nothing is more shadowing than this.
        return true;
    }

    let segments: Vec<&str> = trimmed
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    if let Some(last) = segments.last()
        && last.starts_with('.')
    {
        return true;
    }

    match segments.as_slice() {
        ["home"] | ["root"] => true,
        // `/home/<user>` — the home directory itself. Anything below it is not shadowing.
        ["home", _] => true,
        // `/root` is itself a home, so `/root/<anything>` at depth 2 is *inside* one and fine;
        // the dot-directory check above already covers `/root/.config`.
        _ => false,
    }
}

/// Whether a template may be copied at all, given its own labels and annotations.
///
/// This is the whole of the content inspection RFC 0007 permits — "an explicit, enumerable
/// exception to 'this brick does not read templates', and one that exists because the failure it
/// prevents is silent, total, and looks like a broken image rather than a broken config."
///
/// A template with no `mount-path` at all is admissible: DevWorkspace Operator falls back to its
/// own default location (`/etc/config/...`), which is not a directory a workspace depends on.
pub fn admit(
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
) -> Result<(), TemplateRefusal> {
    if !is_automountable(labels) {
        return Err(TemplateRefusal::NotAutomountable);
    }

    // Only `file` replaces a directory. `subpath` places keys individually, and `env` never
    // touches the filesystem at all — so neither can shadow anything, whatever the path says.
    if MountAs::parse(annotations) != MountAs::File {
        return Ok(());
    }

    match annotations.get(MOUNT_PATH_ANNOTATION) {
        Some(path) if shadows_directory(path) => Err(TemplateRefusal::MountShadowsPath),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn automountable() -> BTreeMap<String, String> {
        map(&[(MOUNT_TO_DEVWORKSPACE_LABEL, "true")])
    }

    #[test]
    fn an_absent_mount_as_is_file_not_subpath() {
        // DevWorkspace Operator's own default. Encoding the convenient answer here would make
        // `admit` pass exactly the template that empties a home directory.
        assert_eq!(MountAs::parse(&BTreeMap::new()), MountAs::File);
    }

    #[test]
    fn the_three_known_mount_as_values_parse() {
        for (raw, expected) in [
            ("file", MountAs::File),
            ("subpath", MountAs::Subpath),
            ("env", MountAs::Env),
        ] {
            assert_eq!(
                MountAs::parse(&map(&[(MOUNT_AS_ANNOTATION, raw)])),
                expected
            );
        }
    }

    #[test]
    fn an_unrecognised_mount_as_is_carried_rather_than_refused() {
        // DWO owns this vocabulary. A value added upstream must not make this operator refuse an
        // object it would otherwise have handled.
        assert_eq!(
            MountAs::parse(&map(&[(MOUNT_AS_ANNOTATION, "something-new")])),
            MountAs::Unknown
        );
    }

    #[test]
    fn only_the_literal_true_counts_as_automountable() {
        assert!(is_automountable(&automountable()));
        for value in ["True", "yes", "1", ""] {
            assert!(
                !is_automountable(&map(&[(MOUNT_TO_DEVWORKSPACE_LABEL, value)])),
                "{value:?} is not what DevWorkspace Operator acts on"
            );
        }
    }

    #[test]
    fn a_template_without_the_automount_label_is_refused() {
        assert_eq!(
            admit(&BTreeMap::new(), &BTreeMap::new()),
            Err(TemplateRefusal::NotAutomountable)
        );
    }

    #[test]
    fn the_rfcs_own_example_is_admitted() {
        // `mount-as: subpath`, `mount-path: /home/user` — the working shape RFC 0007 shows.
        assert_eq!(
            admit(
                &automountable(),
                &map(&[
                    (MOUNT_AS_ANNOTATION, "subpath"),
                    (MOUNT_PATH_ANNOTATION, "/home/user"),
                ]),
            ),
            Ok(())
        );
    }

    #[test]
    fn the_same_path_mounted_as_file_is_refused() {
        assert_eq!(
            admit(
                &automountable(),
                &map(&[
                    (MOUNT_AS_ANNOTATION, "file"),
                    (MOUNT_PATH_ANNOTATION, "/home/user"),
                ]),
            ),
            Err(TemplateRefusal::MountShadowsPath)
        );
    }

    #[test]
    fn an_absent_mount_as_over_a_home_is_refused_too() {
        // The commonest spelling of the failure: nobody writes `mount-as: file`, they omit it.
        assert_eq!(
            admit(
                &automountable(),
                &map(&[(MOUNT_PATH_ANNOTATION, "/home/user")]),
            ),
            Err(TemplateRefusal::MountShadowsPath)
        );
    }

    #[test]
    fn homes_roots_and_dot_directories_all_shadow() {
        for path in [
            "/",
            "",
            "/home",
            "/home/user",
            "/home/user/",
            "/root",
            "/root/.config",
            "/home/user/.cache",
            "/.npm",
        ] {
            assert!(shadows_directory(path), "{path} should shadow");
        }
    }

    #[test]
    fn an_ordinary_directory_below_a_home_does_not_shadow() {
        for path in [
            "/home/user/mirror",
            "/etc/pip.conf",
            "/etc",
            "/opt/conf",
            "/usr/local/share/npm",
        ] {
            assert!(!shadows_directory(path), "{path} should not shadow");
        }
    }

    #[test]
    fn an_env_mount_over_a_home_path_is_admitted() {
        // `env` never touches the filesystem, so a `mount-path` alongside it is inert rather
        // than dangerous — refusing it would refuse a working entry.
        assert_eq!(
            admit(
                &automountable(),
                &map(&[
                    (MOUNT_AS_ANNOTATION, "env"),
                    (MOUNT_PATH_ANNOTATION, "/home/user"),
                ]),
            ),
            Ok(())
        );
    }

    #[test]
    fn a_template_with_no_mount_path_at_all_is_admitted() {
        // DWO falls back to its own default location, which is not a directory anyone depends on.
        assert_eq!(admit(&automountable(), &BTreeMap::new()), Ok(()));
    }

    #[test]
    fn every_refusal_has_a_distinct_metric_label() {
        assert_ne!(
            TemplateRefusal::NotAutomountable.label(),
            TemplateRefusal::MountShadowsPath.label()
        );
    }
}
