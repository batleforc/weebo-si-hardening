//! The `image-policy` feature — see RFC 0005.
//!
//! Which container images a workspace is permitted to run, per team, on the RFC 0002 chassis: an
//! admin writes a catalogue of image patterns, grants each team a subset, and a workspace picks
//! inside what its team was granted. A pattern may interpolate `{TEAM_NAME}`, so a registry laid
//! out one path per team is one catalogue entry rather than a second copy of `spec.teams`.
//!
//! Fewest dependencies in the workspace, same as `weebo-si-dwoc-pin` and
//! `weebo-si-network-profiles`: `weebo-si-crd` + `weebo-si-chassis` only. This crate owns no
//! `k8s-openapi` type, makes no network call, and **never contacts a registry** — it judges
//! names, and names are in the admission request. That is a deliberate boundary rather than a
//! simplification: contacting a registry from admission would make the decision depend on a
//! third party's availability, put an attacker-supplied hostname into an outbound connection
//! from the operator's pod, and turn a five-millisecond verdict into a network round trip in
//! front of every pod creation in a workspace namespace.
//!
//! The module to review hardest is [`reference`], and [`pattern`] after it. Everything else is
//! bookkeeping over what those two decide.

pub mod feature;
pub mod pattern;
pub mod platform;
pub mod port;
pub mod reference;
pub mod resolve;
pub mod subject;
pub mod validate;
pub mod variable;
pub mod verdict;

pub use feature::core::FEATURE_ID;
pub use feature::pod_images::PodImagesFeature;
pub use feature::workspace_images::WorkspaceImagesFeature;
pub use pattern::{HostPattern, PathSegment, Pattern};
pub use platform::{BUILTIN_PLATFORM_PATTERNS, platform_patterns};
pub use port::{ImagePolicyObserver, Resource};
pub use reference::{ImageReference, MAX_REFERENCE_LEN, ParseError};
pub use resolve::{
    NotGranted, Provenance, ResolutionStep, allowed_set, effective_patterns, judge, resolve,
};
pub use subject::{ContainerImage, PodImages, WorkspaceImages};
pub use validate::{is_usable_variable, validate};
pub use variable::{
    NAMESPACE, PathComponent, TEAM_NAME, VariableName, VariableResult, VariableValues,
};
pub use verdict::{ImageVerdict, PermittedBy, Verdict, escape_reference};
