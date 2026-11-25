//! The `team-tools` feature — see RFC 0020.
//!
//! Tools a hardened workspace cannot run (BuildKit) live in a **tools namespace per team**, which
//! the admin declares, labels and binds in Git. This crate decides, without a cluster:
//!
//! * **Who gets what** ([`resolve`]): the devfile attribute, at most 8 keys, against the team's
//!   grant; an ungranted key is dropped, or refused at admission under `onNotGranted: Deny`
//!   ([`workspace_gate`]).
//! * **Whether a catalogue entry and a team block are safe to apply** ([`validate`]): the
//!   templates exist, are of an allowed kind, and the workload pod spec carries no privilege a
//!   template must not smuggle (token, host namespaces, `hostPath`, added capabilities).
//! * **Whether a tools namespace may be written at all** ([`bind`]): the admin's label, no
//!   workspace label, a memory quota.
//! * **How many replicas** ([`scale`]): 1 while a requester runs, then a grace, then 0.
//! * **What objects exist** ([`render`], [`feature`]): three subjects, the tool in the tools
//!   namespace, the client side in each requesting namespace, one egress policy per workspace.
//!
//! "The new configuration is broken" never means "delete the running tool": an invalid entry, an
//! invalid team block, an unbound namespace or an unsynced cache all **hold** what exists.

pub mod bind;
pub mod feature;
pub mod port;
pub mod render;
pub mod resolve;
pub mod scale;
pub mod validate;
pub mod workspace_gate;

pub use bind::{
    EXCLUDE_LABEL, ToolsNamespace, USERNAME_ANNOTATION, Unbound, WORKSPACE_NAMESPACE_LABEL,
    check_tools_namespace, client_identity, has_memory_quota,
};
pub use feature::{
    FEATURE_ID, RequesterDesired, RequesterNamespace, RequestingWorkspace, TeamTool,
    TeamToolsFeature, ToolDesired, WorkspaceDesired,
};
pub use port::{Clock, ToolTemplate, ToolTemplateStore};
pub use render::{FIELD_MANAGER, SCALE_FIELD_MANAGER, ToolObject, ToolObjectKind};
pub use resolve::{INVALID_KEY, Request, parse_keys, resolve, team_for};
pub use scale::{Phase, ScaleDecision, decide};
pub use validate::{
    EntryViolation, PodSpecViolation, TeamViolation, ValidEntry, parse_duration, validate_entry,
    validate_team,
};
pub use workspace_gate::{TeamToolsAdmission, ToolsOperation, ToolsWorkspaceAdmission};

#[cfg(test)]
mod fixtures;
