//! The `team-tools` feature's adapters (RFC 0020): the template cache, the object store with its
//! per-tools-namespace watches and the `/scale` writer, and one reconcile pass per subject.

pub mod kube_template_store;
pub mod kube_tool_store;
pub mod objects;
pub mod port;
pub mod reconcile;

pub use kube_template_store::KubeToolTemplateStore;
pub use kube_tool_store::{KubeToolStore, Watch};
pub use port::{Adoption, StoreError, ToolObjectStore};
pub use reconcile::{
    Converged, RequesterOutcome, ScaleWrite, ToolOutcome, WorkspaceOutcome, reconcile_requester,
    reconcile_tool, reconcile_workspace,
};
