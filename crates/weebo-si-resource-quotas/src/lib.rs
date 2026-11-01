//! The `resource-quotas` feature — see RFC 0014.
//!
//! **What is decided here**, tested without a cluster:
//!
//! * **One profile per namespace** ([`resolve`]): the annotation picks among granted profiles,
//!   otherwise the team's or the cluster's default.
//! * **Whether a profile is safe to write** ([`model::validate`]): a compute quota with no default
//!   for a container that states nothing is a pod-creation outage, and is refused before it
//!   reaches a namespace.
//! * **What happens when it is not**: the namespace keeps what it has. An invalid profile, a
//!   refused request or an empty template cache never means "remove the existing ceiling".
//!
//! Enforcement is the apiserver's own `ResourceQuota` and `LimitRanger` admission; this crate only
//! decides which objects exist.

pub mod application;
pub mod feature;
pub mod model;
pub mod port;
pub mod resolve;

pub use application::{NamespaceState, ReconcileOutcome, ReconcileResult, reconcile, teardown};
pub use feature::resource_quotas::{DesiredState, NamespaceSubject, ResourceQuotasFeature};
pub use model::object::{
    FIELD_MANAGER, LIMITS_NAME, ManagedQuotaObject, QUOTA_NAME, QuotaKind, SaturationBand,
    saturation,
};
pub use model::quantity::{Quantity, QuantityError};
pub use model::template::{LimitItem, LimitRangeTemplate, QuotaTemplate};
pub use model::usage::{Over, PodResources, over};
pub use model::validate::{ProfileViolation, TemplateKind, ValidProfile, validate};
pub use port::{
    ForeignObjects, ManagedQuotaStore, QuotaTemplateStore, QuotaUsage, ReconcileObserver,
};
pub use resolve::{NotGranted, Provenance, ResolutionStep, resolve};
