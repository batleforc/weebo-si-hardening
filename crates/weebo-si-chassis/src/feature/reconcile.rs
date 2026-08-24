//! `ReconcileFeature<S>` — the second feature shape RFC 0002 predicted and RFC 0004 needs: a
//! decision that is "objects that should exist somewhere else," not a patch to the object under
//! admission. See RFC 0004's *Design → Architecture*, "The chassis needs a second trait."

use super::registry::{Context, Subject};
use super::value::FeatureId;
use crate::error::DomainError;

/// One reconcile-shaped hardening behaviour, evaluated over one `Subject`.
///
/// **`Desired` is an associated type, not a fixed chassis type.** `Feature<S>::evaluate` returns
/// `Decision<S>`, a chassis-generic type, because a *mutation* is shared vocabulary
/// (`crate::Mutation` lives here). "Desired state" is not shared vocabulary across reconcile
/// features — it is resource-specific (`NetworkPolicy`/`CiliumNetworkPolicy` objects for
/// `network-profiles`, something else for whatever reconcile feature comes after it). Fixing the
/// return type here would make the chassis depend on a feature's own object model, which is
/// exactly the dependency direction `weebo-si-chassis`'s module doc forbids.
///
/// `Send + Sync` as a supertrait, matching [`crate::port::dwoc_catalog::DwocCatalog`]'s own
/// reasoning: a bare `&dyn ReconcileFeature<S>` parameter (`weebo-si-network-profiles`'s
/// `application::reconcile` takes one) needs it to make the `async fn` holding it `Send`.
pub trait ReconcileFeature<S: Subject>: Send + Sync {
    /// What this feature computes: the resource-specific "here is what should exist" value.
    type Desired;

    /// This feature's identifier.
    fn id(&self) -> FeatureId;

    /// Decide what should exist for `subject`. Never told which mode is in effect — the caller
    /// (an `application::reconcile` in the crate that owns the live cluster state) diffs the
    /// result against what is there and, only in `Enforce`, applies it. Mirrors `Feature::evaluate`'s
    /// mode-blindness for the same reason: a feature that could branch on its mode would make
    /// `DryRun` measure something other than what `Enforce` does.
    fn desired(&self, subject: &S, ctx: &Context<'_>) -> Result<Self::Desired, DomainError>;
}
