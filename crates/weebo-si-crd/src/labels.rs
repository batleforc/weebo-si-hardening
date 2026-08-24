//! Well-known label/annotation keys `network-profiles` and `policy-guard` read and write. Per
//! RFC 0004's *Design*, "Stability": these strings are the contract, shared by
//! `weebo-si-runtime` (which writes them) and `weebo-si-webhook` (which reads them to answer
//! "is this object ours") — defined once here rather than as string literals in each.

/// Every object this feature owns carries this label, set to [`MANAGED_BY_VALUE`]. The
/// ownership boundary: the operator only ever reads, updates or deletes objects carrying it.
pub const MANAGED_BY_LABEL: &str = "hardening.weebo.io/managed-by";
/// [`MANAGED_BY_LABEL`]'s value on every object this operator writes.
pub const MANAGED_BY_VALUE: &str = "weebo-si-operator";
/// The catalogue key a managed object was built from.
pub const PROFILE_LABEL: &str = "hardening.weebo.io/profile";
/// Which dialect (`NetworkPolicy`/`Cilium`) a managed object is written in.
pub const BACKEND_LABEL: &str = "hardening.weebo.io/backend";
/// The label DevWorkspace Operator sets on a workspace's own pods, and the one a profile
/// object's `podSelector`/`endpointSelector` targets.
pub const DEVWORKSPACE_ID_LABEL: &str = "controller.devfile.io/devworkspace_id";
/// The enforcement canary's own objects (its two pods and the deny policy between them) carry
/// this label rather than [`MANAGED_BY_LABEL`], on purpose: they are not profile objects, they
/// live in the operator's own namespace, and nothing in the reconcile diff should ever consider
/// them. Its value is `server` or `client` on a pod, and `deny` on the policy.
pub const CANARY_LABEL: &str = "hardening.weebo.io/canary";
