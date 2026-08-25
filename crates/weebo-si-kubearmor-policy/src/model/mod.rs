//! The reconcile-specific object model — the parts of it that are this feature's own. The
//! backend-agnostic parts (`ObjectKey`, `PodSelector`, the diff) are
//! [`weebo_si_chassis::managed`]'s, per RFC 0006's *Implementation plan*.

pub mod diff;
pub mod policy;
