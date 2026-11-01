//! The two objects this feature writes into a namespace, and the saturation of the one that
//! counts — RFC 0014's *What is written* and *Observability contract*.

use std::collections::BTreeMap;

use weebo_si_chassis::{ObjectKey, managed::Managed};
use weebo_si_crd::{NamespaceName, QuotaProfileKey};

use crate::model::quantity::Quantity;

/// The name of the `ResourceQuota` this feature writes. Fixed: one per namespace.
pub const QUOTA_NAME: &str = "weebo-quota";
/// The name of the `LimitRange` this feature writes. Fixed: one per namespace.
pub const LIMITS_NAME: &str = "weebo-limits";
/// The server-side apply field manager.
pub const FIELD_MANAGER: &str = "weebo-si-resource-quotas";

/// Which kind of object. Plays the chassis diff's `Backend` role: the store needs it to know which
/// API a delete goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QuotaKind {
    /// `weebo-quota`.
    ResourceQuota,
    /// `weebo-limits`.
    LimitRange,
}

impl QuotaKind {
    /// The object name this kind is always written under.
    pub fn object_name(self) -> &'static str {
        match self {
            Self::ResourceQuota => QUOTA_NAME,
            Self::LimitRange => LIMITS_NAME,
        }
    }

    /// The Kubernetes kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ResourceQuota => "ResourceQuota",
            Self::LimitRange => "LimitRange",
        }
    }
}

/// One managed object: a template's `spec` under a fixed name, with the profile it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct ManagedQuotaObject {
    /// `{namespace, weebo-quota | weebo-limits}`.
    pub key: ObjectKey,
    /// Which kind.
    pub kind: QuotaKind,
    /// The profile key, written as `hardening.weebo.io/profile`.
    pub profile: QuotaProfileKey,
    /// The template's `spec`, unchanged.
    pub spec: serde_json::Value,
    /// The uid the store listed it with; `None` for a desired object.
    pub uid: Option<String>,
}

impl ManagedQuotaObject {
    /// The object `kind` a profile writes into `namespace`.
    pub fn desired(
        namespace: &NamespaceName,
        kind: QuotaKind,
        profile: &QuotaProfileKey,
        spec: serde_json::Value,
    ) -> Self {
        Self {
            key: ObjectKey {
                namespace: namespace.clone(),
                name: kind.object_name().to_string(),
            },
            kind,
            profile: profile.clone(),
            spec,
            uid: None,
        }
    }
}

impl Managed for ManagedQuotaObject {
    type Backend = QuotaKind;

    fn key(&self) -> &ObjectKey {
        &self.key
    }

    fn backend(&self) -> QuotaKind {
        self.kind
    }

    /// Same kind, same profile label, same `spec`. A profile switched to another one with the
    /// same templates still rewrites the label, so `kubectl get -l hardening.weebo.io/profile=…`
    /// stays true.
    fn content_eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.profile == other.profile && self.spec == other.spec
    }

    fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }
}

/// `weebo_si_resource_quotas_saturation`'s `band`: a namespace by its most-used resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SaturationBand {
    /// Every resource under 80 % of its hard limit.
    Under80,
    /// The most-used resource between 80 % and 99 %.
    From80To99,
    /// At least one resource at or above its hard limit: the next pod is refused.
    AtLimit,
}

impl SaturationBand {
    /// Every band, for a gauge that publishes its zeroes.
    pub const ALL: [SaturationBand; 3] = [Self::Under80, Self::From80To99, Self::AtLimit];

    /// The metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Under80 => "under_80",
            Self::From80To99 => "80_to_99",
            Self::AtLimit => "at_limit",
        }
    }
}

/// The band of a quota from its `status.hard` and `status.used`. A resource with a hard limit of
/// `0` is a ban rather than a budget, and counts only once something uses it. `None` when the
/// status names nothing comparable yet (the quota controller has not filled it in).
pub fn saturation(
    hard: &BTreeMap<String, String>,
    used: &BTreeMap<String, String>,
) -> Option<SaturationBand> {
    let mut worst: Option<i128> = None;
    for (resource, limit) in hard {
        let (Ok(limit), Some(Ok(usage))) = (
            Quantity::parse(limit),
            used.get(resource).map(|value| Quantity::parse(value)),
        ) else {
            continue;
        };
        let per_mille = match usage.per_mille_of(limit) {
            Some(per_mille) => per_mille,
            None if usage.nanos() > 0 => 1000,
            None => continue,
        };
        worst = Some(worst.map_or(per_mille, |worst| worst.max(per_mille)));
    }
    worst.map(|per_mille| match per_mille {
        ..800 => SaturationBand::Under80,
        800..1000 => SaturationBand::From80To99,
        _ => SaturationBand::AtLimit,
    })
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
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn the_band_is_the_most_used_resource() {
        let hard = map(&[("requests.cpu", "4"), ("pods", "20")]);
        assert_eq!(
            saturation(&hard, &map(&[("requests.cpu", "1"), ("pods", "2")])),
            Some(SaturationBand::Under80)
        );
        assert_eq!(
            saturation(&hard, &map(&[("requests.cpu", "3500m"), ("pods", "2")])),
            Some(SaturationBand::From80To99)
        );
        assert_eq!(
            saturation(&hard, &map(&[("requests.cpu", "1"), ("pods", "23")])),
            Some(SaturationBand::AtLimit)
        );
    }

    #[test]
    fn a_zero_limit_is_a_ban_that_counts_only_once_used() {
        let hard = map(&[("services.nodeports", "0"), ("pods", "20")]);
        assert_eq!(
            saturation(&hard, &map(&[("services.nodeports", "0"), ("pods", "1")])),
            Some(SaturationBand::Under80)
        );
        assert_eq!(
            saturation(&hard, &map(&[("services.nodeports", "1"), ("pods", "1")])),
            Some(SaturationBand::AtLimit)
        );
    }

    #[test]
    fn no_status_yet_is_no_band() {
        assert_eq!(saturation(&map(&[("pods", "20")]), &BTreeMap::new()), None);
    }

    #[test]
    fn content_ignores_the_uid_and_follows_the_profile() {
        let namespace = NamespaceName::new("user-bob");
        let spec = serde_json::json!({"hard": {"pods": "20"}});
        let desired = ManagedQuotaObject::desired(
            &namespace,
            QuotaKind::ResourceQuota,
            &QuotaProfileKey::new("standard"),
            spec.clone(),
        );
        let mut listed = desired.clone();
        listed.uid = Some("abc".to_string());
        assert!(desired.content_eq(&listed));
        let other = ManagedQuotaObject::desired(
            &namespace,
            QuotaKind::ResourceQuota,
            &QuotaProfileKey::new("large"),
            spec,
        );
        assert!(!desired.content_eq(&other));
        assert_eq!(desired.key.name, "weebo-quota");
    }
}
