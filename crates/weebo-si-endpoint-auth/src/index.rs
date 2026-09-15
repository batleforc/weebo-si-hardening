//! Host to policy, and what happens when two objects claim one host.
//!
//! RFC 0009 calls this a security boundary rather than a lookup, and the reason is short: if the
//! gateway resolved a host to whichever object it happened to find, a second developer would open
//! a hole in the first one's endpoint with one manifest in their own namespace. So an ambiguity is
//! a denial — never a tie broken by sort order, by creation timestamp or by whichever watch
//! event arrived last, because every one of those lets an attacker pick the verdict.
//!
//! The index is also where RFC 0009's *Request cost* is paid or not paid. It is built on an
//! informer event, holds compiled [`EndpointPolicy`] values behind an [`Arc`], and is swapped
//! whole; a request clones an `Arc` and reads. Nothing here is built, parsed or resolved while a
//! request is waiting.

use std::collections::HashMap;
use std::collections::hash_map::Entry as MapEntry;
use std::sync::Arc;

use crate::host::Host;
use crate::identity::NamespaceName;
use crate::policy::EndpointPolicy;

/// Which routing object a policy came from — enough to name it in a `WARN`, and never enough to
/// become a metric label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectRef {
    /// The namespace the object lives in.
    pub namespace: NamespaceName,
    /// Its name.
    pub name: String,
}

impl ObjectRef {
    /// Name one object.
    pub fn new(namespace: &str, name: &str) -> Self {
        Self {
            namespace: NamespaceName::new(namespace),
            name: name.to_owned(),
        }
    }
}

/// One compiled endpoint, ready to be indexed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedEndpoint {
    /// The host this object claims.
    pub host: Host,
    /// The object that claims it.
    pub object: ObjectRef,
    /// Its compiled policy.
    pub policy: Arc<EndpointPolicy>,
}

/// Two or more objects claiming one host — the `weebo_si_endpoint_auth_host_conflicts` population,
/// and always either an attack or a bug, never routine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConflict {
    /// The contested host.
    pub host: Host,
    /// Everything that claimed it, in the order the index saw them.
    pub claimants: Vec<ObjectRef>,
}

/// What the index knows about a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogLookup {
    /// Exactly one object answers for this host.
    Policy(Arc<EndpointPolicy>),
    /// More than one does, so the question has no answer and the request is denied.
    Conflict,
    /// Nothing does.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    One(ObjectRef, Arc<EndpointPolicy>),
    Conflict(Vec<ObjectRef>),
}

/// Every governed host in the cluster, and the one policy that answers for it.
#[derive(Debug, Clone, Default)]
pub struct HostIndex {
    generation: u64,
    entries: HashMap<Host, Entry>,
    conflicts: Vec<HostConflict>,
}

impl HostIndex {
    /// Build an index from everything the informer currently holds.
    ///
    /// The same object appearing twice replaces itself rather than conflicting with itself — a
    /// rebuild is not an ambiguity. Two *different* objects claiming one host is, and both lose:
    /// denying only the newcomer would let a later manifest decide whose endpoint stops working.
    pub fn build(generation: u64, endpoints: impl IntoIterator<Item = IndexedEndpoint>) -> Self {
        let mut entries: HashMap<Host, Entry> = HashMap::new();
        for endpoint in endpoints {
            match entries.entry(endpoint.host) {
                MapEntry::Vacant(slot) => {
                    slot.insert(Entry::One(endpoint.object, endpoint.policy));
                }
                MapEntry::Occupied(mut slot) => match slot.get_mut() {
                    Entry::One(existing, _) if existing == &endpoint.object => {
                        slot.insert(Entry::One(endpoint.object, endpoint.policy));
                    }
                    Entry::One(existing, _) => {
                        let claimants = vec![existing.clone(), endpoint.object];
                        slot.insert(Entry::Conflict(claimants));
                    }
                    Entry::Conflict(claimants) => {
                        if !claimants.contains(&endpoint.object) {
                            claimants.push(endpoint.object);
                        }
                    }
                },
            }
        }
        let mut conflicts: Vec<HostConflict> = entries
            .iter()
            .filter_map(|(host, entry)| match entry {
                Entry::Conflict(claimants) => Some(HostConflict {
                    host: host.clone(),
                    claimants: claimants.clone(),
                }),
                Entry::One(..) => None,
            })
            .collect();
        conflicts.sort_by(|a, b| a.host.cmp(&b.host));
        Self {
            generation,
            entries,
            conflicts,
        }
    }

    /// The policy for `host`.
    pub fn lookup(&self, host: &Host) -> CatalogLookup {
        match self.entries.get(host) {
            Some(Entry::One(_, policy)) => CatalogLookup::Policy(Arc::clone(policy)),
            Some(Entry::Conflict(_)) => CatalogLookup::Conflict,
            None => CatalogLookup::Unknown,
        }
    }

    /// Which object answers for `host`, for a log line. `None` for an unknown or contested host.
    pub fn object_for(&self, host: &Host) -> Option<&ObjectRef> {
        match self.entries.get(host) {
            Some(Entry::One(object, _)) => Some(object),
            _ => None,
        }
    }

    /// The generation this index was built at.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// How many hosts are indexed — `weebo_si_endpoint_auth_indexed_endpoints`, and the input to
    /// every memory estimate in RFC 0009's *Capacity*.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty, which for a synced informer means the feature covers nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every contested host. A `WARN` each, never a metric label.
    pub fn conflicts(&self) -> &[HostConflict] {
        &self.conflicts
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
    use crate::testing::policy_for;

    fn endpoint(host: &str, namespace: &str, name: &str) -> IndexedEndpoint {
        IndexedEndpoint {
            host: Host::parse(host).unwrap(),
            object: ObjectRef::new(namespace, name),
            policy: Arc::new(policy_for(namespace, name)),
        }
    }

    #[test]
    fn one_object_answers_for_its_host() {
        let index = HostIndex::build(1, [endpoint("alice-ws-api.weebo.si", "user-alice", "api")]);
        let host = Host::parse("alice-ws-api.weebo.si").unwrap();
        let CatalogLookup::Policy(policy) = index.lookup(&host) else {
            panic!("expected a policy");
        };
        assert_eq!(policy.namespace, NamespaceName::new("user-alice"));
        assert_eq!(index.len(), 1);
        assert!(index.conflicts().is_empty());
    }

    #[test]
    fn a_second_namespace_claiming_a_host_makes_both_lose() {
        // The manifest in RFC 0009: bob writes an Ingress for alice's host. Answering with either
        // policy would be a verdict an attacker chose.
        let index = HostIndex::build(
            7,
            [
                endpoint("alice-ws-api.weebo.si", "user-alice", "api"),
                endpoint("alice-ws-api.weebo.si", "user-bob", "steal"),
            ],
        );
        let host = Host::parse("alice-ws-api.weebo.si").unwrap();
        assert_eq!(index.lookup(&host), CatalogLookup::Conflict);
        assert_eq!(index.object_for(&host), None);
        assert_eq!(index.conflicts().len(), 1);
        assert_eq!(index.conflicts()[0].claimants.len(), 2);
    }

    #[test]
    fn the_same_object_seen_twice_is_a_rebuild_and_not_a_conflict() {
        let index = HostIndex::build(
            2,
            [
                endpoint("alice-ws-api.weebo.si", "user-alice", "api"),
                endpoint("alice-ws-api.weebo.si", "user-alice", "api"),
            ],
        );
        let host = Host::parse("alice-ws-api.weebo.si").unwrap();
        assert!(matches!(index.lookup(&host), CatalogLookup::Policy(_)));
        assert!(index.conflicts().is_empty());
    }

    #[test]
    fn an_unindexed_host_is_unknown_rather_than_allowed() {
        let index = HostIndex::build(1, []);
        assert_eq!(
            index.lookup(&Host::parse("alice-ws-api.weebo.si").unwrap()),
            CatalogLookup::Unknown
        );
        assert!(index.is_empty());
        assert_eq!(index.generation(), 1);
    }
}
