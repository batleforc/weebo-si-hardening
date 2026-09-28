//! Merging one cluster catalogue with every team's — RFC 0011's *Resolution*.
//!
//! Six features, one rule, so it is written once and called six times rather than copied with
//! six sets of key types. The rule: **a catalogue key means one thing cluster-wide**. The cluster
//! catalogue comes first, teams follow in resolution order, and the first definition of a key
//! wins. A later, *different* definition of the same key is reported and dropped — the team that
//! wrote it still reaches the key, and reaches the winning definition, which is by construction
//! one an admin already reviewed.
//!
//! Team-scoped key namespaces (`platform/gpu`) were the alternative and are rejected in RFC
//! 0011: keys are typed by hand into namespace annotations and devfile attributes, printed by the
//! CLI and used as metric labels, and none of those three has a team to prefix with.

use std::collections::BTreeMap;

use crate::team::TeamName;

/// One team's redefinition of a key somebody already defined, differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogConflict<K> {
    /// The team whose entry lost.
    pub team: TeamName,
    /// The contested key.
    pub key: K,
}

/// Merge `cluster` with each team's entries, first definition winning.
///
/// Duplicate keys *within* the cluster catalogue are left alone: every feature already reports
/// them as its own `DuplicateKey` violation, and reporting them twice under two names would make
/// one typo look like two problems.
pub(crate) fn merge_catalogs<T, K>(
    cluster: &[T],
    teams: &[(TeamName, Vec<T>)],
    key_of: impl Fn(&T) -> K,
) -> (Vec<T>, Vec<CatalogConflict<K>>)
where
    T: Clone + PartialEq,
    K: Ord + Clone,
{
    let mut merged: Vec<T> = cluster.to_vec();
    let mut seen: BTreeMap<K, usize> = BTreeMap::new();
    for (index, entry) in merged.iter().enumerate() {
        seen.entry(key_of(entry)).or_insert(index);
    }

    let mut conflicts = Vec::new();
    for (team, entries) in teams {
        for entry in entries {
            let key = key_of(entry);
            match seen.get(&key) {
                Some(&index) => {
                    if merged.get(index) != Some(entry) {
                        conflicts.push(CatalogConflict {
                            team: team.clone(),
                            key,
                        });
                    }
                }
                None => {
                    seen.insert(key, merged.len());
                    merged.push(entry.clone());
                }
            }
        }
    }

    (merged, conflicts)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Entry {
        key: String,
        value: u8,
    }

    fn entry(key: &str, value: u8) -> Entry {
        Entry {
            key: key.to_string(),
            value,
        }
    }

    fn team(name: &str, entries: Vec<Entry>) -> (TeamName, Vec<Entry>) {
        (TeamName::new(name), entries)
    }

    #[test]
    fn team_entries_are_appended_to_the_cluster_catalogue() {
        let (merged, conflicts) = merge_catalogs(
            &[entry("baseline", 1)],
            &[team("platform", vec![entry("gpu", 2)])],
            |e| e.key.clone(),
        );
        assert_eq!(merged, vec![entry("baseline", 1), entry("gpu", 2)]);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn two_teams_declaring_one_key_identically_is_not_a_conflict() {
        let (merged, conflicts) = merge_catalogs(
            &[],
            &[
                team("platform", vec![entry("gpu", 2)]),
                team("research", vec![entry("gpu", 2)]),
            ],
            |e| e.key.clone(),
        );
        assert_eq!(merged, vec![entry("gpu", 2)]);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn a_redefinition_is_reported_and_the_first_definition_wins() {
        let (merged, conflicts) = merge_catalogs(
            &[],
            &[
                team("platform", vec![entry("gpu", 2)]),
                team("research", vec![entry("gpu", 9)]),
            ],
            |e| e.key.clone(),
        );
        assert_eq!(merged, vec![entry("gpu", 2)]);
        assert_eq!(
            conflicts,
            vec![CatalogConflict {
                team: TeamName::new("research"),
                key: "gpu".to_string(),
            }]
        );
    }

    #[test]
    fn a_team_cannot_shadow_a_cluster_entry() {
        let (merged, conflicts) = merge_catalogs(
            &[entry("baseline", 1)],
            &[team("platform", vec![entry("baseline", 99)])],
            |e| e.key.clone(),
        );
        assert_eq!(merged, vec![entry("baseline", 1)]);
        assert_eq!(conflicts.len(), 1);
    }
}
