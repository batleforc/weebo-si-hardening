//! Request resolution — RFC 0020, *Behaviour rules* "Attribute absent versus empty" and
//! "Request". Pure: the teams, the configuration, the namespace's labels and the raw attribute.

use std::collections::{BTreeMap, HashSet};

use weebo_si_crd::{MAX_REQUESTED_TOOLS, ResolvedTeamToolsConfig, Team, TeamName, ToolKey};

use crate::validate::validate_team;

/// What a key that is not a catalogue-shaped key (a DNS label of at most 40 characters) is echoed
/// as. The attribute is user-written and is quoted back in the verdict annotation, warnings and
/// denials: only a key the CRD could have admitted is quoted as is.
pub const INVALID_KEY: &str = "<invalid>";

/// One workspace's request, resolved against its team's grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// The team the namespace belongs to, if any.
    pub team: Option<TeamName>,
    /// The keys this workspace gets, in request order, each in the team's `allowed`.
    pub granted: Vec<ToolKey>,
    /// The requested keys the team is not granted.
    pub dropped: Vec<ToolKey>,
}

fn is_key_shaped(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 40
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

/// Parse the attribute: a comma-separated list, trimmed, empty segments dropped, deduplicated in
/// order, **at most 8** (RFC 0020, D3). A ninth distinct key stops the read and is reported as
/// [`INVALID_KEY`], so the overflow is refused or warned about, never silently lost.
pub fn parse_keys(raw: &str) -> Vec<ToolKey> {
    let mut seen = HashSet::new();
    let mut keys: Vec<ToolKey> = raw
        .split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if is_key_shaped(segment) {
                segment
            } else {
                INVALID_KEY
            }
        })
        .filter(|segment| seen.insert(*segment))
        .take(MAX_REQUESTED_TOOLS.saturating_add(1))
        .map(ToolKey::new)
        .collect();
    let invalid = ToolKey::new(INVALID_KEY);
    if keys.len() > MAX_REQUESTED_TOOLS {
        keys.truncate(MAX_REQUESTED_TOOLS);
        if !keys.contains(&invalid) {
            keys.push(invalid);
        }
    }
    keys
}

/// The first team whose `namespaceSelector` matches `labels` — teams are ordered, first match
/// wins, as every feature resolves them.
pub fn team_for<'a>(teams: &'a [Team], labels: &BTreeMap<String, String>) -> Option<&'a Team> {
    teams
        .iter()
        .find(|team| team.namespace_selector.matches(labels))
}

/// Resolve one workspace's request.
///
/// - `attribute` `None` (absent, or the configured attribute name is `""`) is the team's
///   `default`; `Some("")` is "no tool", even if the
///   team has a default.
/// - A namespace with no team, a team with no block, or a team whose block fails
///   [`validate_team`] (RFC 0020: "team block ignored") grants nothing: every requested key is
///   dropped.
/// - Each key is checked against `allowed`; an ungranted key is dropped. Whether a drop refuses
///   the admission is the gate's decision ([`crate::workspace_gate`]), never this function's.
pub fn resolve(
    teams: &[Team],
    config: &ResolvedTeamToolsConfig,
    namespace_labels: &BTreeMap<String, String>,
    attribute: Option<&str>,
) -> Request {
    let team = team_for(teams, namespace_labels);
    let grant = team
        .and_then(|team| config.grants.get(team.name.as_str()))
        .filter(|grant| validate_team(grant, &config.catalog).is_empty());
    // `workspaceSelection.attribute: ""` disables the request step, as network-profiles' does:
    // whatever the adapter extracted is ignored and the team default applies.
    let attribute = attribute.filter(|_| !config.workspace_selection.attribute.is_empty());
    let requested = match attribute {
        Some(raw) => parse_keys(raw),
        None => grant
            .map(|grant| {
                grant
                    .default
                    .iter()
                    .take(MAX_REQUESTED_TOOLS)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default(),
    };
    let (granted, dropped) = requested
        .into_iter()
        .partition(|key| grant.is_some_and(|grant| grant.allowed.contains(key)));
    Request {
        team: team.map(|team| team.name.clone()),
        granted,
        dropped,
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
    use crate::fixtures::{config_with, keys, team, weebo_labels};

    #[test]
    fn an_absent_attribute_is_the_team_default() {
        let config = config_with(&["buildkit"], &["buildkit"]);
        let request = resolve(&[team()], &config, &weebo_labels(), None);
        assert_eq!(request.granted, keys(&["buildkit"]));
        assert!(request.dropped.is_empty());
        assert_eq!(request.team.unwrap().as_str(), "weebo");
    }

    #[test]
    fn an_empty_attribute_is_no_tool_even_with_a_default() {
        let config = config_with(&["buildkit"], &["buildkit"]);
        let request = resolve(&[team()], &config, &weebo_labels(), Some(""));
        assert_eq!(request.granted, Vec::new());
        assert!(request.dropped.is_empty());
    }

    #[test]
    fn duplicates_are_removed_in_order_and_blanks_ignored() {
        assert_eq!(
            parse_keys(" buildkit, ,android,buildkit ,"),
            keys(&["buildkit", "android"])
        );
    }

    #[test]
    fn a_ninth_key_is_reported_as_invalid() {
        let parsed = parse_keys("k1,k2,k3,k4,k5,k6,k7,k8,k9,k10");
        assert_eq!(
            parsed,
            keys(&["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", INVALID_KEY])
        );
        assert_eq!(
            parse_keys("k1,k2,k3,k4,k5,k6,k7,k8").len(),
            MAX_REQUESTED_TOOLS
        );
        // An overflow is never granted: `<invalid>` is not a catalogue key.
        let config = config_with(&["k1"], &[]);
        let request = resolve(
            &[team()],
            &config,
            &weebo_labels(),
            Some("k1,k2,k3,k4,k5,k6,k7,k8,k9"),
        );
        assert!(request.dropped.contains(&ToolKey::new(INVALID_KEY)));
    }

    #[test]
    fn a_key_the_crd_could_not_admit_is_never_echoed() {
        assert_eq!(
            parse_keys("Build;kit=1,buildkit,a\u{202e}b,UPPER"),
            keys(&[INVALID_KEY, "buildkit"])
        );
        let long = "a".repeat(41);
        assert_eq!(parse_keys(&long), keys(&[INVALID_KEY]));
    }

    #[test]
    fn an_ungranted_key_is_dropped() {
        let config = config_with(&["buildkit"], &[]);
        let request = resolve(
            &[team()],
            &config,
            &weebo_labels(),
            Some("android,buildkit"),
        );
        assert_eq!(request.granted, keys(&["buildkit"]));
        assert_eq!(request.dropped, keys(&["android"]));
    }

    #[test]
    fn a_namespace_with_no_team_gets_no_tool_ever() {
        let config = config_with(&["buildkit"], &["buildkit"]);
        let request = resolve(&[team()], &config, &BTreeMap::new(), Some("buildkit"));
        assert_eq!(request.team, None);
        assert!(request.granted.is_empty());
        assert_eq!(request.dropped, keys(&["buildkit"]));
        assert_eq!(
            resolve(&[team()], &config, &BTreeMap::new(), None),
            Request::default()
        );
    }

    #[test]
    fn an_empty_attribute_name_disables_the_request_step() {
        let mut config = config_with(&["buildkit"], &[]);
        config.config.workspace_selection.attribute = String::new();
        let request = resolve(&[team()], &config, &weebo_labels(), Some("buildkit"));
        assert!(request.granted.is_empty() && request.dropped.is_empty());
    }

    #[test]
    fn an_invalid_team_block_grants_nothing() {
        // `default` outside `allowed`: the whole block is ignored.
        let config = config_with(&[], &["buildkit"]);
        let request = resolve(&[team()], &config, &weebo_labels(), Some("buildkit"));
        assert!(request.granted.is_empty());
        assert_eq!(request.dropped, keys(&["buildkit"]));
    }
}
