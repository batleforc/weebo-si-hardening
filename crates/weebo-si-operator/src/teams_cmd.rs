//! `weebo-si-operator teams export` — RFC 0011's migration command.
//!
//! The one piece of this project that reads a shape the code no longer has a type for. RFC 0011
//! removed `spec.teams` and every per-feature `grants` map from the schema in one cut, which
//! leaves exactly one thing to build: something that reads the *old* singleton and writes the
//! `WeeboSiTeam` objects that replace it. It therefore works on raw JSON, deliberately, and the
//! only typed step is the last one — the rendered block is deserialized into
//! [`weebo_si_crd::WeeboSiTeamSpec`] before it is printed, so this command cannot emit a team the
//! CRD would refuse.
//!
//! **It writes nothing to the cluster.** It prints objects for an admin to read, keep and apply,
//! because RFC 0011's *Rollback* depends on the old manifest still existing somewhere after step
//! three has removed it from the cluster.

use std::collections::BTreeSet;

use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams};
use kube::{Client, ResourceExt};
use serde_json::{Value, json};
use weebo_si_crd::{SINGLETON_NAME, WeeboSiTeam, WeeboSiTeamSpec};

use crate::cli::{flag, has_flag};

/// The priority the first team in `spec.teams` gets; each later team gets a multiple of it.
///
/// Document order was the old precedence rule and this is what replaces it, spaced out so an
/// admin can insert a team between two others without renumbering the file.
const PRIORITY_STEP: i32 = 100;

/// Route the `teams` subcommand.
pub async fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("export") => export(&args[1..]).await,
        Some(other) => Err(format!(
            "unrecognized teams subcommand '{other}' (expected export)"
        )),
        None => Err("teams needs a subcommand: export".to_string()),
    }
}

/// `teams export [--from <file>] [--check]`.
async fn export(args: &[String]) -> Result<(), String> {
    let spec = match flag(args, "--from") {
        Some(path) => from_file(path)?,
        None => from_cluster().await?,
    };

    let Exported { teams, warnings } = teams_from(&spec)?;
    for warning in &warnings {
        eprintln!("weebo-si-operator: {warning}");
    }

    if has_flag(args, "--check") {
        return check(&teams).await;
    }

    if teams.is_empty() {
        eprintln!(
            "weebo-si-operator: this configuration declares no team, so there is nothing to \
             export — remove spec.teams and the grants maps and you are migrated"
        );
        return Ok(());
    }

    for (index, team) in teams.iter().enumerate() {
        if index > 0 {
            println!("---");
        }
        let yaml = serde_yaml_bw::to_string(team)
            .map_err(|err| format!("could not render team {}: {err}", team.name_any()))?;
        print!("{yaml}");
    }

    eprintln!(
        "weebo-si-operator: {} team(s) exported. Apply them, run 'teams export --check' to \
         confirm, and only then remove spec.teams and every grants map from the singleton.",
        teams.len()
    );
    Ok(())
}

/// The old singleton's `spec`, read from a manifest an admin still has.
fn from_file(path: &str) -> Result<Value, String> {
    let text =
        std::fs::read_to_string(path).map_err(|err| format!("could not read {path}: {err}"))?;
    let document: Value =
        serde_yaml_bw::from_str(&text).map_err(|err| format!("could not parse {path}: {err}"))?;
    document
        .get("spec")
        .cloned()
        .ok_or_else(|| format!("{path} carries no spec block"))
}

/// The old singleton's `spec`, read from the live cluster.
///
/// Read as a `DynamicObject` rather than as a `WeeboSiConfig`: the typed deserialization would
/// drop `spec.teams` and every `grants` map on the floor, which are the only fields this command
/// exists to read.
async fn from_cluster() -> Result<Value, String> {
    let client = Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let gvk = GroupVersionKind::gvk("hardening.weebo.io", "v1alpha1", "WeeboSiConfig");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "weebosiconfigs");
    let api: Api<DynamicObject> = Api::all_with(client, &resource);
    let config = api
        .get(SINGLETON_NAME)
        .await
        .map_err(|err| format!("could not read WeeboSiConfig/{SINGLETON_NAME}: {err}"))?;
    config
        .data
        .get("spec")
        .cloned()
        .ok_or_else(|| format!("WeeboSiConfig/{SINGLETON_NAME} carries no spec block"))
}

/// Compare what the cluster holds against what the old singleton says it should.
async fn check(expected: &[WeeboSiTeam]) -> Result<(), String> {
    let client = Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let api: Api<WeeboSiTeam> = Api::all(client);
    let live = api
        .list(&ListParams::default())
        .await
        .map_err(|err| format!("could not list WeeboSiTeam objects: {err}"))?
        .items;

    let verdicts = compare(expected, &live);
    let problems = verdicts
        .iter()
        .filter(|(_, verdict)| verdict.is_problem())
        .count();
    for (name, verdict) in &verdicts {
        println!("{name}: {verdict}");
    }

    if problems > 0 {
        return Err(format!(
            "{problems} team(s) are not applied as the singleton describes them"
        ));
    }
    println!("every team the singleton declares is applied as declared");
    Ok(())
}

/// What `--check` found about one team.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Applied, and what the singleton says.
    Applied,
    /// The singleton declares it and the cluster does not have it.
    Missing,
    /// Applied, but not as the singleton describes it.
    Differs,
    /// In the cluster, not in the singleton. **Not a problem**: a team created since the
    /// migration is the normal case once this has been run. Printed because a typo'd name looks
    /// exactly like one.
    Extra,
}

impl Verdict {
    fn is_problem(self) -> bool {
        matches!(self, Self::Missing | Self::Differs)
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Applied => write!(f, "ok"),
            Self::Missing => write!(f, "MISSING — not applied yet"),
            Self::Differs => {
                write!(
                    f,
                    "DIFFERS — the applied object is not what the singleton says"
                )
            }
            Self::Extra => write!(f, "extra — in the cluster, not in the singleton"),
        }
    }
}

/// The diff itself, over values: expected teams first, in their own order, then whatever else the
/// cluster holds.
fn compare(expected: &[WeeboSiTeam], live: &[WeeboSiTeam]) -> Vec<(String, Verdict)> {
    let mut verdicts: Vec<(String, Verdict)> = expected
        .iter()
        .map(|team| {
            let name = team.name_any();
            let verdict = match live.iter().find(|candidate| candidate.name_any() == name) {
                None => Verdict::Missing,
                Some(applied) if applied.spec != team.spec => Verdict::Differs,
                Some(_) => Verdict::Applied,
            };
            (name, verdict)
        })
        .collect();

    let expected_names: BTreeSet<String> = expected.iter().map(ResourceExt::name_any).collect();
    verdicts.extend(
        live.iter()
            .map(ResourceExt::name_any)
            .filter(|name| !expected_names.contains(name))
            .map(|name| (name, Verdict::Extra)),
    );
    verdicts
}

/// Every team the old singleton declares, and everything dropped on the way.
struct Exported {
    teams: Vec<WeeboSiTeam>,
    warnings: Vec<String>,
}

/// The conversion itself: `spec.teams` plus every `grants` map, into one object per team.
fn teams_from(spec: &Value) -> Result<Exported, String> {
    let declared = spec
        .get("teams")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let features = spec.get("features").cloned().unwrap_or(json!({}));

    let names: BTreeSet<String> = declared
        .iter()
        .filter_map(|team| team.get("name").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();

    let mut warnings = Vec::new();
    for (feature, _, _) in FEATURES {
        let Some(grants) = features.get(feature).and_then(|block| block.get("grants")) else {
            continue;
        };
        let Some(grants) = grants.as_object() else {
            continue;
        };
        for team in grants.keys() {
            if !names.contains(team.as_str()) {
                warnings.push(format!(
                    "dropped: {feature} grants team '{team}', which spec.teams never declared"
                ));
            }
        }
    }

    let mut teams = Vec::new();
    for (index, declared_team) in declared.iter().enumerate() {
        let name = declared_team
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "a spec.teams entry carries no name".to_string())?;
        let selector = declared_team
            .get("namespaceSelector")
            .cloned()
            .unwrap_or(json!({}));

        let mut blocks = serde_json::Map::new();
        for (feature, catalog_field, floor) in FEATURES {
            if let Some(block) = team_block(
                &features,
                feature,
                catalog_field,
                floor,
                name,
                &mut warnings,
            ) {
                blocks.insert(feature.to_string(), block);
            }
        }

        let spec = json!({
            "priority": (index as i32 + 1) * PRIORITY_STEP,
            "namespaceSelector": selector,
            "features": Value::Object(blocks),
        });
        let spec: WeeboSiTeamSpec = serde_json::from_value(spec)
            .map_err(|err| format!("team {name} does not fit the WeeboSiTeam schema: {err}"))?;
        teams.push(WeeboSiTeam::new(name, spec));
    }

    Ok(Exported { teams, warnings })
}

/// Where a feature's floor — the keys every namespace reaches without a grant — is written.
#[derive(Clone, Copy)]
enum Floor {
    /// A single key, under `default`.
    Default,
    /// A list of keys, under `default`.
    DefaultList,
    /// A single key, under `baseline`.
    Baseline,
    /// Nothing is reachable without a grant.
    None,
}

/// Every feature that had a `grants` map, the field its catalogue is under, and where its floor
/// is written. One table rather than six near-identical functions.
const FEATURES: [(&str, &str, Floor); 6] = [
    ("dwocPin", "catalog", Floor::Default),
    ("networkProfiles", "catalog", Floor::Baseline),
    ("imagePolicy", "catalog", Floor::DefaultList),
    ("kubearmorPolicy", "catalog", Floor::Baseline),
    ("registryConfig", "catalog", Floor::None),
    ("endpointAuth", "catalog", Floor::Default),
];

/// One team's block for one feature, or `None` when that feature never granted it anything.
///
/// The entries that move are the ones the grant named and the cluster does not already hand to
/// everybody: a team's reachable set is its own catalogue **plus** the cluster's floor, so
/// re-declaring the floor would be noise that a later edit could make wrong.
fn team_block(
    features: &Value,
    feature: &str,
    catalog_field: &str,
    floor: Floor,
    team: &str,
    warnings: &mut Vec<String>,
) -> Option<Value> {
    let block = features.get(feature)?;
    let grant = block.get("grants")?.get(team)?;

    let allowed: Vec<String> = match grant.get("allowed") {
        Some(Value::Array(keys)) => keys
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let floor_keys: BTreeSet<String> = match floor {
        Floor::Default | Floor::Baseline => {
            let field = if matches!(floor, Floor::Baseline) {
                "baseline"
            } else {
                "default"
            };
            block
                .get(field)
                .and_then(Value::as_str)
                .map(|key| BTreeSet::from([key.to_owned()]))
                .unwrap_or_default()
        }
        Floor::DefaultList => block
            .get("default")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        Floor::None => BTreeSet::new(),
    };

    let catalog = block
        .get(catalog_field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut entries = Vec::new();
    for key in allowed.iter().filter(|key| !floor_keys.contains(*key)) {
        match catalog
            .iter()
            .find(|entry| entry.get("key").and_then(Value::as_str) == Some(key.as_str()))
        {
            Some(entry) => entries.push(entry.clone()),
            None => warnings.push(format!(
                "dropped: {feature} grants team '{team}' the key '{key}', which its catalogue \
                 never declared"
            )),
        }
    }

    let default = grant.get("default").cloned()?;

    // A grant that named nothing beyond the cluster floor is a grant that changed nothing. The
    // team object that carries it would be a block saying "the default, please" — legal, and
    // exactly what a team with no block for this feature already gets. Omitted, so what survives
    // the migration is the entitlement somebody actually granted.
    if entries.is_empty() && is_floor(&default, &floor_keys) {
        return None;
    }

    Some(json!({ "catalog": entries, "default": default }))
}

/// Whether a grant's `default` — one key or a list of them — is exactly the cluster's floor.
fn is_floor(default: &Value, floor_keys: &BTreeSet<String>) -> bool {
    match default {
        Value::String(key) => floor_keys.contains(key),
        Value::Array(keys) => {
            let named: BTreeSet<String> = keys
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect();
            named == *floor_keys
        }
        _ => false,
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

    fn old_spec() -> Value {
        json!({
            "teams": [
                {"name": "platform", "namespaceSelector": {"matchLabels": {"weebo.io/team": "platform"}}},
                {"name": "research", "namespaceSelector": {"matchLabels": {"weebo.io/team": "research"}}},
            ],
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [
                        {"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"},
                        {"key": "gpu", "name": "gpu-config", "namespace": "eclipse-che"},
                    ],
                    "default": "baseline",
                    "grants": {
                        "platform": {"allowed": ["baseline", "gpu"], "default": "gpu"},
                    },
                },
                "imagePolicy": {
                    "mode": "Enforce",
                    "catalog": [
                        {"key": "internal", "patterns": ["registry.internal/shared/**"]},
                        {"key": "team-registry", "patterns": ["registry.internal/teams/{TEAM_NAME}/**"]},
                    ],
                    "default": ["internal"],
                    "grants": {
                        "platform": {"allowed": ["internal", "team-registry"], "default": ["internal", "team-registry"]},
                        "ghost": {"allowed": ["internal"], "default": ["internal"]},
                    },
                },
            },
        })
    }

    #[test]
    fn document_order_becomes_priority() {
        let exported = teams_from(&old_spec()).unwrap();
        assert_eq!(exported.teams.len(), 2);
        assert_eq!(exported.teams[0].name_any(), "platform".to_string());
        assert_eq!(exported.teams[0].spec.priority, 100);
        assert_eq!(exported.teams[1].spec.priority, 200);
    }

    #[test]
    fn a_grant_becomes_the_teams_own_catalogue_minus_the_cluster_floor() {
        let exported = teams_from(&old_spec()).unwrap();
        let dwoc = exported.teams[0].spec.features.dwoc_pin.as_ref().unwrap();
        let keys: Vec<String> = dwoc
            .catalog
            .entries()
            .iter()
            .map(|entry| entry.key.to_string())
            .collect();
        assert_eq!(
            keys,
            vec!["gpu".to_string()],
            "`baseline` is the cluster default and stays reachable without being redeclared"
        );
        assert_eq!(dwoc.default.as_str(), "gpu");

        let images = exported.teams[0]
            .spec
            .features
            .image_policy
            .as_ref()
            .unwrap();
        let keys: Vec<String> = images
            .catalog
            .entries()
            .iter()
            .map(|entry| entry.key.to_string())
            .collect();
        assert_eq!(keys, vec!["team-registry".to_string()]);
    }

    #[test]
    fn a_grant_that_only_named_the_cluster_floor_is_not_carried_over() {
        let mut spec = old_spec();
        spec["features"]["dwocPin"]["grants"]["research"] =
            json!({"allowed": ["baseline"], "default": "baseline"});
        let exported = teams_from(&spec).unwrap();
        let research = &exported.teams[1];
        assert!(
            research.spec.features.dwoc_pin.is_none(),
            "a team reaching only what everybody reaches needs no block"
        );
    }

    #[test]
    fn a_team_with_no_grant_carries_no_block_for_that_feature() {
        let exported = teams_from(&old_spec()).unwrap();
        let research = &exported.teams[1];
        assert!(research.spec.features.dwoc_pin.is_none());
        assert!(research.spec.features.image_policy.is_none());
    }

    #[test]
    fn a_grant_naming_a_team_nobody_declared_is_reported_not_silently_dropped() {
        let exported = teams_from(&old_spec()).unwrap();
        assert!(
            exported
                .warnings
                .iter()
                .any(|warning| warning.contains("'ghost'")),
            "{:?}",
            exported.warnings
        );
    }

    #[test]
    fn a_granted_key_the_catalogue_never_declared_is_reported() {
        let mut spec = old_spec();
        spec["features"]["dwocPin"]["grants"]["platform"]["allowed"] =
            json!(["baseline", "gpu", "typo"]);
        let exported = teams_from(&spec).unwrap();
        assert!(
            exported
                .warnings
                .iter()
                .any(|warning| warning.contains("'typo'")),
            "{:?}",
            exported.warnings
        );
    }

    #[test]
    fn a_configuration_with_no_team_exports_nothing_and_does_not_fail() {
        let exported = teams_from(&json!({"features": {}})).unwrap();
        assert!(exported.teams.is_empty());
        assert!(exported.warnings.is_empty());
    }

    #[test]
    fn check_reports_missing_differing_and_extra_teams() {
        let exported = teams_from(&old_spec()).unwrap();
        let mut applied = exported.teams[0].clone();
        applied.spec.priority = 999;
        let extra = WeeboSiTeam::new("since-the-migration", applied.spec.clone());
        let verdicts = compare(&exported.teams, &[applied, extra]);
        assert_eq!(
            verdicts,
            vec![
                ("platform".to_string(), Verdict::Differs),
                ("research".to_string(), Verdict::Missing),
                ("since-the-migration".to_string(), Verdict::Extra),
            ]
        );
        assert!(
            !Verdict::Extra.is_problem(),
            "an added team is not a failure"
        );
    }

    #[test]
    fn check_is_clean_when_every_team_is_applied_as_declared() {
        let exported = teams_from(&old_spec()).unwrap();
        let verdicts = compare(&exported.teams, &exported.teams);
        assert!(verdicts.iter().all(|(_, verdict)| !verdict.is_problem()));
    }

    #[test]
    fn the_exported_object_round_trips_through_the_real_schema() {
        let exported = teams_from(&old_spec()).unwrap();
        let yaml = serde_yaml_bw::to_string(&exported.teams[0]).unwrap();
        let parsed: WeeboSiTeam = serde_yaml_bw::from_str(&yaml).unwrap();
        assert_eq!(parsed.spec, exported.teams[0].spec);
        assert!(
            yaml.contains("kind: WeeboSiTeam"),
            "the printed object is applyable as-is: {yaml}"
        );
    }
}
