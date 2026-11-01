//! `weebo-si-operator pods audit` — RFC 0013's *CLI*: which existing pods each namespace's level
//! would refuse, asked of the apiserver before anything is switched on.
//!
//! The apiserver answers it, not this binary: a server-side **dry run** of the `enforce` label
//! returns one warning per existing pod the level would refuse. A second implementation of the
//! Pod Security Standards here would be wrong the first time upstream changes a check.
//!
//! Uses **the invoking kubeconfig**, never the operator's service account, like `images audit`.
//! A dry run needs the same RBAC as the write — `patch` on `namespaces` — and writes nothing.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Namespace;
use kube::{Api, Client, ResourceExt};
use weebo_si_crd::{
    NamespaceName, PodSecurityLevel, PodSecurityVersion, ResolvedPodSecurityConfig, SINGLETON_NAME,
    Team, WeeboSiConfig, WeeboSiTeam, team_views,
};
use weebo_si_pod_security::resolve;
use weebo_si_pod_security_adapters::KubeNamespaceLabelStore;
use weebo_si_pod_security_adapters::pod_security_metrics::violating_pods;

use crate::cli::{flag, has_flag};

/// Route the `pods` subcommand.
pub async fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("audit") => audit(&args[1..]).await,
        Some(other) => Err(format!(
            "unrecognized pods subcommand '{other}' (expected audit)"
        )),
        None => Err("pods needs a subcommand: audit".to_string()),
    }
}

/// What `audit` checks one namespace against.
struct Target {
    namespace: String,
    team: Option<String>,
    level: PodSecurityLevel,
}

/// The `podSecurity` block resolved against every `WeeboSiTeam`, and the teams, or `None` when the
/// cluster has no such block — which `--level` makes legal: the question "what would `baseline`
/// refuse here" does not need a configuration.
async fn load(client: &Client) -> Result<Option<(ResolvedPodSecurityConfig, Vec<Team>)>, String> {
    let config = Api::<WeeboSiConfig>::all(client.clone())
        .get_opt(SINGLETON_NAME)
        .await
        .map_err(|err| format!("could not read the WeeboSiConfig named {SINGLETON_NAME}: {err}"))?;
    let Some(pod_security) = config.and_then(|config| config.spec.features.pod_security) else {
        return Ok(None);
    };
    let teams = Api::<WeeboSiTeam>::all(client.clone())
        .list(&Default::default())
        .await
        .map(|list| list.items)
        .map_err(|err| format!("could not list WeeboSiTeam objects: {err}"))?;
    let (resolved, _violations) = pod_security.resolve(&teams);
    Ok(Some((resolved, team_views(&teams))))
}

/// Parse `--level`.
fn level_flag(args: &[String]) -> Result<Option<PodSecurityLevel>, String> {
    flag(args, "--level")
        .map(|raw| {
            PodSecurityLevel::parse(raw).ok_or_else(|| {
                format!("--level {raw} is not a level (privileged, baseline or restricted)")
            })
        })
        .transpose()
}

/// Which level each namespace is checked against: `--level` when given, otherwise the one the
/// configuration resolves to, exactly as the controller would.
fn targets(
    namespaces: &[Namespace],
    config: Option<&(ResolvedPodSecurityConfig, Vec<Team>)>,
    level: Option<PodSecurityLevel>,
) -> Result<Vec<Target>, String> {
    namespaces
        .iter()
        .map(|ns| {
            let labels: BTreeMap<String, String> = ns.labels().clone();
            let resolution = config.map(|(config, teams)| {
                let annotation = (!config.namespace_selection.annotation.is_empty())
                    .then(|| ns.annotations().get(&config.namespace_selection.annotation))
                    .flatten();
                resolve(teams, config, &labels, annotation.map(String::as_str))
            });
            let level = level
                .or(resolution.as_ref().map(|resolution| resolution.level))
                .ok_or_else(|| {
                    "this cluster's WeeboSiConfig has no spec.features.podSecurity block; pass \
                     --level to audit against a level of your choosing"
                        .to_string()
                })?;
            Ok(Target {
                namespace: ns.name_any(),
                team: resolution
                    .and_then(|resolution| resolution.team)
                    .map(|team| team.to_string()),
                level,
            })
        })
        .collect()
}

/// Whether a namespace is one the controller would reconcile: outside `kube-*`, `openshift-*`
/// and the default namespaces, and inside the feature's `namespaceSelector` when one is set.
fn in_scope(ns: &Namespace, config: Option<&ResolvedPodSecurityConfig>) -> bool {
    let name = ns.name_any();
    let system = name.starts_with("kube-")
        || name.starts_with("openshift")
        || matches!(name.as_str(), "default" | "kube-system");
    let selected = config
        .and_then(|config| config.namespace_selector.as_ref())
        .is_none_or(|selector| selector.matches(ns.labels()));
    !system && selected
}

/// `pods audit [--level L] [--version V] [--namespace NS | --all-namespaces]`.
async fn audit(args: &[String]) -> Result<(), String> {
    let level = level_flag(args)?;
    let client = Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let config = load(&client).await?;
    let version = flag(args, "--version")
        .map(PodSecurityVersion::new)
        .or_else(|| config.as_ref().map(|(config, _)| config.version.clone()))
        .unwrap_or_else(|| PodSecurityVersion::new("latest"));
    if !version.is_well_formed() {
        return Err(format!("--version {version} is neither latest nor v1.N"));
    }

    let api: Api<Namespace> = Api::all(client.clone());
    let namespaces: Vec<Namespace> = match (
        flag(args, "--namespace"),
        has_flag(args, "--all-namespaces"),
    ) {
        (Some(_), true) => {
            return Err("pass --namespace or --all-namespaces, not both".to_string());
        }
        (Some(name), false) => vec![
            api.get(name)
                .await
                .map_err(|err| format!("could not read namespace {name}: {err}"))?,
        ],
        (None, true) => api
            .list(&Default::default())
            .await
            .map_err(|err| format!("could not list namespaces: {err}"))?
            .items
            .into_iter()
            .filter(|ns| in_scope(ns, config.as_ref().map(|(config, _)| config)))
            .collect(),
        (None, false) => {
            return Err("pods audit needs --namespace <ns> or --all-namespaces".to_string());
        }
    };

    let store = KubeNamespaceLabelStore::new(client);
    println!(
        "{:<24} {:<14} {:<11} VIOLATIONS",
        "NAMESPACE", "TEAM", "LEVEL"
    );
    let mut total = 0;
    for target in targets(&namespaces, config.as_ref(), level)? {
        let warnings = store
            .dry_run_enforce(
                &NamespaceName::new(&target.namespace),
                target.level,
                &version,
            )
            .await
            .map_err(|err| err.to_string())?;
        let pods = violating_pods(&warnings);
        total += pods;
        let details: Vec<&str> = warnings
            .iter()
            .filter(|warning| !warning.starts_with("existing pods in namespace"))
            .map(String::as_str)
            .collect();
        println!(
            "{:<24} {:<14} {:<11} {pods}{}",
            target.namespace,
            target.team.as_deref().unwrap_or("(none)"),
            target.level.as_str(),
            if details.is_empty() {
                String::new()
            } else {
                format!("  {}", details.join("; "))
            },
        );
    }
    eprintln!(
        "{total} existing pod(s) would be refused on their next creation, at version {version}"
    );
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use kube::api::ObjectMeta;
    use weebo_si_crd::{
        FeatureMode, PodSecurityBackend, PodSecurityConfig, PodSecurityNamespaceSelection,
        Resolved, Selector, TeamName, TeamPodSecurity,
    };

    use super::*;

    fn namespace(name: &str, labels: &[(&str, &str)]) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(
                    labels
                        .iter()
                        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                        .collect(),
                ),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        }
    }

    fn config() -> (ResolvedPodSecurityConfig, Vec<Team>) {
        let config = Resolved::without_teams(PodSecurityConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            default: PodSecurityLevel::Restricted,
            ceiling: PodSecurityLevel::Baseline,
            version: PodSecurityVersion::new("v1.34"),
            backend: PodSecurityBackend::Labels,
            namespace_selection: PodSecurityNamespaceSelection::default(),
        })
        .with_grants(BTreeMap::from([(
            "team-build".to_string(),
            TeamPodSecurity {
                level: Some(PodSecurityLevel::Baseline),
                warn_level: None,
            },
        )]));
        let teams = vec![Team {
            name: TeamName::new("team-build"),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), "team-build".to_string())].into(),
                match_expressions: Vec::new(),
            },
        }];
        (config, teams)
    }

    #[test]
    fn each_namespace_gets_the_level_the_controller_would_resolve() {
        let namespaces = [
            namespace("user-carol", &[("weebo.io/team", "team-build")]),
            namespace("user-dave", &[]),
        ];
        let targets = targets(&namespaces, Some(&config()), None).unwrap();
        assert_eq!(targets[0].level, PodSecurityLevel::Baseline);
        assert_eq!(targets[0].team.as_deref(), Some("team-build"));
        assert_eq!(targets[1].level, PodSecurityLevel::Restricted);
        assert_eq!(targets[1].team, None);
    }

    #[test]
    fn level_overrides_the_configuration_and_works_without_one() {
        let namespaces = [namespace("user-carol", &[("weebo.io/team", "team-build")])];
        let with = targets(
            &namespaces,
            Some(&config()),
            Some(PodSecurityLevel::Restricted),
        )
        .unwrap();
        assert_eq!(with[0].level, PodSecurityLevel::Restricted);
        let without = targets(&namespaces, None, Some(PodSecurityLevel::Baseline)).unwrap();
        assert_eq!(without[0].level, PodSecurityLevel::Baseline);
        assert!(targets(&namespaces, None, None).is_err());
    }

    #[test]
    fn system_namespaces_and_those_outside_the_selector_are_skipped() {
        let (mut config, _) = config();
        assert!(!in_scope(&namespace("kube-system", &[]), None));
        assert!(!in_scope(&namespace("openshift-monitoring", &[]), None));
        assert!(in_scope(&namespace("user-dave", &[]), None));
        config.namespace_selector = Some(Selector {
            match_labels: [("weebo.io/workspace".to_string(), "true".to_string())].into(),
            match_expressions: Vec::new(),
        });
        assert!(!in_scope(&namespace("user-dave", &[]), Some(&config)));
        assert!(in_scope(
            &namespace("user-dave", &[("weebo.io/workspace", "true")]),
            Some(&config)
        ));
    }

    #[test]
    fn an_unknown_level_is_a_usage_error() {
        let args = vec!["--level".to_string(), "Restricted".to_string()];
        assert!(level_flag(&args).is_err());
    }
}
