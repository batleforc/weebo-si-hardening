//! `weebo-si-operator quotas audit` — RFC 0014's *CLI*: who is already above the profile they
//! would get, before anything is switched on.
//!
//! It sums the requests and limits of the running pods and counts the objects a quota names, with
//! **the invoking kubeconfig**, like `images audit`. It runs the admission-time rule itself — one
//! comparison per resource — and only advises: the apiserver is the enforcer.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    ConfigMap, Namespace, PersistentVolumeClaim, Pod, ResourceQuota, Secret, Service,
};
use kube::{Api, Client, ResourceExt};
use weebo_si_crd::{
    QuotaProfileKey, ResolvedResourceQuotasConfig, SINGLETON_NAME, Team, WeeboSiConfig,
    WeeboSiTeam, team_views,
};
use weebo_si_resource_quotas::{Over, PodResources, Quantity, over, resolve};

use crate::cli::{flag, has_flag};

/// Route the `quotas` subcommand.
pub async fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("audit") => audit(&args[1..]).await,
        Some(other) => Err(format!(
            "unrecognized quotas subcommand '{other}' (expected audit)"
        )),
        None => Err("quotas needs a subcommand: audit".to_string()),
    }
}

async fn load(client: &Client) -> Result<(ResolvedResourceQuotasConfig, Vec<Team>), String> {
    let config = Api::<WeeboSiConfig>::all(client.clone())
        .get(SINGLETON_NAME)
        .await
        .map_err(|err| format!("could not read the WeeboSiConfig named {SINGLETON_NAME}: {err}"))?;
    let quotas = config.spec.features.resource_quotas.ok_or_else(|| {
        "this cluster's WeeboSiConfig has no spec.features.resourceQuotas block".to_string()
    })?;
    let teams = Api::<WeeboSiTeam>::all(client.clone())
        .list(&Default::default())
        .await
        .map(|list| list.items)
        .map_err(|err| format!("could not list WeeboSiTeam objects: {err}"))?;
    let (resolved, _conflicts) = quotas.resolve(&teams);
    Ok((resolved, team_views(&teams)))
}

fn resources(
    requirements: Option<&k8s_openapi::api::core::v1::ResourceRequirements>,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let render = |map: Option<
        &BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>,
    >| {
        map.map(|map| {
            map.iter()
                .map(|(key, value)| (key.clone(), value.0.clone()))
                .collect()
        })
        .unwrap_or_default()
    };
    (
        render(requirements.and_then(|r| r.requests.as_ref())),
        render(requirements.and_then(|r| r.limits.as_ref())),
    )
}

fn count(value: usize) -> Quantity {
    Quantity::from_nanos(i128::try_from(value).unwrap_or(i128::MAX) * 1_000_000_000)
}

/// Today's usage in one namespace: every non-terminated pod, and the object counts and storage a
/// quota can name.
async fn usage(
    client: &Client,
    namespace: &str,
) -> Result<(Vec<PodResources>, BTreeMap<String, Quantity>), String> {
    let list_error = |what: &str| {
        let what = what.to_string();
        move |err: kube::Error| format!("could not list {what} in {namespace}: {err}")
    };
    let pods: Vec<Pod> = Api::<Pod>::namespaced(client.clone(), namespace)
        .list(&Default::default())
        .await
        .map_err(list_error("pods"))?
        .items
        .into_iter()
        .filter(|pod| {
            !matches!(
                pod.status
                    .as_ref()
                    .and_then(|status| status.phase.as_deref()),
                Some("Succeeded" | "Failed")
            )
        })
        .collect();
    let pod_resources: Vec<PodResources> = pods
        .iter()
        .map(|pod| {
            let spec = pod.spec.as_ref();
            PodResources {
                containers: spec
                    .map(|spec| {
                        spec.containers
                            .iter()
                            .map(|c| resources(c.resources.as_ref()))
                            .collect()
                    })
                    .unwrap_or_default(),
                init_containers: spec
                    .and_then(|spec| spec.init_containers.as_ref())
                    .map(|init| {
                        init.iter()
                            .map(|c| resources(c.resources.as_ref()))
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    let services = Api::<Service>::namespaced(client.clone(), namespace)
        .list(&Default::default())
        .await
        .map_err(list_error("services"))?
        .items;
    let typed = |kind: &str| {
        services
            .iter()
            .filter(|service| {
                service.spec.as_ref().and_then(|spec| spec.type_.as_deref()) == Some(kind)
            })
            .count()
    };
    let node_ports: usize = services
        .iter()
        .filter_map(|service| service.spec.as_ref()?.ports.as_ref())
        .flatten()
        .filter(|port| port.node_port.is_some())
        .count();
    let claims = Api::<PersistentVolumeClaim>::namespaced(client.clone(), namespace)
        .list(&Default::default())
        .await
        .map_err(list_error("persistentvolumeclaims"))?
        .items;
    let storage: i128 = claims
        .iter()
        .filter_map(|claim| {
            let request = claim
                .spec
                .as_ref()?
                .resources
                .as_ref()?
                .requests
                .as_ref()?
                .get("storage")?;
            Quantity::parse(&request.0).ok()
        })
        .map(Quantity::nanos)
        .sum();
    let config_maps = Api::<ConfigMap>::namespaced(client.clone(), namespace)
        .list_metadata(&Default::default())
        .await
        .map_err(list_error("configmaps"))?
        .items
        .len();
    let secrets = Api::<Secret>::namespaced(client.clone(), namespace)
        .list_metadata(&Default::default())
        .await
        .map_err(list_error("secrets"))?
        .items
        .len();

    let counted = BTreeMap::from([
        ("pods".to_string(), count(pods.len())),
        ("count/pods".to_string(), count(pods.len())),
        ("services".to_string(), count(services.len())),
        ("count/services".to_string(), count(services.len())),
        (
            "services.loadbalancers".to_string(),
            count(typed("LoadBalancer")),
        ),
        ("services.nodeports".to_string(), count(node_ports)),
        ("persistentvolumeclaims".to_string(), count(claims.len())),
        (
            "count/persistentvolumeclaims".to_string(),
            count(claims.len()),
        ),
        (
            "requests.storage".to_string(),
            Quantity::from_nanos(storage),
        ),
        ("configmaps".to_string(), count(config_maps)),
        ("count/configmaps".to_string(), count(config_maps)),
        ("secrets".to_string(), count(secrets)),
        ("count/secrets".to_string(), count(secrets)),
    ]);
    Ok((pod_resources, counted))
}

fn render(over: &[Over]) -> String {
    if over.is_empty() {
        return "-".to_string();
    }
    over.iter()
        .map(|over| {
            format!(
                "{} {}/{}",
                over.resource,
                over.used.display_for(&over.resource),
                over.hard.display_for(&over.resource)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `quotas audit [--profile KEY] [--namespace NS | --all-namespaces]`.
async fn audit(args: &[String]) -> Result<(), String> {
    let client = Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let (config, teams) = load(&client).await?;
    let forced = flag(args, "--profile").map(QuotaProfileKey::new);
    if let Some(key) = &forced
        && !config.catalog.contains(key)
    {
        return Err(format!("--profile {key} is not in the catalog"));
    }

    let api: Api<Namespace> = Api::all(client.clone());
    let namespaces: Vec<Namespace> = match (
        flag(args, "--namespace"),
        has_flag(args, "--all-namespaces"),
    ) {
        (Some(_), true) => return Err("pass --namespace or --all-namespaces, not both".to_string()),
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
            .filter(|ns| {
                let name = ns.name_any();
                !name.starts_with("kube-")
                    && !name.starts_with("openshift")
                    && name != "default"
                    && config
                        .namespace_selector
                        .as_ref()
                        .is_none_or(|selector| selector.matches(ns.labels()))
            })
            .collect(),
        (None, false) => {
            return Err("quotas audit needs --namespace <ns> or --all-namespaces".to_string());
        }
    };

    println!("{:<24} {:<14} {:<12} OVER", "NAMESPACE", "TEAM", "PROFILE");
    let mut above = 0;
    for ns in &namespaces {
        let name = ns.name_any();
        let annotation = (!config.namespace_selection.annotation.is_empty())
            .then(|| ns.annotations().get(&config.namespace_selection.annotation))
            .flatten();
        let (team, profile) = match (
            &forced,
            resolve(&teams, &config, ns.labels(), annotation.map(String::as_str)),
        ) {
            (Some(key), resolved) => (resolved.ok().and_then(|p| p.team), key.clone()),
            (None, Ok(provenance)) => (provenance.team, provenance.profile),
            (None, Err(refused)) => {
                println!(
                    "{name:<24} {:<14} {:<12} (asks for {}, not granted: unchanged under Deny)",
                    refused.team.as_ref().map_or("(none)", |team| team.as_str()),
                    "-",
                    refused.requested
                );
                continue;
            }
        };
        let hard = match config
            .catalog
            .profile(&profile)
            .and_then(|p| p.quota_ref.clone())
        {
            Some(template) => {
                Api::<ResourceQuota>::namespaced(client.clone(), template.namespace.as_str())
                    .get(&template.name)
                    .await
                    .map_err(|err| {
                        format!(
                            "could not read quota template {}/{}: {err}",
                            template.namespace, template.name
                        )
                    })?
                    .spec
                    .and_then(|spec| spec.hard)
                    .map(|hard| {
                        hard.into_iter()
                            .map(|(key, value)| (key, value.0))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            None => BTreeMap::new(),
        };
        let (pods, counted) = usage(&client, &name).await?;
        let over = over(&hard, &pods, &counted);
        if !over.is_empty() {
            above += 1;
        }
        println!(
            "{name:<24} {:<14} {:<12} {}",
            team.as_ref().map_or("(none)", |team| team.as_str()),
            profile.as_str(),
            render(&over)
        );
    }
    eprintln!(
        "{above} namespace(s) above their profile: their next pod would be refused once Enforce"
    );
    Ok(())
}
