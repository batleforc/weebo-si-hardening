//! `deploy/weebo-si/` — the reference configuration for weebo-si — checked as the operator reads it.
//!
//! The guide (`docs/guides/weebo-si-standard.md`) walks that directory one stage at a time, so
//! every stage has to be a configuration the controller accepts, not only the last one. Each
//! stage is the singleton with the stage files merge-patched in, in order, exactly as
//! `kubectl patch --type merge` would; each is deserialized, resolved against the teams and
//! validated, feature by feature, with the functions the reconcile loops call.
//!
//! What this cannot catch is a field the CRD schema does not know: serde ignores it, the
//! apiserver prunes it. That half is the envtest tier at the bottom, which applies every stage
//! with strict field validation against the generated CRDs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::Value;
use weebo_si_crd::{WeeboSiConfig, WeeboSiTeam, WeeboSiUser, team_views};

/// The selector every policy template carries, so the live template in the operator's
/// namespace applies to no pod.
const NEVER_MATCHES: &str = "never-matches";
const TEMPLATE_NAMESPACE: &str = "weebo-si-hardening";
const QUOTA_TEMPLATE_NAMESPACE: &str = "weebo-si-hardening-templates";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/weebo-si")
}

fn yaml_files(dir: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(root().join(dir))
        .unwrap_or_else(|e| panic!("deploy/weebo-si/{dir}: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    files.sort();
    files
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn load<T: DeserializeOwned>(path: &Path) -> T {
    serde_yaml_bw::from_str(&read(path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn load_all<T: DeserializeOwned>(dir: &str) -> Vec<T> {
    yaml_files(dir)
        .iter()
        .flat_map(|path| {
            serde_yaml_bw::from_str_multi::<T>(&read(path))
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        })
        .collect()
}

/// RFC 7386 JSON merge patch — what `kubectl patch --type merge` does with a stage file.
fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(serde_json::Map::new());
    }
    let Value::Object(target) = target else {
        unreachable!("made an object above")
    };
    for (key, value) in patch {
        if value.is_null() {
            target.remove(key);
        } else {
            merge_patch(target.entry(key.clone()).or_insert(Value::Null), value);
        }
    }
}

/// Stage 0 (the singleton as written) and every stage after it, cumulatively.
fn stages() -> Vec<(String, Value)> {
    let mut current: Value = load(&root().join("config/weebosiconfig.yaml"));
    let mut out = vec![("00-config".to_owned(), current.clone())];
    for path in yaml_files("stages") {
        let patch: Value = load(&path);
        merge_patch(&mut current, &patch);
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        out.push((name, current.clone()));
    }
    out
}

fn teams() -> Vec<WeeboSiTeam> {
    load_all("teams")
}

fn users() -> Vec<WeeboSiUser> {
    load_all("users")
}

/// Every conflict and violation the controller would report for this configuration.
fn violations(config: &WeeboSiConfig, teams: &[WeeboSiTeam], users: &[WeeboSiUser]) -> Vec<String> {
    let (resolved, conflicts) = config.spec.resolve_teams(teams);
    let views = team_views(teams);
    let mut out: Vec<String> = conflicts.into_iter().map(|c| c.message).collect();
    let text = |v: &dyn std::fmt::Display| v.to_string();
    if let Some(f) = &resolved.dwoc_pin {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.network_profiles {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.image_policy {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.kubearmor_policy {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.registry_config {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.endpoint_auth {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.pod_security {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.resource_quotas {
        out.extend(f.validate(&views).iter().map(|v| text(v)));
    }
    if let Some(f) = &resolved.identity {
        out.extend(f.validate(teams, users).iter().map(|v| text(v)));
    }
    out
}

#[test]
fn every_stage_resolves_with_no_violation() {
    let teams = teams();
    let users = users();
    assert!(!teams.is_empty(), "deploy/weebo-si/teams is empty");
    for (stage, value) in stages() {
        let config: WeeboSiConfig = serde_json::from_value(value)
            .unwrap_or_else(|e| panic!("stage {stage} does not deserialize: {e}"));
        let found = violations(&config, &teams, &users);
        assert!(found.is_empty(), "stage {stage}:\n  {}", found.join("\n  "));
    }
}

#[test]
fn every_team_reaches_the_access_keys_the_guide_offers() {
    // A team reaches what it catalogues plus the cluster default: a key the guide tells a
    // developer to write and the team does not reach is refused at admission, so the workspace
    // does not start.
    let teams = teams();
    let (_, last) = stages().pop().unwrap();
    let config: WeeboSiConfig = serde_json::from_value(last).unwrap();
    let (resolved, _) = config.spec.resolve_teams(&teams);
    let endpoint_auth = resolved
        .endpoint_auth
        .expect("the last stage configures endpointAuth");
    for team in &teams {
        let name = team.team_name();
        let grant = endpoint_auth.grant_for(Some(&name));
        for key in ["private", "team", "shared"] {
            assert!(
                grant.allowed.iter().any(|allowed| allowed.as_str() == key),
                "team {name} does not reach `{key}`: {:?}",
                grant.allowed
            );
        }
    }
}

#[test]
fn every_feature_is_present_from_stage_zero_and_enforced_by_the_last() {
    let all = stages();
    let features = |value: &Value| -> Vec<(String, String)> {
        value["spec"]["features"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, block)| (name.clone(), block["mode"].as_str().unwrap().to_owned()))
            .collect()
    };
    let (_, first) = all.first().unwrap();
    for (name, mode) in features(first) {
        assert_eq!(
            mode, "Off",
            "stage 0 must change nothing, but {name} is {mode}"
        );
    }
    let (last_name, last) = all.last().unwrap();
    for (name, mode) in features(last) {
        assert_eq!(mode, "Enforce", "after {last_name}, {name} is still {mode}");
    }
    assert_eq!(
        last["spec"]["features"]["endpointAuth"]["gateway"]["enforcement"], "Enforce",
        "the guide ends with the gate refusing"
    );
}

/// Every object a `templateRef`, `quotaRef` or `limitRangeRef` names, as `(kind-hint, name, namespace)`.
fn references(value: &Value, out: &mut Vec<(String, String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if matches!(key.as_str(), "templateRef" | "quotaRef" | "limitRangeRef") {
                    out.push((
                        key.clone(),
                        inner["name"].as_str().unwrap().to_owned(),
                        inner["namespace"].as_str().unwrap().to_owned(),
                    ));
                } else {
                    references(inner, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| references(item, out)),
        _ => {}
    }
}

fn templates() -> Vec<Value> {
    [
        "templates/network",
        "templates/kubearmor",
        "templates/registry",
        "templates/quotas",
    ]
    .iter()
    .flat_map(|dir| load_all::<Value>(dir))
    .collect()
}

#[test]
fn every_reference_names_a_template_in_this_directory() {
    let templates = templates();
    let mut refs = Vec::new();
    references(&load(&root().join("config/weebosiconfig.yaml")), &mut refs);
    for path in yaml_files("teams") {
        references(&load(&path), &mut refs);
    }
    assert!(!refs.is_empty());
    for (field, name, namespace) in refs {
        let found = templates.iter().any(|t| {
            t["metadata"]["name"] == name.as_str()
                && t["metadata"]["namespace"] == namespace.as_str()
        });
        assert!(
            found,
            "{field} {namespace}/{name} has no template under deploy/weebo-si/templates"
        );
    }
}

#[test]
fn every_policy_template_selects_no_pod_where_it_lives() {
    for template in templates() {
        let kind = template["kind"].as_str().unwrap();
        let name = template["metadata"]["name"].as_str().unwrap();
        let selector = match kind {
            "CiliumNetworkPolicy" => &template["spec"]["endpointSelector"],
            "NetworkPolicy" => &template["spec"]["podSelector"],
            "KubeArmorPolicy" => &template["spec"]["selector"],
            _ => continue,
        };
        assert_eq!(
            selector["matchLabels"]["hardening.weebo.io/template"], NEVER_MATCHES,
            "{kind} {name}: a template is a live policy in {TEMPLATE_NAMESPACE}; its selector must match no pod"
        );
        assert_eq!(
            template["metadata"]["namespace"], TEMPLATE_NAMESPACE,
            "{kind} {name}"
        );
    }
}

#[test]
fn quota_templates_live_where_no_pod_runs() {
    for template in templates() {
        let kind = template["kind"].as_str().unwrap();
        if matches!(kind, "ResourceQuota" | "LimitRange") {
            assert_eq!(
                template["metadata"]["namespace"], QUOTA_TEMPLATE_NAMESPACE,
                "{kind} {}: a quota is enforced where it lives",
                template["metadata"]["name"]
            );
        }
    }
}

#[test]
fn registry_templates_never_shadow_the_home_directory() {
    for template in templates() {
        if template["kind"] != "ConfigMap" && template["kind"] != "Secret" {
            continue;
        }
        let name = template["metadata"]["name"].as_str().unwrap();
        let annotations = &template["metadata"]["annotations"];
        let mount_as = annotations["controller.devfile.io/mount-as"].as_str();
        assert!(
            matches!(mount_as, Some("subpath" | "env")),
            "{name}: mount-as {mount_as:?} — `file` (DevWorkspace Operator's default) mounts a directory over the path"
        );
        assert_eq!(
            template["metadata"]["labels"]["controller.devfile.io/mount-to-devworkspace"], "true",
            "{name}: without the automount label DevWorkspace Operator mounts nothing"
        );
    }
}

/// The apiserver half: every stage, every team and every user, server-side applied in dry-run
/// with strict field validation against the CRDs this crate generates. A field the schema does
/// not know is a refused request here, where it would be a silently pruned one on a cluster.
#[cfg(feature = "envtest")]
mod envtest {
    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::{Api, Patch, PatchParams};
    use kube::{CustomResourceExt, ResourceExt};
    use weebo_si_envtest_support::EnvTest;

    async fn install(client: kube::Client, crd: CustomResourceDefinition) {
        let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
        let name = crd.name_any();
        crds.patch(
            &name,
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&crd),
        )
        .await
        .unwrap();
        for _ in 0..60 {
            let established = crds
                .get(&name)
                .await
                .ok()
                .and_then(|c| c.status)
                .and_then(|s| s.conditions)
                .is_some_and(|cs| {
                    cs.iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
                });
            if established {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!("{name} never became established");
    }

    async fn dry_apply(api: &Api<kube::api::DynamicObject>, name: &str, value: &Value, what: &str) {
        let params = PatchParams::apply("deploy-weebo-si")
            .dry_run()
            .validation_strict();
        if let Err(e) = api.patch(name, &params, &Patch::Apply(value)).await {
            panic!("{what}: refused by the apiserver: {e}");
        }
    }

    fn api(client: &kube::Client, crd: &CustomResourceDefinition) -> Api<kube::api::DynamicObject> {
        let version = &crd.spec.versions[0].name;
        let gvk = kube::api::GroupVersionKind::gvk(&crd.spec.group, version, &crd.spec.names.kind);
        let resource = kube::api::ApiResource::from_gvk_with_plural(&gvk, &crd.spec.names.plural);
        Api::all_with(client.clone(), &resource)
    }

    #[tokio::test]
    async fn the_apiserver_accepts_every_stage_with_strict_field_validation() {
        let Some(env) = EnvTest::try_start().await else {
            return;
        };
        let client = env.client().unwrap();
        let (config_crd, team_crd, user_crd) =
            (WeeboSiConfig::crd(), WeeboSiTeam::crd(), WeeboSiUser::crd());
        for crd in [&config_crd, &team_crd, &user_crd] {
            install(client.clone(), crd.clone()).await;
        }

        for (stage, value) in stages() {
            dry_apply(
                &api(&client, &config_crd),
                "cluster",
                &value,
                &format!("stage {stage}"),
            )
            .await;
        }
        for (dir, crd) in [("teams", &team_crd), ("users", &user_crd)] {
            for path in yaml_files(dir) {
                for value in serde_yaml_bw::from_str_multi::<Value>(&read(&path)).unwrap() {
                    let name = value["metadata"]["name"].as_str().unwrap().to_owned();
                    dry_apply(
                        &api(&client, crd),
                        &name,
                        &value,
                        &path.display().to_string(),
                    )
                    .await;
                }
            }
        }
    }
}
