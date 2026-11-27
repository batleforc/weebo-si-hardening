//! The workspace suite: every feature that acts on a DevWorkspace or its namespace, against a
//! workspace Che's DevWorkspace Operator actually starts.
//!
//! Each test states the whole `spec.features` it needs (`set_features`), so the order they run
//! in never matters. Run with `--test-threads=1`: they share the cluster's one singleton.
//!
//! Templates live in the operator's own namespace and are real, live objects there — so every
//! `NetworkPolicy` template here selects a label no pod carries. A template with
//! `podSelector: {}` would apply its own egress rules to the operator's webhook.

#![cfg(feature = "e2e")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::time::Duration;

use weebo_si_e2e::{
    Cleanup, Namespace, OPERATOR_NAMESPACE, RECONCILE, WORKSPACE_START, Workspace, WorkspaceSpec,
    apply, delete, feature_status, get, json, kubectl, metric_sum, must, set_features, stays, team,
    text, try_apply, try_apply_with_warnings, wait_until,
};

fn in_scope() -> serde_json::Value {
    json!({ "matchExpressions": [{ "key": "hardening.weebo.io/workspace-namespace", "operator": "Exists" }] })
}

/// The image-policy block every test that starts a workspace needs once image-policy is on: the
/// suite's own workspace image, granted to everybody.
fn workspace_image_only() -> serde_json::Value {
    json!({
        "mode": "Enforce",
        "catalog": [{ "key": "e2e-workspace", "patterns": ["localhost/e2e-workspace:*"] }],
        "default": ["e2e-workspace"],
    })
}

// --- dwoc-pin ---------------------------------------------------------------------------------------

/// A DevWorkspaceOperatorConfig whose one observable effect is an annotation on every pod it
/// configures — the proof, read off the pod, that DevWorkspace Operator ran the workspace with the
/// configuration `dwoc-pin` pinned rather than the one the dashboard asked for.
fn dwoc(name: &str) -> Cleanup {
    apply(
        &json!({
            "apiVersion": "controller.devfile.io/v1alpha1",
            "kind": "DevWorkspaceOperatorConfig",
            "metadata": { "name": name, "namespace": "eclipse-che" },
            "config": { "workspace": { "podAnnotations": { "e2e.weebo.io/dwoc": name } } },
        })
        .to_string(),
    );
    Cleanup::new(&["devworkspaceoperatorconfig", "-n", "eclipse-che", name])
}

fn dwoc_pin(default: &str, on_unknown_key: &str) -> serde_json::Value {
    json!({
        "mode": "Enforce",
        "namespaceSelector": in_scope(),
        "catalog": [
            { "key": "hardened", "name": "e2e-hardened", "namespace": "eclipse-che" },
        ],
        "default": default,
        "namespaceSelection": { "annotation": "hardening.weebo.io/dwoc", "onUnknownKey": on_unknown_key },
        "onMissingTarget": "Deny",
    })
}

fn pinned_to(workspace: &Workspace) -> String {
    text(
        &workspace.object(),
        "/spec/template/attributes/controller.devfile.io~1devworkspace-config/name",
    )
}

fn pod_annotation(workspace: &Workspace, key: &str) -> String {
    let pod = workspace.pod();
    let object = get(&["pod", "-n", &workspace.namespace, &pod]).unwrap();
    text(
        &object,
        &format!("/metadata/annotations/{}", key.replace('/', "~1")),
    )
}

#[test]
fn dwoc_pin_replaces_the_dashboards_config_and_devworkspace_operator_runs_with_it() {
    let _config = dwoc("e2e-hardened");
    set_features(json!({ "dwocPin": dwoc_pin("hardened", "Default") }));
    let ns = Namespace::workspace("alice", "dwoc-default", None);

    let workspace = Workspace::create(&ns.name, "pinned", &WorkspaceSpec::default());
    assert_eq!(pinned_to(&workspace), "e2e-hardened");
    let audit = text(
        &workspace.object(),
        "/metadata/annotations/hardening.weebo.io~1dwoc-pin",
    );
    assert!(
        audit.starts_with("replaced:eclipse-che/devworkspace-config;")
            && audit.ends_with("key=hardened"),
        "audit annotation {audit:?}"
    );

    workspace.wait_running();
    assert_eq!(
        pod_annotation(&workspace, "e2e.weebo.io/dwoc"),
        "e2e-hardened",
        "DevWorkspace Operator did not run the workspace with the pinned configuration"
    );
    assert!(
        metric_sum(
            "webhook",
            "weebo_si_dwoc_pin_total",
            &[("result", "replaced")]
        ) >= 1.0
    );
    assert_eq!(text(&feature_status("dwoc-pin"), "/state"), "Active");
}

#[test]
fn a_teams_own_dwoc_is_reached_through_the_namespace_annotation_and_the_lower_priority_team_wins() {
    let _hardened = dwoc("e2e-hardened");
    let _gpu = dwoc("e2e-gpu");
    let _other = dwoc("e2e-other");
    set_features(json!({ "dwocPin": dwoc_pin("hardened", "Deny") }));
    // Both teams select the namespace; `gpu` at priority 10 must win over `other` at 20.
    let _gpu_team = team(
        "e2e-gpu",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "gpu" } },
            "features": { "dwocPin": {
                "catalog": [{ "key": "gpu", "name": "e2e-gpu", "namespace": "eclipse-che" }],
                "default": "hardened",
            } },
        }),
    );
    let _other_team = team(
        "e2e-other",
        json!({
            "priority": 20,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "gpu" } },
            "features": { "dwocPin": {
                "catalog": [{ "key": "other", "name": "e2e-other", "namespace": "eclipse-che" }],
                "default": "other",
            } },
        }),
    );
    // Resolution reads teams from a watch; give the webhook the new objects before asking it.
    set_features(json!({ "dwocPin": dwoc_pin("hardened", "Deny") }));

    let ns = Namespace::workspace("alice", "dwoc-team", Some("gpu"));
    let plain = Workspace::create(&ns.name, "team-default", &WorkspaceSpec::default());
    assert_eq!(
        pinned_to(&plain),
        "e2e-hardened",
        "team gpu's default is `hardened`, not `other`"
    );

    ns.annotate("hardening.weebo.io/dwoc", "gpu");
    let annotated = Workspace::create(&ns.name, "annotated", &WorkspaceSpec::default());
    assert_eq!(pinned_to(&annotated), "e2e-gpu");
    annotated.wait_running();
    assert_eq!(pod_annotation(&annotated, "e2e.weebo.io/dwoc"), "e2e-gpu");

    // `other` is the losing team's key: outside this namespace's reach, and Deny refuses it.
    ns.annotate("hardening.weebo.io/dwoc", "other");
    let refused = Workspace::try_create(&ns.name, "refused", &WorkspaceSpec::default());
    let err = refused.expect_err("a key outside the grant must be refused under Deny");
    assert!(
        err.contains("names a catalogue key outside this namespace's grant: \"other\""),
        "{err}"
    );
}

#[test]
fn a_catalogue_entry_pointing_at_nothing_is_refused_under_on_missing_target_deny() {
    // No `e2e-hardened` object this time.
    delete(&[
        "devworkspaceoperatorconfig",
        "-n",
        "eclipse-che",
        "e2e-hardened",
    ]);
    set_features(json!({ "dwocPin": dwoc_pin("hardened", "Default") }));
    let ns = Namespace::workspace("alice", "dwoc-missing", None);
    let err =
        wait_until(
            "the missing target to be refused",
            RECONCILE,
            || match Workspace::try_create(&ns.name, "orphan", &WorkspaceSpec::default()) {
                Ok(created) => {
                    drop(created);
                    Err("admitted".to_string())
                }
                Err(err) => Ok(err),
            },
        );
    assert!(err.contains("which does not exist"), "{err}");
}

// --- image-policy -----------------------------------------------------------------------------------

#[test]
fn an_ungranted_image_is_refused_at_the_workspace_and_at_the_pod() {
    set_features(json!({ "imagePolicy": workspace_image_only() }));
    let ns = Namespace::workspace("bob", "images", None);

    let err = Workspace::try_create(
        &ns.name,
        "busybox",
        &WorkspaceSpec {
            image: "docker.io/library/busybox:1.37",
            ..WorkspaceSpec::default()
        },
    )
    .expect_err("an ungranted workspace image must be refused");
    assert!(
        err.contains(r#"image "docker.io/library/busybox:1.37" is not permitted"#),
        "{err}"
    );

    // The floor: a pod nobody declared through a devfile, in a workspace namespace.
    let err = kubectl(&[
        "run",
        "sneaky",
        "-n",
        &ns.name,
        "--image=docker.io/library/busybox:1.37",
        "--restart=Never",
        "--",
        "sleep",
        "60",
    ])
    .expect_err("an ungranted pod image must be refused");
    assert!(err.contains("is not permitted"), "{err}");
    assert!(
        metric_sum(
            "webhook",
            "weebo_si_image_policy_total",
            &[("result", "denied"), ("resource", "pod")]
        ) >= 1.0
    );
}

#[test]
fn a_granted_workspace_starts_with_every_pod_devworkspace_operator_builds_admitted() {
    set_features(json!({ "imagePolicy": workspace_image_only() }));
    let ns = Namespace::workspace("bob", "images-ok", None);
    let workspace = Workspace::create(&ns.name, "granted", &WorkspaceSpec::default());
    // Running means the pod DevWorkspace Operator built — its own init containers included —
    // passed the pod-level floor, not only the devfile-level check.
    workspace.wait_running();
    assert!(
        metric_sum(
            "webhook",
            "weebo_si_image_policy_total",
            &[("result", "allowed"), ("resource", "pod")]
        ) >= 1.0
    );
}

#[test]
fn dry_run_counts_an_ungranted_image_and_admits_it() {
    let mut block = workspace_image_only();
    block["mode"] = json!("DryRun");
    set_features(json!({ "imagePolicy": block }));
    let ns = Namespace::workspace("bob", "images-dry", None);
    let before = metric_sum(
        "webhook",
        "weebo_si_image_policy_total",
        &[("result", "denied"), ("resource", "devworkspace")],
    );
    let workspace = Workspace::create(
        &ns.name,
        "would-deny",
        &WorkspaceSpec {
            image: "docker.io/library/busybox:1.37",
            ..WorkspaceSpec::default()
        },
    );
    assert_eq!(text(&workspace.object(), "/metadata/name"), "would-deny");
    wait_until("the dry-run denial to be counted", RECONCILE, || {
        let after = metric_sum(
            "webhook",
            "weebo_si_image_policy_total",
            &[("result", "denied"), ("resource", "devworkspace")],
        );
        if after > before {
            Ok(())
        } else {
            Err(format!("still {after}"))
        }
    });
}

// --- image-rewrite (RFC 0017, §6.P) ------------------------------------------------------------------

/// The suite's image under a name only the rewrite can resolve: `example.invalid` has no DNS, so a
/// pull that was not rewritten fails, and one that was finds `localhost/e2e/e2e-workspace:e2e`,
/// loaded on the node by `scripts/e2e.sh`.
const UPSTREAM_IMAGE: &str = "example.invalid/e2e-workspace:e2e";
const MIRRORED_IMAGE: &str = "localhost/e2e/e2e-workspace:e2e";

/// `image-policy` granting only what is on the node (`localhost/**`), plus `extra` patterns.
fn local_images_only(extra: &[&str]) -> serde_json::Value {
    let mut patterns = vec!["localhost/**"];
    patterns.extend_from_slice(extra);
    json!({
        "mode": "Enforce",
        "catalog": [{ "key": "local", "patterns": patterns }],
        "default": ["local"],
    })
}

fn image_rewrite(mode: &str, rules: serde_json::Value) -> serde_json::Value {
    json!({ "mode": mode, "namespaceSelector": in_scope(), "rules": rules })
}

fn mirror_rule() -> serde_json::Value {
    json!([{ "from": "example.invalid", "to": "localhost/e2e" }])
}

fn rewritten_workspaces() -> f64 {
    metric_sum(
        "webhook",
        "weebo_si_image_rewrites_total",
        &[("result", "rewritten"), ("resource", "devworkspace")],
    )
}

fn component_image(workspace: &Workspace) -> String {
    text(
        &workspace.object(),
        "/spec/template/components/0/container/image",
    )
}

/// Observation 1: the DevWorkspace half. The stored object names the mirror and the workspace
/// runs, which it could not from `example.invalid`.
#[test]
fn an_upstream_workspace_image_is_rewritten_onto_the_mirror_and_runs() {
    set_features(json!({
        "imagePolicy": local_images_only(&[]),
        "imageRewrite": image_rewrite("Enforce", mirror_rule()),
    }));
    let ns = Namespace::workspace("carol", "rewrite", None);
    let workspace = Workspace::create(
        &ns.name,
        "mirrored",
        &WorkspaceSpec {
            image: UPSTREAM_IMAGE,
            ..WorkspaceSpec::default()
        },
    );
    assert_eq!(component_image(&workspace), MIRRORED_IMAGE);
    assert!(
        text(
            &workspace.object(),
            "/metadata/annotations/hardening.weebo.io~1image-rewrite"
        )
        .contains(UPSTREAM_IMAGE)
    );
    workspace.wait_running();
}

/// Observation 2: the Pod half, on an image nobody wrote. A workspace with a project gets
/// DevWorkspace Operator's `project-clone` init container from `quay.io`; the pod carries it
/// under the mirror. Asserted on the pod spec, or on the name the kubelet then pulled, which is
/// what the rewrite changes: whether the node can pull it is the mirror's business, not this row's.
#[test]
fn an_init_container_devworkspace_operator_injects_is_rewritten_at_the_pod() {
    set_features(json!({
        "imagePolicy": local_images_only(&[]),
        "imageRewrite": image_rewrite(
            "Enforce",
            json!([
                { "from": "example.invalid", "to": "localhost/e2e" },
                { "from": "quay.io", "to": "localhost/quay" },
            ]),
        ),
    }));
    let ns = Namespace::workspace("carol", "rewrite-clone", None);
    let mut manifest = Workspace::manifest(
        &ns.name,
        "with-project",
        &WorkspaceSpec {
            image: UPSTREAM_IMAGE,
            ..WorkspaceSpec::default()
        },
    );
    manifest["spec"]["template"]["projects"] = json!([{
        "name": "sample",
        "git": { "remotes": { "origin": "https://example.invalid/sample.git" } },
    }]);
    // project-clone mounts the `projects` volume, which DevWorkspace Operator only adds when a
    // container mounts sources: without it the Deployment is invalid and no pod is ever made.
    manifest["spec"]["template"]["components"][0]["container"]["mountSources"] = json!(true);
    apply(&manifest.to_string());
    let _cleanup = Cleanup::new(&["devworkspace", "-n", &ns.name, "with-project"]);

    // The mirror does not hold project-clone on kind, so the pull fails at once and DevWorkspace
    // Operator fails the workspace and removes its pod within seconds: read the pod while it
    // exists, else the kubelet's pull event, which outlives it.
    let clone = wait_until("project-clone to reach a pod", WORKSPACE_START, || {
        let pods = get(&[
            "pods",
            "-n",
            &ns.name,
            "-l",
            "controller.devfile.io/devworkspace_name=with-project",
        ])
        .ok_or("no pod list")?;
        if let Some(init) = pods
            .pointer("/items/0/spec/initContainers")
            .and_then(serde_json::Value::as_array)
        {
            return init
                .iter()
                .find(|c| text(c, "/name") == "project-clone")
                .map(|c| text(c, "/image"))
                .ok_or_else(|| format!("no project-clone init container: {init:?}"));
        }
        let events = get(&["events", "-n", &ns.name]).ok_or("no event list")?;
        let pulled = events
            .pointer("/items")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                text(e, "/message")
                    .strip_prefix("Pulling image ")
                    .map(str::to_owned)
            })
            .find(|image| image.contains("project-clone"));
        if let Some(image) = pulled {
            return Ok(image.trim_matches('"').to_owned());
        }
        let workspace = get(&["devworkspace", "-n", &ns.name, "with-project"]).unwrap_or_default();
        let message = text(&workspace, "/status/message");
        if text(&workspace, "/status/phase") == "Failed" {
            panic!("the workspace failed before project-clone reached a pod: {message}; {events}");
        }
        Err(format!("no pod yet: {message}"))
    });
    assert!(
        clone.starts_with("localhost/quay/"),
        "project-clone was not rewritten: {clone}"
    );
}

/// Observation 3: the refusal. With the rewrite `Off`, the upstream name reaches `image-policy`
/// and is refused before any pod exists, so it is never pulled.
#[test]
fn with_the_rewrite_off_the_upstream_image_is_refused_and_never_pulled() {
    set_features(json!({
        "imagePolicy": local_images_only(&[]),
        "imageRewrite": image_rewrite("Off", mirror_rule()),
    }));
    let ns = Namespace::workspace("carol", "rewrite-off", None);
    let err = Workspace::try_create(
        &ns.name,
        "upstream",
        &WorkspaceSpec {
            image: UPSTREAM_IMAGE,
            ..WorkspaceSpec::default()
        },
    )
    .expect_err("an upstream image must be refused while the rewrite is off");
    assert!(
        err.contains(&format!(r#"image "{UPSTREAM_IMAGE}" is not permitted"#)),
        "{err}"
    );
    let events = must(&["get", "events", "-n", &ns.name, "-o", "json"]);
    assert!(
        !events.contains("example.invalid"),
        "something tried to pull the refused name: {events}"
    );
}

/// Observation 4: `DryRun` is refused exactly as `Off`, and counts what `Enforce` would rewrite.
#[test]
fn a_dry_run_rewrite_counts_the_rewrite_and_changes_nothing() {
    set_features(json!({
        "imagePolicy": local_images_only(&[]),
        "imageRewrite": image_rewrite("DryRun", mirror_rule()),
    }));
    let ns = Namespace::workspace("carol", "rewrite-dry", None);
    let before = rewritten_workspaces();
    let err = Workspace::try_create(
        &ns.name,
        "upstream",
        &WorkspaceSpec {
            image: UPSTREAM_IMAGE,
            ..WorkspaceSpec::default()
        },
    )
    .expect_err("a dry-run rewrite must leave the upstream name to be refused");
    assert!(err.contains("is not permitted"), "{err}");
    wait_until("the dry-run rewrite to be counted", RECONCILE, || {
        let after = rewritten_workspaces();
        if after > before {
            Ok(())
        } else {
            Err(format!("still {after}"))
        }
    });
}

/// Observation 5: a chain is refused by the apiserver itself, and the stored rules stay.
#[test]
fn a_chained_rule_set_is_refused_at_write_and_the_previous_rules_stay() {
    set_features(json!({ "imageRewrite": image_rewrite("Enforce", mirror_rule()) }));
    let err = try_apply(
        &json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiConfig",
            "metadata": { "name": "cluster" },
            "spec": { "features": { "imageRewrite": image_rewrite("Enforce", json!([
                { "from": "example.invalid", "to": "localhost/e2e" },
                { "from": "localhost", "to": "example.invalid/x" },
            ])) } },
        })
        .to_string(),
    )
    .expect_err("the apiserver must refuse a chain");
    assert!(err.contains("chain or loop"), "{err}");
    assert_eq!(
        get(&["weebosiconfig", "cluster"])
            .and_then(|c| c.pointer("/spec/features/imageRewrite/rules").cloned()),
        Some(mirror_rule())
    );
}

/// Observation 6: switching the rewrite on restarts nothing. A rule that would visibly change a
/// running workspace's image (`localhost` → `example.invalid/x`, both granted so a rewrite would
/// be admitted rather than refused) is enabled under it; label patches on its DevWorkspace and
/// its pod change no image and restart no container.
#[test]
fn enabling_the_rewrite_does_not_restart_a_running_workspace() {
    let rules = json!([{ "from": "localhost", "to": "example.invalid/x" }]);
    let policy = local_images_only(&["example.invalid/**"]);
    set_features(json!({
        "imagePolicy": policy,
        "imageRewrite": image_rewrite("Off", rules.clone()),
    }));
    let ns = Namespace::workspace("carol", "rewrite-late", None);
    let workspace = Workspace::create(&ns.name, "running", &WorkspaceSpec::default());
    workspace.wait_running();
    let pod = workspace.pod();
    let restarts = |pod: &str| {
        text(
            &get(&["pod", "-n", &ns.name, pod]).unwrap_or_default(),
            "/status/containerStatuses/0/restartCount",
        )
    };
    let before = restarts(&pod);

    set_features(json!({
        "imagePolicy": local_images_only(&["example.invalid/**"]),
        "imageRewrite": image_rewrite("Enforce", rules),
    }));
    must(&[
        "label",
        "--overwrite",
        "devworkspace",
        "-n",
        &ns.name,
        "running",
        "e2e.weebo.io/touched=yes",
    ]);
    must(&[
        "label",
        "--overwrite",
        "pod",
        "-n",
        &ns.name,
        &pod,
        "e2e.weebo.io/touched=yes",
    ]);

    assert_eq!(component_image(&workspace), weebo_si_e2e::WORKSPACE_IMAGE);
    let after = get(&["pod", "-n", &ns.name, &pod]).unwrap_or_default();
    assert_eq!(
        text(&after, "/spec/containers/0/image"),
        weebo_si_e2e::WORKSPACE_IMAGE
    );
    stays(
        "the workspace container keeps its restart count",
        Duration::from_secs(20),
        || {
            let now = restarts(&pod);
            if now == before {
                Ok(())
            } else {
                Err(format!("restartCount {before} → {now}"))
            }
        },
    );
}

// --- network-profiles and policy-guard --------------------------------------------------------------

/// Two templates: a baseline that allows DNS and nothing else out, and a profile that also
/// allows the rig's identity provider. Both select a label no pod carries — see the module docs.
fn network_templates() -> [Cleanup; 2] {
    let template = |name: &str, egress: serde_json::Value| {
        apply(
            &json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": { "name": name, "namespace": OPERATOR_NAMESPACE },
                "spec": {
                    "podSelector": { "matchLabels": { "e2e.weebo.io/template": "never-matches" } },
                    "policyTypes": ["Egress"],
                    "egress": egress,
                },
            })
            .to_string(),
        );
        Cleanup::new(&["networkpolicy", "-n", OPERATOR_NAMESPACE, name])
    };
    [
        template(
            "e2e-base",
            json!([{ "ports": [{ "protocol": "UDP", "port": 53 }, { "protocol": "TCP", "port": 53 }] }]),
        ),
        template(
            "e2e-sso",
            json!([{
                "to": [{ "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "sso" } } }],
                "ports": [{ "protocol": "TCP", "port": 8080 }],
            }]),
        ),
    ]
}

fn network_profiles() -> serde_json::Value {
    json!({
        "mode": "Enforce",
        "namespaceSelector": in_scope(),
        "catalog": [{
            "key": "base",
            "variants": [{ "backend": "NetworkPolicy",
                           "templateRef": { "name": "e2e-base", "namespace": OPERATOR_NAMESPACE } }],
        }],
        "baseline": "base",
        "onNotGranted": "Deny",
        "enforcement": { "backend": "NetworkPolicy", "canary": { "enabled": true, "intervalSeconds": 60 } },
    })
}

fn sso_team() -> Cleanup {
    sso_team_with(false)
}

/// The `sso` team, its `sso` profile marked `restricted` or not (RFC 0021).
fn sso_team_with(restricted: bool) -> Cleanup {
    team(
        "e2e-sso",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "sso" } },
            "features": { "networkProfiles": {
                "catalog": [{
                    "key": "sso",
                    "variants": [{ "backend": "NetworkPolicy",
                                   "templateRef": { "name": "e2e-sso", "namespace": OPERATOR_NAMESPACE } }],
                    "restricted": restricted,
                }],
                "default": [],
            } },
        }),
    )
}

/// Whether the workspace can open a TCP connection to Keycloak's Service.
fn reaches_sso(workspace: &Workspace) -> bool {
    workspace
        .exec(&[
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "--max-time",
            "5",
            "http://keycloak.sso.svc:8080/realms/che",
        ])
        .is_ok()
}

#[test]
fn the_baseline_drops_real_traffic_and_a_granted_profile_opens_exactly_its_own_path() {
    let _templates = network_templates();
    let _team = sso_team();
    set_features(
        json!({ "networkProfiles": network_profiles(), "policyGuard": { "mode": "Enforce", "namespaceSelector": in_scope() } }),
    );
    let ns = Namespace::workspace("carol", "network", Some("sso"));

    let baseline = wait_until("the baseline in the new namespace", RECONCILE, || {
        get(&["networkpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });
    assert_eq!(
        text(&baseline, "/metadata/labels/hardening.weebo.io~1managed-by"),
        "weebo-si-operator"
    );
    assert_eq!(text(&baseline, "/spec/podSelector"), "{}");

    let closed = Workspace::create(&ns.name, "closed", &WorkspaceSpec::default());
    closed.wait_running();
    assert!(
        !reaches_sso(&closed),
        "the baseline allows DNS only, so Keycloak must be unreachable"
    );

    let open = Workspace::create(
        &ns.name,
        "open",
        &WorkspaceSpec {
            attributes: json!({ "hardening.weebo.io/network-profiles": "sso" }),
            ..WorkspaceSpec::default()
        },
    );
    open.wait_running();
    let id = open.id();
    let profile = wait_until("the workspace's own profile object", RECONCILE, || {
        get(&["networkpolicy", "-n", &ns.name, &format!("weebo-sso-{id}")])
            .ok_or_else(|| "absent".to_string())
    });
    assert_eq!(
        text(
            &profile,
            "/spec/podSelector/matchLabels/controller.devfile.io~1devworkspace_id"
        ),
        id
    );
    wait_until("the granted profile to open the path", RECONCILE, || {
        if reaches_sso(&open) {
            Ok(())
        } else {
            Err("still dropped".into())
        }
    });
    // …and only for the workspace that asked: its neighbour stays closed.
    assert!(
        !reaches_sso(&closed),
        "the profile must select its own workspace only"
    );

    wait_until(
        "the canary to report an enforcing CNI",
        Duration::from_secs(300),
        || {
            let enforcing = metric_sum(
                "controller",
                "weebo_si_network_canary",
                &[("result", "enforcing")],
            );
            if enforcing >= 1.0 {
                Ok(())
            } else {
                Err(format!("canary {enforcing}"))
            }
        },
    );
}

#[test]
fn an_ungranted_profile_is_refused_before_the_workspace_exists() {
    let _templates = network_templates();
    set_features(json!({ "networkProfiles": network_profiles() }));
    let ns = Namespace::workspace("bob", "network-deny", None);
    wait_until("the baseline", RECONCILE, || {
        get(&["networkpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });
    let err = Workspace::try_create(
        &ns.name,
        "greedy",
        &WorkspaceSpec {
            attributes: json!({ "hardening.weebo.io/network-profiles": "sso" }),
            ..WorkspaceSpec::default()
        },
    )
    .expect_err("bob's namespace is in no team, so `sso` is not granted");
    assert!(err.contains("requests network profile(s) [sso]"), "{err}");
}

// --- restricted profiles and namespace grants (RFC 0021) ----------------------------------------

const NETWORK_GRANTS: &str = "hardening.weebo.io/network-grants";

/// `network_profiles()` in `mode`, with `onNotGranted: Default` so a refused restricted key
/// starts the workspace on the team default.
fn network_profiles_default(mode: &str) -> serde_json::Value {
    let mut features = network_profiles();
    features["mode"] = json!(mode);
    features["onNotGranted"] = json!("Default");
    features
}

fn restricted_total(result: &str) -> f64 {
    metric_sum(
        "controller",
        "weebo_si_restricted_grant_total",
        &[
            ("feature", "network-profiles"),
            ("key", "sso"),
            ("result", result),
        ],
    )
}

/// The Events with `reason` regarding `workspace`.
fn restricted_events(workspace: &Workspace, reason: &str) -> usize {
    get(&[
        "events",
        "-n",
        &workspace.namespace,
        "--field-selector",
        &format!("reason={reason},involvedObject.name={}", workspace.name),
    ])
    .and_then(|list| {
        list.get("items")
            .and_then(|items| items.as_array())
            .map(Vec::len)
    })
    .unwrap_or(0)
}

/// A namespace in team `sso`, with its baseline, and a workspace in it naming `sso` itself.
fn sso_workspace(user: &str) -> (Namespace, Workspace) {
    let ns = Namespace::workspace(user, "restricted", Some("sso"));
    wait_until("the baseline", RECONCILE, || {
        get(&["networkpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });
    let workspace = Workspace::create(
        &ns.name,
        "wants-sso",
        &WorkspaceSpec {
            attributes: json!({ "hardening.weebo.io/network-profiles": "sso" }),
            ..WorkspaceSpec::default()
        },
    );
    (ns, workspace)
}

fn profile_object(workspace: &Workspace, id: &str) -> Option<serde_json::Value> {
    get(&[
        "networkpolicy",
        "-n",
        &workspace.namespace,
        &format!("weebo-sso-{id}"),
    ])
}

/// RFC 0021 (1)(2), T-07: the workspace names a restricted profile itself; nothing is written
/// until the Namespace grants it, and both outcomes leave a counter and an Event.
#[test]
fn a_restricted_profile_is_honoured_only_through_the_namespace() {
    let _templates = network_templates();
    let _team = sso_team_with(true);
    set_features(json!({ "networkProfiles": network_profiles_default("Enforce") }));
    let refused_before = restricted_total("refused");
    let honoured_before = restricted_total("honoured");
    let (ns, workspace) = sso_workspace("dave");
    let id = workspace.id();

    wait_until("the refusal to be counted", RECONCILE, || {
        let now = restricted_total("refused");
        if now > refused_before {
            Ok(())
        } else {
            Err(format!("refused {now}"))
        }
    });
    assert!(restricted_events(&workspace, "RestrictedGrantRefused") >= 1);
    stays(
        "no sso profile without the grant",
        Duration::from_secs(15),
        || match profile_object(&workspace, &id) {
            None => Ok(()),
            Some(_) => Err("weebo-sso written without a namespace grant".into()),
        },
    );

    ns.annotate(NETWORK_GRANTS, "sso");
    wait_until("the granted profile", Duration::from_secs(30), || {
        profile_object(&workspace, &id).ok_or_else(|| "absent".to_string())
    });
    wait_until("the honoured Event and count", RECONCILE, || {
        let now = restricted_total("honoured");
        if now > honoured_before && restricted_events(&workspace, "RestrictedGrantHonoured") >= 1 {
            Ok(())
        } else {
            Err(format!("honoured {now}"))
        }
    });
}

/// RFC 0021 S9: in `DryRun` nothing is written, the refusal is still counted.
#[test]
fn a_dry_run_restricted_refusal_is_still_counted() {
    let _templates = network_templates();
    let _team = sso_team_with(true);
    // The baseline is written in Enforce first: the gate refuses a workspace without one.
    set_features(json!({ "networkProfiles": network_profiles_default("Enforce") }));
    let ns = Namespace::workspace("erin", "restricted", Some("sso"));
    wait_until("the baseline", RECONCILE, || {
        get(&["networkpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });
    set_features(json!({ "networkProfiles": network_profiles_default("DryRun") }));
    let refused_before = restricted_total("refused");
    let workspace = Workspace::create(
        &ns.name,
        "wants-sso",
        &WorkspaceSpec {
            attributes: json!({ "hardening.weebo.io/network-profiles": "sso" }),
            ..WorkspaceSpec::default()
        },
    );
    let id = workspace.id();
    wait_until("the dry-run refusal to be counted", RECONCILE, || {
        let now = restricted_total("refused");
        if now > refused_before {
            Ok(())
        } else {
            Err(format!("refused {now}"))
        }
    });
    assert!(profile_object(&workspace, &id).is_none());
}

/// RFC 0021 (7): under `onNotGranted: Deny` a CREATE naming an ungranted restricted profile is
/// refused, in the restricted wording.
#[test]
fn a_restricted_profile_without_the_grant_is_refused_at_create_under_deny() {
    let _templates = network_templates();
    let _team = sso_team_with(true);
    set_features(json!({ "networkProfiles": network_profiles() }));
    let ns = Namespace::workspace("frank", "restricted", Some("sso"));
    wait_until("the baseline", RECONCILE, || {
        get(&["networkpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });
    let err = Workspace::try_create(
        &ns.name,
        "wants-sso",
        &WorkspaceSpec {
            attributes: json!({ "hardening.weebo.io/network-profiles": "sso" }),
            ..WorkspaceSpec::default()
        },
    )
    .expect_err("sso is restricted and the namespace does not grant it");
    assert!(
        err.contains(&format!(
            "requests network profile(s) [sso], which are restricted: namespace {} does not \
             grant them (annotation {NETWORK_GRANTS})",
            ns.name
        )),
        "{err}"
    );
    assert!(get(&["devworkspace", "-n", &ns.name, "wants-sso"]).is_none());
}

/// RFC 0021 S6 / (6): the Namespace event re-queues the workspace, so a removed grant takes the
/// profile away well inside the 300 s requeue. 30 s: one watch event, one reconcile, one delete.
#[test]
fn removing_a_network_grant_removes_the_profile_within_30_seconds() {
    let _templates = network_templates();
    let _team = sso_team_with(true);
    set_features(json!({ "networkProfiles": network_profiles_default("Enforce") }));
    let (ns, workspace) = sso_workspace("grace");
    ns.annotate(NETWORK_GRANTS, "sso");
    let id = workspace.id();
    wait_until("the granted profile", RECONCILE, || {
        profile_object(&workspace, &id).ok_or_else(|| "absent".to_string())
    });

    must(&[
        "annotate",
        "namespace",
        &ns.name,
        &format!("{NETWORK_GRANTS}-"),
    ]);
    wait_until(
        "the profile to go with the grant",
        Duration::from_secs(30),
        || match profile_object(&workspace, &id) {
            None => Ok(()),
            Some(_) => Err("still there".into()),
        },
    );
}

#[test]
fn policy_guard_refuses_even_a_cluster_admin_and_the_controller_puts_drift_back() {
    let _templates = network_templates();
    set_features(json!({
        "networkProfiles": network_profiles(),
        "policyGuard": { "mode": "Enforce", "namespaceSelector": in_scope() },
    }));
    let ns = Namespace::workspace("bob", "guard", None);
    wait_until("the baseline", RECONCILE, || {
        get(&["networkpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });

    let err = kubectl(&["delete", "networkpolicy", "-n", &ns.name, "weebo-base"])
        .expect_err("deleting a managed policy must be refused");
    assert!(err.contains("is managed by weebo-si-operator"), "{err}");

    let err = try_apply(
        &json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": { "name": "allow-everything", "namespace": ns.name },
            "spec": { "podSelector": {}, "policyTypes": ["Egress"], "egress": [{}] },
        })
        .to_string(),
    )
    .expect_err("authoring a policy in a workspace namespace must be refused");
    assert!(err.contains("belongs to the platform"), "{err}");

    // The operator's own write path is the one the guard exempts: prove it by changing the
    // template and watching the change land through the guard.
    apply(
        &json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": { "name": "e2e-base", "namespace": OPERATOR_NAMESPACE },
            "spec": {
                "podSelector": { "matchLabels": { "e2e.weebo.io/template": "never-matches" } },
                "policyTypes": ["Egress"],
                "egress": [{ "ports": [{ "protocol": "UDP", "port": 53 }] }],
            },
        })
        .to_string(),
    );
    // Nothing watches the templates: an edit lands on the namespace's five-minute requeue.
    wait_until(
        "the edited template to reach the namespace",
        Duration::from_secs(360),
        || {
            let live = get(&["networkpolicy", "-n", &ns.name, "weebo-base"]).ok_or("absent")?;
            let ports = live
                .pointer("/spec/egress/0/ports")
                .and_then(|p| p.as_array())
                .map(Vec::len);
            if ports == Some(1) {
                Ok(())
            } else {
                Err(format!("ports {ports:?}"))
            }
        },
    );
}

// --- registry-config --------------------------------------------------------------------------------

fn registry_templates() -> [Cleanup; 2] {
    // DWO only caches objects carrying its watch label, so an automount label without it mounts
    // nothing; the copies keep the template's labels verbatim, so the template is where it goes.
    let metadata = |name: &str, watch: &str| {
        json!({
            "name": name,
            "namespace": OPERATOR_NAMESPACE,
            "labels": {
                "controller.devfile.io/mount-to-devworkspace": "true",
                format!("controller.devfile.io/watch-{watch}"): "true",
            },
            "annotations": {
                "controller.devfile.io/mount-as": "subpath",
                "controller.devfile.io/mount-path": "/home/user",
            },
        })
    };
    apply(
        &json!({
            "apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata("e2e-npmrc", "configmap"),
            "data": { ".npmrc": "registry=https://npm.e2e.weebo.si/\n" },
        })
        .to_string(),
    );
    apply(
        &json!({
            "apiVersion": "v1", "kind": "Secret", "metadata": metadata("e2e-npm-token", "secret"),
            "stringData": { ".npm-token": "e2e-not-a-real-token\n" },
        })
        .to_string(),
    );
    [
        Cleanup::new(&["configmap", "-n", OPERATOR_NAMESPACE, "e2e-npmrc"]),
        Cleanup::new(&["secret", "-n", OPERATOR_NAMESPACE, "e2e-npm-token"]),
    ]
}

fn registry_config() -> serde_json::Value {
    json!({
        "mode": "Enforce",
        "namespaceSelector": in_scope(),
        "catalog": [],
        "onNotGranted": "Default",
    })
}

fn registry_team() -> Cleanup {
    team(
        "e2e-npm",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "npm" } },
            "features": { "registryConfig": {
                "catalog": [{
                    "key": "internal-npm",
                    "ecosystem": "Npm",
                    "sources": [
                        { "kind": "ConfigMap", "templateRef": { "name": "e2e-npmrc", "namespace": OPERATOR_NAMESPACE } },
                        { "kind": "Secret", "templateRef": { "name": "e2e-npm-token", "namespace": OPERATOR_NAMESPACE } },
                    ],
                }],
                "default": ["internal-npm"],
            } },
        }),
    )
}

#[test]
fn a_teams_registry_configuration_is_copied_mounted_by_devworkspace_operator_and_guarded() {
    let _templates = registry_templates();
    let _team = registry_team();
    // The guard on the copies is `policyGuard`'s — one mode for every guard rule this operator
    // serves — so asserting the refusal below needs it on as well.
    set_features(json!({
        "registryConfig": registry_config(),
        "policyGuard": { "mode": "Enforce", "namespaceSelector": in_scope() },
    }));
    let ns = Namespace::workspace("alice", "registry", Some("npm"));

    wait_until("both copies in the team's namespace", RECONCILE, || {
        let cm = get(&[
            "configmap",
            "-n",
            &ns.name,
            "weebo-si-internal-npm-e2e-npmrc",
        ]);
        let secret = get(&[
            "secret",
            "-n",
            &ns.name,
            "weebo-si-internal-npm-e2e-npm-token",
        ]);
        match (cm, secret) {
            (Some(_), Some(_)) => Ok(()),
            (cm, secret) => Err(format!(
                "configmap {}, secret {}",
                cm.is_some(),
                secret.is_some()
            )),
        }
    });

    let workspace = Workspace::create(&ns.name, "npm", &WorkspaceSpec::default());
    workspace.wait_running();
    let npmrc = workspace.exec(&["cat", "/home/user/.npmrc"]).unwrap();
    assert_eq!(npmrc, "registry=https://npm.e2e.weebo.si/\n");

    // A hand edit of a managed copy is refused.
    let err = kubectl(&[
        "patch",
        "configmap",
        "-n",
        &ns.name,
        "weebo-si-internal-npm-e2e-npmrc",
        "--type=merge",
        "-p",
        r#"{"data":{".npmrc":"registry=https://evil.example/\n"}}"#,
    ])
    .expect_err("editing a managed copy must be refused");
    assert!(err.contains("is managed by weebo-si-operator"), "{err}");

    // A namespace in no team gets nothing — and keeps getting nothing.
    let bystander = Namespace::workspace("bob", "registry-none", None);
    stays(
        "no registry copy outside the team",
        Duration::from_secs(30),
        || match get(&[
            "configmap",
            "-n",
            &bystander.name,
            "weebo-si-internal-npm-e2e-npmrc",
        ]) {
            None => Ok(()),
            Some(_) => Err("a copy appeared".into()),
        },
    );
    assert_eq!(text(&feature_status("registry-config"), "/state"), "Active");
}

// --- passwd-append ----------------------------------------------------------------------------------

#[test]
fn passwd_append_gives_devworkspace_operators_arbitrary_uid_a_name() {
    set_features(json!({}));
    let ns = Namespace::workspace("alice", "passwd", None);
    let workspace = Workspace::create(&ns.name, "whoami", &WorkspaceSpec::default());
    workspace.wait_running();

    assert_eq!(workspace.exec(&["whoami"]).unwrap().trim(), "user");
    let uid = workspace.exec(&["id", "-u"]).unwrap().trim().to_string();
    let entry = workspace.exec(&["getent", "passwd", &uid]).unwrap();
    assert_eq!(
        entry.trim(),
        format!("user:x:{uid}:0:user user:/home/user:/bin/bash")
    );
    let group = workspace.exec(&["getent", "group", &uid]).unwrap();
    assert_eq!(group.trim(), format!("user:x:{uid}:"));

    let logs = must(&["logs", "-n", &ns.name, &workspace.pod(), "-c", "tools"]);
    assert!(
        logs.contains("passwd-append: appended to /etc/passwd"),
        "{logs}"
    );
}

// --- teams and status -------------------------------------------------------------------------------

#[test]
fn a_team_reports_its_namespaces_and_a_conflicting_redefinition_is_blamed_on_it() {
    let _hardened = dwoc("e2e-hardened");
    let _gpu = dwoc("e2e-gpu");
    set_features(json!({ "dwocPin": dwoc_pin("hardened", "Default") }));
    // Namespaces before teams: the team loop counts them when a team changes and otherwise only
    // on its five-minute requeue, which is longer than the suite waits.
    let _a = Namespace::workspace("alice", "first-a", Some("first"));
    let _b = Namespace::workspace("carol", "first-b", Some("first"));
    let _first = team(
        "e2e-first",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "first" } },
            "features": { "dwocPin": {
                "catalog": [{ "key": "shared", "name": "e2e-gpu", "namespace": "eclipse-che" }],
                "default": "shared",
            } },
        }),
    );
    let _second = team(
        "e2e-second",
        json!({
            "priority": 20,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "second" } },
            "features": { "dwocPin": {
                "catalog": [{ "key": "shared", "name": "e2e-hardened", "namespace": "eclipse-che" }],
                "default": "shared",
            } },
        }),
    );

    wait_until(
        "team e2e-first to count its two namespaces",
        RECONCILE,
        || {
            let team = get(&["weebositeam", "e2e-first"]).ok_or("absent")?;
            let namespaces = text(&team, "/status/namespaces");
            if namespaces == "2" {
                Ok(())
            } else {
                Err(format!("namespaces {namespaces:?}"))
            }
        },
    );
    wait_until(
        "team e2e-second to be Degraded for redefining `shared`",
        RECONCILE,
        || {
            let team = get(&["weebositeam", "e2e-second"]).ok_or("absent")?;
            let conditions = team
                .pointer("/status/conditions")
                .cloned()
                .unwrap_or_default();
            let degraded = conditions
                .as_array()
                .into_iter()
                .flatten()
                .find(|c| text(c, "/type") == "Degraded" && text(c, "/status") == "True");
            match degraded {
                Some(c) if text(c, "/message").contains("shared") => Ok(()),
                _ => Err(format!("conditions {conditions}")),
            }
        },
    );
    // The team that defined the key first is not blamed.
    let first = get(&["weebositeam", "e2e-first"]).unwrap();
    assert!(
        !first.to_string().contains("redefines"),
        "e2e-first must not carry e2e-second's mistake: {first}"
    );
}

// --- devfile-contract (RFC 0019, *Proof against a real client*) --------------------------------------

/// The real `weebo-che-project` parent: WeeboDevImage on `refs/heads/main` (row 2).
const BRANCH_PARENT: &str = "https://raw.githubusercontent.com/batleforc/WeeboDevImage/refs/heads/main/che-min-mise/devfile.yaml";
/// The namespace of the suite's own parent devfile server: outside every feature's selector.
const PARENTS_NS: &str = "e2e-devfile-parents";
/// A 40-hex path segment, which the classifier reads as a pinned commit.
const PARENT_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const CONTRACT_ANNOTATION: &str = "hardening.weebo.io/devfile-contract";
const REASON_ANNOTATION: &str = "hardening.weebo.io/devfile-contract-reason";
const ABSENT_WARNING: &str = "devfile has no weebo.io/platform-contract attribute; add \"weebo.io/platform-contract: 3\" to its attributes";
const BRANCH_WARNING: &str =
    "devfile parent follows branch \"main\": pin parent.uri to a tag or a commit";
/// What every devfile-contract refusal is prefixed with: denials on this route are HTTP 400,
/// which kubectl prints as a bare `Error from server:` (not the RFC mocks' `Forbidden`).
const DENIED_BY: &str =
    "admission webhook \"devworkspaces.hardening.weebo.io\" denied the request: ";

/// The pinned parent's URI, served in-cluster by [`parent_server`] — no internet needed for
/// DevWorkspace Operator to resolve it.
fn pinned_parent() -> String {
    format!("http://parents.{PARENTS_NS}.svc:8080/{PARENT_COMMIT}/devfile.yaml")
}

/// The mocks' configuration: `currentContract: 3`, `minimumContract: 2`, schema `2.2.0`.
fn devfile_contract(mode: &str, denied_parents: serde_json::Value) -> serde_json::Value {
    json!({
        "mode": mode,
        "namespaceSelector": in_scope(),
        "currentContract": 3,
        "minimumContract": 2,
        "minimumSchemaVersion": "2.2.0",
        "deniedContracts": [],
        "deniedParents": denied_parents,
        "onDenied": "Deny",
    })
}

/// [`Workspace::manifest`] with a devfile `parent` and `started`.
fn with_parent(
    namespace: &str,
    name: &str,
    spec: &WorkspaceSpec<'_>,
    parent: serde_json::Value,
    started: bool,
) -> serde_json::Value {
    let mut manifest = Workspace::manifest(namespace, name, spec);
    manifest["spec"]["template"]["parent"] = parent;
    manifest["spec"]["started"] = json!(started);
    manifest
}

/// The `weebo-che-project` devfile as a DevWorkspace: no contract, parent on a branch (row 2).
fn weebo_che_project(namespace: &str, name: &str, spec: &WorkspaceSpec<'_>) -> serde_json::Value {
    with_parent(namespace, name, spec, json!({ "uri": BRANCH_PARENT }), true)
}

/// Apply `manifest`, failing the test on a refusal: the workspace (dropped = deleted) and
/// kubectl's stderr.
#[track_caller]
fn apply_dw(manifest: &serde_json::Value) -> (Workspace, String) {
    let stderr =
        try_apply_with_warnings(&manifest.to_string()).unwrap_or_else(|err| panic!("{err}"));
    let workspace = Workspace {
        namespace: text(manifest, "/metadata/namespace"),
        name: text(manifest, "/metadata/name"),
    };
    (workspace, stderr)
}

/// The admission warnings in kubectl's stderr, without kubectl's `Warning: ` prefix.
fn warnings(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter_map(|line| line.strip_prefix("Warning: "))
        .collect()
}

fn annotation(workspace: &Workspace, key: &str) -> String {
    text(
        &workspace.object(),
        &format!("/metadata/annotations/{}", key.replace('/', "~1")),
    )
}

/// A plain HTTP server for the pinned parent devfile, in a namespace of its own: the suite's
/// workspace image running `python3 -m http.server` over a ConfigMap at `/<PARENT_COMMIT>/`.
fn parent_server() -> Cleanup {
    // A rerun must not apply into the previous run's namespace (left over or terminating).
    delete(&["namespace", PARENTS_NS]);
    wait_until(
        "the previous parents namespace to be gone",
        RECONCILE,
        || get(&["namespace", PARENTS_NS]).map_or(Ok(()), |_| Err("still there".to_string())),
    );
    let devfile = "schemaVersion: 2.2.0\nmetadata:\n  name: e2e-parent\n";
    for object in [
        json!({ "apiVersion": "v1", "kind": "Namespace", "metadata": { "name": PARENTS_NS } }),
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "parent", "namespace": PARENTS_NS },
            "data": { "devfile.yaml": devfile },
        }),
        json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "parents", "namespace": PARENTS_NS, "labels": { "app": "parents" } },
            "spec": {
                "securityContext": { "runAsNonRoot": true, "seccompProfile": { "type": "RuntimeDefault" } },
                "containers": [{
                    "name": "http",
                    "image": weebo_si_e2e::WORKSPACE_IMAGE,
                    "command": ["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/srv"],
                    "ports": [{ "containerPort": 8080 }],
                    // Ready only once the server listens: without a probe the endpoint is ready
                    // before Python binds, and DWO's single fetch meets "connection refused".
                    "readinessProbe": { "tcpSocket": { "port": 8080 }, "periodSeconds": 1 },
                    "securityContext": {
                        "allowPrivilegeEscalation": false,
                        "capabilities": { "drop": ["ALL"] },
                    },
                    "volumeMounts": [{ "name": "parent", "mountPath": format!("/srv/{PARENT_COMMIT}") }],
                }],
                "volumes": [{ "name": "parent", "configMap": { "name": "parent" } }],
            },
        }),
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "parents", "namespace": PARENTS_NS },
            // Headless: DNS names the pod itself, so no kube-proxy rule lagging behind the
            // ready endpoint can refuse DWO's single fetch (nightly of 2026-11-27).
            "spec": { "clusterIP": "None", "selector": { "app": "parents" }, "ports": [{ "port": 8080 }] },
        }),
    ] {
        apply(&object.to_string());
    }
    let cleanup = Cleanup::new(&["namespace", PARENTS_NS]);
    must(&[
        "wait",
        "-n",
        PARENTS_NS,
        "--for=condition=Ready",
        "pod/parents",
        "--timeout=600s",
    ]);
    // A Ready pod is not yet a Service endpoint: DWO's fetch would meet "connection refused".
    wait_until("the parents Service to have an endpoint", RECONCILE, || {
        let slices = get(&[
            "endpointslices",
            "-n",
            PARENTS_NS,
            "-l",
            "kubernetes.io/service-name=parents",
        ])
        .ok_or("no endpointslice list")?;
        let ready = slices
            .pointer("/items")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|slice| {
                    slice
                        .pointer("/endpoints")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|endpoints| {
                            endpoints.iter().any(|endpoint| {
                                endpoint.pointer("/conditions/ready")
                                    == Some(&serde_json::Value::Bool(true))
                            })
                        })
                })
            });
        if ready {
            Ok(())
        } else {
            Err("no ready endpoint".to_string())
        }
    });
    cleanup
}

fn warnings_total(mode: &str) -> f64 {
    metric_sum(
        "webhook",
        "weebo_si_admission_warnings_total",
        &[("feature", "devfile-contract"), ("mode", mode)],
    )
}

/// Rows 1 and 5. A current devfile costs zero lines of output and runs; denying its parent later
/// never blocks the running workspace's stop or delete, only its next start.
#[test]
fn a_current_devfile_is_silent_and_a_later_denial_only_refuses_the_next_start() {
    let _server = parent_server();
    set_features(json!({ "devfileContract": devfile_contract("Enforce", json!([])) }));
    let ns = Namespace::workspace("alice", "devfile-current", None);
    let current = WorkspaceSpec {
        attributes: json!({ "weebo.io/platform-contract": 3 }),
        ..WorkspaceSpec::default()
    };
    let parent = json!({ "uri": pinned_parent() });

    let (workspace, stderr) = apply_dw(&with_parent(
        &ns.name,
        "go-api",
        &current,
        parent.clone(),
        true,
    ));
    assert_eq!(stderr, "", "a current devfile prints nothing");
    assert_eq!(annotation(&workspace, CONTRACT_ANNOTATION), "current");
    workspace.wait_running();
    // The copy is created stopped while nothing is denied: a CREATE is a start (D-13).
    let (copy, _) = apply_dw(&with_parent(
        &ns.name,
        "go-api-copy",
        &current,
        parent,
        false,
    ));

    let prefix = format!("http://parents.{PARENTS_NS}.svc:8080/{PARENT_COMMIT}/");
    set_features(json!({
        "devfileContract": devfile_contract("Enforce", json!([{ "uriPrefix": prefix }])),
    }));
    let stop = weebo_si_e2e::kubectl_with_warnings(
        &[
            "patch",
            "devworkspace",
            "-n",
            &ns.name,
            &workspace.name,
            "--type=merge",
            "-p",
            r#"{"spec":{"started":false}}"#,
        ],
        None,
    )
    .unwrap_or_else(|err| panic!("a stop is never refused: {err}"));
    assert!(
        warnings(&stop).contains(
            &"devfile parent is denied by the platform (deniedParents entry 1): this workspace will be refused at its next start"
        ),
        "{stop}"
    );
    must(&[
        "delete",
        "devworkspace",
        "-n",
        &ns.name,
        &workspace.name,
        "--timeout=300s",
    ]);

    let err = kubectl(&[
        "patch",
        "devworkspace",
        "-n",
        &ns.name,
        &copy.name,
        "--type=merge",
        "-p",
        r#"{"spec":{"started":true}}"#,
    ])
    .expect_err("starting a workspace on a denied parent is refused");
    assert!(
        err.contains("Error from server") && err.contains(DENIED_BY),
        "{err}"
    );
}

/// Row 2: the real-world devfile, exactly the mock's two warnings and the `unknown` annotation.
#[test]
fn the_weebo_che_project_devfile_gets_exactly_the_two_warnings_of_the_mock() {
    set_features(json!({ "devfileContract": devfile_contract("Enforce", json!([])) }));
    let ns = Namespace::workspace("alice", "devfile-real", None);
    let (workspace, stderr) = apply_dw(&weebo_che_project(
        &ns.name,
        "weebo-che-project",
        &WorkspaceSpec::default(),
    ));
    assert_eq!(
        warnings(&stderr),
        [ABSENT_WARNING, BRANCH_WARNING],
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 2, "{stderr}");
    assert_eq!(annotation(&workspace, CONTRACT_ANNOTATION), "unknown");
    assert_eq!(
        annotation(&workspace, REASON_ANNOTATION),
        "contract-absent,parent-branch,schema-unknown"
    );
}

/// Row 3: a DevWorkspaceTemplate parent warns once, and the workspace still starts.
#[test]
fn a_devworkspacetemplate_parent_warns_and_still_starts() {
    set_features(json!({ "devfileContract": devfile_contract("Enforce", json!([])) }));
    let ns = Namespace::workspace("alice", "devfile-dwt", None);
    apply(
        &json!({
            "apiVersion": "workspace.devfile.io/v1alpha2",
            "kind": "DevWorkspaceTemplate",
            "metadata": { "name": "base", "namespace": ns.name },
            "spec": {},
        })
        .to_string(),
    );
    let spec = WorkspaceSpec {
        attributes: json!({ "weebo.io/platform-contract": 3 }),
        ..WorkspaceSpec::default()
    };
    let (workspace, stderr) = apply_dw(&with_parent(
        &ns.name,
        "dwt-parent",
        &spec,
        json!({ "kubernetes": { "name": "base" } }),
        true,
    ));
    assert_eq!(
        warnings(&stderr),
        [
            "devfile parent is a DevWorkspaceTemplate (parent.kubernetes): the workspace itself can change it"
        ],
        "{stderr}"
    );
    workspace.wait_running();
}

/// Row 4: a denied parent is refused with the mock's text (HTTP 400, a bare `Error from server:`), and nothing
/// reaches DevWorkspace Operator.
#[test]
fn a_denied_parent_is_refused_before_devworkspace_operator_sees_it() {
    let prefix = format!("http://parents.{PARENTS_NS}.svc:8080/{PARENT_COMMIT}/");
    set_features(json!({
        "devfileContract": devfile_contract("Enforce", json!([{ "uriPrefix": prefix }])),
    }));
    let ns = Namespace::workspace("bob", "devfile-denied", None);
    let spec = WorkspaceSpec {
        attributes: json!({ "weebo.io/platform-contract": 3 }),
        ..WorkspaceSpec::default()
    };
    let manifest = with_parent(
        &ns.name,
        "old-base",
        &spec,
        json!({ "uri": pinned_parent() }),
        true,
    );
    let err = try_apply_with_warnings(&manifest.to_string())
        .expect_err("the parent is on the denied list");
    assert!(err.contains("exit status: 1"), "{err}");
    assert!(err.contains("Error from server"), "{err}");
    assert!(
        err.contains(&format!(
            "{DENIED_BY}devfile parent is denied by the platform (deniedParents entry 1: {prefix}): \
             move parent.uri to a newer version; contract 3 in the User Guide lists them"
        )),
        "{err}"
    );
    assert!(get(&["devworkspace", "-n", &ns.name, "old-base"]).is_none());
    let created = get(&["devworkspacetemplates,deployments", "-n", &ns.name]).unwrap();
    assert_eq!(created["items"], json!([]), "{created}");
}

/// Row 6: DryRun shows the developer nothing and writes nothing, yet counts the two warnings.
#[test]
fn dry_run_is_invisible_to_the_developer_and_counted() {
    let ns = Namespace::workspace("carol", "devfile-dry", None);
    // Scoped to this namespace alone: the counter is global, and an earlier test's workspace
    // still being torn down would otherwise add its own warnings.
    let mut config = devfile_contract("DryRun", json!([]));
    config["namespaceSelector"] =
        json!({ "matchLabels": { "kubernetes.io/metadata.name": ns.name } });
    set_features(json!({ "devfileContract": config }));
    let before = warnings_total("dry_run");
    // (2)'s object, stopped: an ephemeral, stopped workspace gets no write from DevWorkspace
    // Operator that would be judged again before the scrape.
    let mut manifest = weebo_che_project(&ns.name, "dry", &WorkspaceSpec::default());
    manifest["spec"]["started"] = json!(false);
    let (workspace, stderr) = apply_dw(&manifest);
    assert_eq!(stderr, "", "DryRun prints nothing");
    assert_eq!(annotation(&workspace, CONTRACT_ANNOTATION), "");
    let delta = warnings_total("dry_run") - before;
    assert!(
        (delta - 2.0).abs() < f64::EPSILON,
        "warnings counter moved by {delta}"
    );
}

/// Row 7: a 10 KiB generator full of ESC and CRLF reaches no warning and at most 32 characters
/// of the log line.
#[test]
fn a_hostile_generator_attribute_is_bounded_everywhere() {
    set_features(json!({ "devfileContract": devfile_contract("Enforce", json!([])) }));
    let ns = Namespace::workspace("dave", "devfile-bounds", None);
    let generator = "\u{1b}[31mgen\r\n".repeat(1024);
    let spec = WorkspaceSpec {
        attributes: json!({ "weebo.io/generator": generator }),
        ..WorkspaceSpec::default()
    };
    let (workspace, stderr) = apply_dw(&weebo_che_project(&ns.name, "hostile", &spec));
    assert!(
        !stderr.contains('\u{1b}'),
        "an ESC byte reached kubectl: {stderr:?}"
    );
    for warning in warnings(&stderr) {
        assert!(warning.chars().count() <= 120, "{warning:?}");
    }

    let needle = format!("workspace={} ", workspace.name);
    let line = wait_until("the decision's log line", RECONCILE, || {
        weebo_si_e2e::operator_pods("webhook")
            .iter()
            .filter_map(|pod| kubectl(&["logs", "-n", OPERATOR_NAMESPACE, pod, "--since=10m"]).ok())
            .flat_map(|logs| logs.lines().map(str::to_string).collect::<Vec<_>>())
            .find(|line| line.contains("devfile-contract") && line.contains(&needle))
            .ok_or_else(|| "no devfile-contract line for the workspace yet".to_string())
    });
    let field = line
        .split("generator=")
        .nth(1)
        .unwrap_or_else(|| panic!("no generator= field: {line}"));
    let value: String = field
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\u{1b}'))
        .collect();
    // The field only: the log formatter may colour the rest of the line with its own ESC codes.
    assert!(
        !value.is_empty()
            && value.chars().count() <= 32
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-')),
        "generator={value:?} in {line:?}"
    );
}

/// Row 8: with the image rewrite on, the apiserver reinvokes this webhook after the rewrite.
/// The RFC leaves open whether kubectl then prints each warning once or twice [R10].
// shortcut: accepts once or twice until a kind run records the count; pin it to that count then.
#[test]
fn a_reinvocation_prints_each_warning_the_same_number_of_times() {
    set_features(json!({
        "devfileContract": devfile_contract("Enforce", json!([])),
        "imageRewrite": image_rewrite("Enforce", mirror_rule()),
    }));
    let ns = Namespace::workspace("erin", "devfile-reinvoke", None);
    let spec = WorkspaceSpec {
        image: UPSTREAM_IMAGE,
        ..WorkspaceSpec::default()
    };
    let (workspace, stderr) = apply_dw(&weebo_che_project(&ns.name, "reinvoked", &spec));
    assert_eq!(
        component_image(&workspace),
        MIRRORED_IMAGE,
        "the rewrite ran"
    );
    let lines = warnings(&stderr);
    let absent = lines.iter().filter(|line| **line == ABSENT_WARNING).count();
    let branch = lines.iter().filter(|line| **line == BRANCH_WARNING).count();
    eprintln!("reinvocation: each warning printed {absent} time(s)");
    assert!(
        (1..=2).contains(&absent) && absent == branch && lines.len() == absent * 2,
        "{stderr}"
    );
}

#[test]
fn the_webhook_fails_closed_when_it_is_down() {
    set_features(json!({ "imagePolicy": workspace_image_only() }));
    let ns = Namespace::workspace("bob", "fail-closed", None);
    let deployment = "deploy/weebo-si-operator-webhook".to_string();
    must(&[
        "scale",
        "-n",
        OPERATOR_NAMESPACE,
        &deployment,
        "--replicas=0",
    ]);
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = kubectl(&["scale", "-n", OPERATOR_NAMESPACE, &self.0, "--replicas=2"]);
            // `rollout status` returns at once after a scale (the generation did not move): wait
            // for both replicas to be ready, or the next test meets "connection refused".
            let _ = kubectl(&[
                "wait",
                "-n",
                OPERATOR_NAMESPACE,
                &self.0,
                "--for=jsonpath={.status.readyReplicas}=2",
                "--timeout=300s",
            ]);
            // Ready replicas are not yet a programmed Service: until a dry run is admitted, the
            // next test's write meets "connection refused" (nightly of 2026-11-27). No panic in
            // a Drop: a test already unwinding would abort.
            let probe = r#"{"apiVersion":"workspace.devfile.io/v1alpha2","kind":"DevWorkspace","metadata":{"name":"e2e-webhook-probe","namespace":"default"},"spec":{"started":false,"template":{}}}"#;
            for _ in 0..60 {
                if weebo_si_e2e::kubectl_with(
                    &["apply", "--dry-run=server", "-f", "-"],
                    Some(probe),
                )
                .is_ok()
                {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
    let _restore = Restore(deployment);
    wait_until("every webhook replica to be gone", RECONCILE, || {
        if weebo_si_e2e::operator_pods("webhook").is_empty() {
            Ok(())
        } else {
            Err("still running".into())
        }
    });
    let err = Workspace::try_create(&ns.name, "unguarded", &WorkspaceSpec::default()).expect_err(
        "with every webhook replica gone, admission must refuse rather than wave through",
    );
    assert!(err.contains("failed calling webhook"), "{err}");
}
