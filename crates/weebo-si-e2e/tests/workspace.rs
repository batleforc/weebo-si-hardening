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
    Cleanup, Namespace, OPERATOR_NAMESPACE, RECONCILE, Workspace, WorkspaceSpec, apply, delete,
    feature_status, get, json, kubectl, metric_sum, must, set_features, stays, team, text,
    try_apply, wait_until,
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
        err.contains("names a catalogue key outside this namespace's grant: other"),
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
    set_features(json!({ "registryConfig": registry_config() }));
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
            let _ = kubectl(&[
                "rollout",
                "status",
                "-n",
                OPERATOR_NAMESPACE,
                &self.0,
                "--timeout=300s",
            ]);
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
