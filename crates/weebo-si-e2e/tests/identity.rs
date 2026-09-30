//! The identity suite — RFC 0011's provisioning half, end to end: a `WeeboSiUser` becomes a real
//! account in a real Authentik (through the weebo-authentik operator) and a workspace Application
//! a real Argo CD syncs from the team's template, and deleting the person takes both away.
//!
//! envtest already proves the operator writes the right `AuthentikUser` and `Application`; what
//! only this tier can prove is that the objects it writes are objects the two upstream operators
//! actually accept and act on.

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
    Cleanup, RECONCILE, Value, WORKSPACE_IMAGE, apply, delete, get, json, kubectl, must,
    set_features, stays, team, text, wait_until,
};

const CHARTS: &str = "http://charts.charts.svc:8080";
const SYNC: Duration = Duration::from_secs(600);

fn identity(mode: &str) -> Value {
    json!({
        "mode": mode,
        "authentik": { "allowedGroupRefs": ["e2e-platform", "e2e-oncall"] },
        "che": {
            "applicationNamespace": "argocd",
            "allowedProjects": ["weebo-dev"],
            "allowedRepoUrls": [CHARTS],
        },
    })
}

fn groups() -> [Cleanup; 2] {
    ["e2e-platform", "e2e-oncall"].map(|name| {
        apply(
            &json!({
                "apiVersion": "authentik.weebo.io/v1alpha1",
                "kind": "AuthentikGroup",
                "metadata": { "name": name },
                "spec": { "name": name },
            })
            .to_string(),
        );
        Cleanup::new(&["authentikgroup", name])
    })
}

fn platform_team() -> Cleanup {
    team(
        "e2e-platform",
        json!({
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "platform" } },
            "identity": { "authentik": { "groupRefs": ["e2e-platform"] } },
            "workspace": { "che": {
                "mode": "Ensure",
                "project": "weebo-dev",
                "source": {
                    "repoUrl": CHARTS,
                    "chart": "che-user",
                    "targetRevision": "1.0.0",
                    "values": { "username": "{USERNAME}", "email": "{EMAIL}", "team": "{TEAM_NAME}" },
                },
                "destination": { "server": "https://kubernetes.default.svc", "namespace": "{USERNAME}-che" },
                "syncPolicy": { "automated": { "prune": true, "selfHeal": true }, "options": ["CreateNamespace=true"] },
            } },
        }),
    )
}

fn user(name: &str, spec: Value) -> Cleanup {
    apply(
        &json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiUser",
            "metadata": { "name": name },
            "spec": spec,
        })
        .to_string(),
    );
    Cleanup::new(&["weebosiuser", name])
}

fn condition(object: &Value, kind: &str) -> Option<Value> {
    object
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|conditions| {
            conditions
                .iter()
                .find(|c| text(c, "/type") == kind)
                .cloned()
        })
}

/// Ask the real Authentik about a username, with the bootstrap token, from inside the cluster —
/// the workspace image carries curl and is already loaded on the node.
fn authentik_user(username: &str) -> Value {
    let out = must(&[
        "run",
        "-n",
        "authentik",
        &format!("ask-{}", std::process::id()),
        "--rm",
        "-i",
        "--quiet",
        "--restart=Never",
        &format!("--image={WORKSPACE_IMAGE}"),
        "--image-pull-policy=Never",
        "--command",
        "--",
        "curl",
        "-s",
        "-H",
        "Authorization: Bearer e2e-bootstrap-token-not-a-real-secret",
        &format!(
            "http://authentik-server.authentik.svc:9000/api/v3/core/users/?username={username}&include_groups=true"
        ),
    ]);
    serde_json::from_str(&out).unwrap_or_else(|err| panic!("authentik answered {out:?}: {err}"))
}

#[test]
fn a_person_becomes_a_real_authentik_account_in_their_teams_groups_and_leaves_with_their_object() {
    let _groups = groups();
    let _team = platform_team();
    set_features(json!({ "identity": identity("Enforce") }));
    let person = user(
        "dave",
        json!({
            "username": "dave", "displayName": "Dave E2E", "email": "dave@weebo.si",
            "team": "e2e-platform",
            "authentik": { "mode": "Ensure", "groupRefs": ["e2e-oncall"] },
        }),
    );

    let account = wait_until(
        "AuthentikUser dave to be synced into Authentik",
        SYNC,
        || {
            let account = get(&["authentikuser", "dave"]).ok_or("absent")?;
            let ready = condition(&account, "Ready").map(|c| text(&c, "/status"));
            if ready.as_deref() == Some("True") && !text(&account, "/status/authentikId").is_empty()
            {
                Ok(account)
            } else {
                Err(format!(
                    "status {}",
                    account.pointer("/status").cloned().unwrap_or_default()
                ))
            }
        },
    );
    assert_eq!(text(&account, "/spec/username"), "dave");
    assert_eq!(text(&account, "/spec/name"), "Dave E2E");
    assert_eq!(
        account.pointer("/spec/groupRefs"),
        Some(&json!(["e2e-oncall", "e2e-platform"])),
        "team groups and personal groups, merged and sorted"
    );
    assert_eq!(
        text(&account, "/metadata/ownerReferences/0/kind"),
        "WeeboSiUser"
    );

    let found = authentik_user("dave");
    assert_eq!(
        found.pointer("/pagination/count"),
        Some(&json!(1)),
        "{found}"
    );
    let groups: Vec<String> = found
        .pointer("/results/0/groups_obj")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|group| text(group, "/name"))
        .collect();
    assert!(
        groups.contains(&"e2e-platform".to_string()) && groups.contains(&"e2e-oncall".to_string()),
        "{groups:?}"
    );

    let object = get(&["weebosiuser", "dave"]).unwrap();
    assert_eq!(text(&object, "/status/authentik/state"), "Created");

    drop(person);
    wait_until(
        "the AuthentikUser to be garbage-collected",
        RECONCILE,
        || match get(&["authentikuser", "dave"]) {
            None => Ok(()),
            Some(_) => Err("still there".into()),
        },
    );
    wait_until("the account to leave Authentik", SYNC, || {
        let found = authentik_user("dave");
        if found.pointer("/pagination/count") == Some(&json!(0)) {
            Ok(())
        } else {
            Err(found.to_string())
        }
    });
}

#[test]
fn a_persons_workspace_application_is_synced_by_argo_cd_with_their_own_values() {
    let _team = platform_team();
    set_features(json!({ "identity": identity("Enforce") }));
    let _person = user(
        "erin",
        json!({
            "username": "erin", "email": "erin@weebo.si", "team": "e2e-platform",
            "che": { "mode": "Ensure", "values": { "storage": { "size": "5Gi" } } },
        }),
    );

    let application = wait_until(
        "Argo CD to sync and report erin's Application healthy",
        SYNC,
        || {
            let application = get(&["application", "-n", "argocd", "erin"]).ok_or("absent")?;
            let sync = text(&application, "/status/sync/status");
            let health = text(&application, "/status/health/status");
            if sync == "Synced" && health == "Healthy" {
                Ok(application)
            } else {
                Err(format!("{sync}/{health}"))
            }
        },
    );
    assert_eq!(text(&application, "/spec/project"), "weebo-dev");
    assert_eq!(
        text(&application, "/spec/destination/namespace"),
        "erin-che"
    );
    assert_eq!(
        text(&application, "/metadata/ownerReferences/0/kind"),
        "WeeboSiUser"
    );

    let rendered =
        get(&["configmap", "-n", "erin-che", "che-user"]).expect("Argo CD deployed the chart");
    assert_eq!(text(&rendered, "/data/username"), "erin");
    assert_eq!(text(&rendered, "/data/email"), "erin@weebo.si");
    assert_eq!(text(&rendered, "/data/team"), "e2e-platform");
    assert_eq!(
        text(&rendered, "/data/storageSize"),
        "5Gi",
        "the person's values override the team's"
    );

    let object = get(&["weebosiuser", "erin"]).unwrap();
    assert_eq!(text(&object, "/status/che/state"), "Created");
    delete(&["namespace", "erin-che"]);
}

#[test]
fn an_account_somebody_else_made_is_adopted_and_never_written() {
    let _groups = groups();
    set_features(json!({ "identity": identity("Enforce") }));
    apply(
        &json!({
            "apiVersion": "authentik.weebo.io/v1alpha1",
            "kind": "AuthentikUser",
            "metadata": { "name": "frank" },
            "spec": { "username": "frank", "name": "Frank By Hand", "email": "frank@weebo.si", "groupRefs": [] },
        })
        .to_string(),
    );
    let _by_hand = Cleanup::new(&["authentikuser", "frank"]);
    let _person = user(
        "frank",
        json!({ "username": "frank", "displayName": "Frank Declared", "email": "frank@weebo.si",
                "authentik": { "mode": "Ensure", "groupRefs": ["e2e-oncall"] } }),
    );

    wait_until("frank to be reported Adopted", RECONCILE, || {
        let object = get(&["weebosiuser", "frank"]).ok_or("absent")?;
        let state = text(&object, "/status/authentik/state");
        if state == "Adopted" {
            Ok(())
        } else {
            Err(state)
        }
    });
    stays(
        "the hand-made account to stay untouched",
        Duration::from_secs(30),
        || {
            let account = get(&["authentikuser", "frank"]).ok_or("gone")?;
            if text(&account, "/spec/name") != "Frank By Hand" {
                return Err(format!("rewritten: {account}"));
            }
            if account.pointer("/metadata/ownerReferences").is_some() {
                return Err("an owner reference was added".into());
            }
            Ok(())
        },
    );
}

#[test]
fn a_group_outside_the_allow_list_refuses_the_whole_person_and_writes_nothing() {
    set_features(json!({ "identity": identity("Enforce") }));
    let _person = user(
        "grace",
        json!({ "username": "grace", "email": "grace@weebo.si",
                "authentik": { "mode": "Ensure", "groupRefs": ["cluster-admins"] } }),
    );
    wait_until("grace to be Degraded naming the group", RECONCILE, || {
        let object = get(&["weebosiuser", "grace"]).ok_or("absent")?;
        match condition(&object, "Degraded") {
            Some(c)
                if text(&c, "/status") == "True"
                    && text(&c, "/message").contains("cluster-admins") =>
            {
                Ok(())
            }
            other => Err(format!("{other:?}")),
        }
    });
    assert!(
        get(&["authentikuser", "grace"]).is_none(),
        "a refused person must create nothing"
    );
}

#[test]
fn dry_run_says_what_it_would_create_and_creates_nothing() {
    let _team = platform_team();
    set_features(json!({ "identity": identity("DryRun") }));
    let _person = user(
        "heidi",
        json!({ "username": "heidi", "email": "heidi@weebo.si", "team": "e2e-platform",
                "authentik": { "mode": "Ensure" }, "che": { "mode": "Ensure" } }),
    );
    wait_until("heidi's status to say what would happen", RECONCILE, || {
        let object = get(&["weebosiuser", "heidi"]).ok_or("absent")?;
        let message = text(&object, "/status/authentik/message");
        if message.starts_with("would create") {
            Ok(())
        } else {
            Err(message)
        }
    });
    stays(
        "nothing to be created in DryRun",
        Duration::from_secs(20),
        || {
            if get(&["authentikuser", "heidi"]).is_some() {
                return Err("an AuthentikUser appeared".into());
            }
            if get(&["application", "-n", "argocd", "heidi"]).is_some() {
                return Err("an Application appeared".into());
            }
            Ok(())
        },
    );
}

#[test]
fn a_second_person_claiming_a_taken_account_is_in_conflict() {
    set_features(json!({ "identity": identity("Enforce") }));
    let _one = user(
        "ivan-one",
        json!({ "username": "ivan", "email": "ivan@weebo.si", "authentik": { "mode": "Ensure", "name": "ivan" } }),
    );
    let _two = user(
        "ivan-two",
        json!({ "username": "ivan", "email": "ivan@weebo.si", "authentik": { "mode": "Ensure", "name": "ivan" } }),
    );
    // The target is the AuthentikUser *object*, named after the WeeboSiUser unless
    // `authentik.name` says otherwise — so both name it, or there are two targets and no claim to
    // contest. Whichever is reconciled first creates it and keeps it; the other finds it owned by
    // a different WeeboSiUser and is refused (docs/weebosiuser.md: nobody's object is taken
    // over). Which of the two wins is the reconcile order's to decide, so the test does not.
    let states = wait_until("one owner and one conflict", RECONCILE, || {
        let states = ["ivan-one", "ivan-two"].map(|name| {
            get(&["weebosiuser", name])
                .map(|object| text(&object, "/status/authentik/state"))
                .unwrap_or_default()
        });
        let mut sorted = states.clone();
        sorted.sort();
        if sorted == ["Conflict", "Created"] {
            Ok(states)
        } else {
            Err(format!("{states:?}"))
        }
    });
    let loser = if states[0] == "Conflict" {
        "ivan-one"
    } else {
        "ivan-two"
    };
    let object = get(&["weebosiuser", loser]).unwrap();
    assert_eq!(
        condition(&object, "Degraded").map(|c| text(&c, "/status")),
        Some("True".to_string()),
        "the person in conflict must be Degraded: {object}"
    );
    let _ = kubectl(&["get", "weebosiusers"]);
}
