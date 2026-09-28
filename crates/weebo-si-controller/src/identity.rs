//! The `WeeboSiTeam` and `WeeboSiUser` reconcile loops — RFC 0011's *Architecture*, the two loops
//! the feature's own crate cannot run because they need a cluster.
//!
//! Two controllers, one module, because they share everything that matters: the same lease, the
//! same `spec.features.identity`, the same view of the team objects. What they do not share is
//! their job — the team loop **reports** (it writes no object but its own `status`), and the user
//! loop **provisions** (it writes an `AuthentikUser` and an `Application`, and nothing else).
//!
//! Neither loop is on an admission path. The worst outcome of this module being down is that
//! provisioning stops and two `status` blocks go stale; no workload is blocked, nothing is
//! denied, and the entitlement half of RFC 0011 — the catalogues and grants the webhook resolves
//! — keeps working without either loop ever having run.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use serde_json::json;
use weebo_si_crd::{
    FeatureMode, IdentityConfig, SINGLETON_NAME, TargetState, TargetStatus, WeeboSiConfig,
    WeeboSiTeam, WeeboSiTeamStatus, WeeboSiUser, WeeboSiUserStatus,
};
use weebo_si_identity::application::{ObservedNamespace, report_team};
use weebo_si_identity::port::{DesiredObject, ObjectOwner, ProvisionObserver, Provisioner};
use weebo_si_identity::reconcile_target;

/// How often each loop re-examines an object it already agreed with. Long, like every other sweep
/// here: the interesting changes arrive as watch events, and this is the backstop for the ones
/// that do not — a `WeeboSiConfig` edit, a namespace relabelled, a restart.
const REQUEUE: Duration = Duration::from_secs(300);

/// The field manager both loops patch `status` as.
const FIELD_MANAGER: &str = "weebo-si-operator";

/// The `apiVersion` of the `ownerReference` every provisioned object carries.
const OWNER_API_VERSION: &str = "hardening.weebo.io/v1alpha1";

/// Everything the two loops need, built by the composition root — the concrete adapters live in
/// `weebo-si-runtime` and are injected as ports, so this crate never names one.
pub struct IdentityDeps {
    /// `spec.features.identity`, hot-reloaded. `None` — the feature absent from the singleton —
    /// is the off switch: both loops still report, neither writes anything anywhere.
    pub config: Arc<RwLock<Option<IdentityConfig>>>,
    /// The `AuthentikUser` handle.
    pub authentik: Arc<dyn Provisioner>,
    /// The Argo CD `Application` handle.
    pub workspace: Arc<dyn Provisioner>,
    /// Where every pass reports what it did.
    pub observer: Arc<dyn ProvisionObserver>,
}

/// Shared reconcile context. Public, like [`crate::reconcile::Ctx`], so the envtest tier can
/// drive one pass directly instead of racing a watch loop.
pub struct Ctx {
    /// The client both loops read and patch through.
    pub client: Client,
    /// The ports and the configuration handle.
    pub deps: IdentityDeps,
    /// Whether this replica currently holds the leader lease.
    pub is_leader: Arc<AtomicBool>,
}

/// Something that stopped a pass from completing. Never panics the loop — `kube-runtime` calls
/// the error policy and requeues.
#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "identity reconcile failed: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Start both loops. Returns once the watches are established; the loops run until the process
/// stops.
pub async fn spawn(client: Client, deps: IdentityDeps, is_leader: Arc<AtomicBool>) {
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        deps,
        is_leader,
    });

    let teams: Api<WeeboSiTeam> = Api::all(client.clone());
    let team_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        Controller::new(teams, WatcherConfig::default())
            .shutdown_on_signal()
            .run(reconcile_team, error_policy, team_ctx)
            .for_each(|_| futures_util::future::ready(()))
            .await;
    });

    let users: Api<WeeboSiUser> = Api::all(client);
    tokio::spawn(async move {
        Controller::new(users, WatcherConfig::default())
            .shutdown_on_signal()
            .run(reconcile_user, error_policy, ctx)
            .for_each(|_| futures_util::future::ready(()))
            .await;
    });
}

fn error_policy<K>(_object: Arc<K>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    eprintln!("ERROR weebo-si-controller: {err}");
    Action::requeue(Duration::from_secs(30))
}

/// One pass over one team: count what it owns, collect what is wrong with it, write `status`.
///
/// It writes **nothing else**. A team object is a declaration, and the only thing this operator
/// knows that the author does not is how the declaration turned out.
pub async fn reconcile_team(team: Arc<WeeboSiTeam>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if !ctx.is_leader.load(Ordering::Relaxed) {
        return Ok(Action::requeue(Duration::from_secs(15)));
    }

    let generation = team.metadata.generation.unwrap_or(0);
    let teams = list_teams(&ctx.client).await?;
    let users = list_users(&ctx.client).await?;
    let namespaces = list_namespaces(&ctx.client).await?;

    // The singleton, resolved against every team: its conflicts are where a team learns it
    // redefined somebody else's catalogue key. Read here rather than from the hot handle because
    // this loop needs the whole `spec`, not only `features.identity`.
    let (conflicts, identity) = match singleton(&ctx.client).await? {
        Some(config) => {
            let mut spec = config.spec.clone();
            let conflicts = spec.resolve_teams(&teams);
            (conflicts, spec.features.identity.clone())
        }
        None => (Vec::new(), None),
    };

    let report = report_team(
        &team,
        &teams,
        &users,
        &namespaces,
        &conflicts,
        identity.as_ref(),
    );
    ctx.deps
        .observer
        .team_reconciled(!report.violations.is_empty());

    let status = WeeboSiTeamStatus {
        observed_generation: generation,
        namespaces: report.namespaces,
        members: report.members,
        conditions: vec![condition(
            report.violations.is_empty(),
            generation,
            if report.violations.is_empty() {
                format!(
                    "{} namespace(s), {} member(s)",
                    report.namespaces, report.members
                )
            } else {
                report.violations.join("; ")
            },
        )],
    };

    let api: Api<WeeboSiTeam> = Api::all(ctx.client.clone());
    patch_team_status(&api, &team.name_any(), &status).await?;
    Ok(Action::requeue(REQUEUE))
}

/// One pass over one person: plan, provision what the mode allows, write `status`.
pub async fn reconcile_user(user: Arc<WeeboSiUser>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if !ctx.is_leader.load(Ordering::Relaxed) {
        return Ok(Action::requeue(Duration::from_secs(15)));
    }

    let generation = user.metadata.generation.unwrap_or(0);
    let api: Api<WeeboSiUser> = Api::all(ctx.client.clone());
    let team_name = user.spec.team.as_ref().map(ToString::to_string);

    let Some(config) = read_config(&ctx.deps.config) else {
        // The feature is absent from the singleton. Not an error and not a degradation: nobody
        // asked this operator to create anything, so it reports that and stops.
        let status = WeeboSiUserStatus {
            observed_generation: generation,
            team: team_name,
            authentik: None,
            che: None,
            conditions: vec![condition(
                true,
                generation,
                "spec.features.identity is not configured: nothing is provisioned".to_string(),
            )],
        };
        patch_user_status(&api, &user.name_any(), &status).await?;
        return Ok(Action::requeue(REQUEUE));
    };

    if config.mode == FeatureMode::Off {
        let status = WeeboSiUserStatus {
            observed_generation: generation,
            team: team_name,
            authentik: None,
            che: None,
            conditions: vec![condition(
                true,
                generation,
                "spec.features.identity is Off: nothing is provisioned".to_string(),
            )],
        };
        patch_user_status(&api, &user.name_any(), &status).await?;
        return Ok(Action::requeue(REQUEUE));
    }

    let teams = list_teams(&ctx.client).await?;
    let team = user
        .spec
        .team
        .as_ref()
        .and_then(|name| teams.iter().find(|team| &team.team_name() == name));

    let plan = match config.plan_for(&user, team) {
        Ok(plan) => plan,
        Err(violations) => {
            let status = WeeboSiUserStatus {
                observed_generation: generation,
                team: team_name,
                authentik: None,
                che: None,
                conditions: vec![condition(
                    false,
                    generation,
                    violations
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; "),
                )],
            };
            patch_user_status(&api, &user.name_any(), &status).await?;
            return Ok(Action::requeue(REQUEUE));
        }
    };

    // Ownership is by uid, so an object with none cannot be provisioned for: without it, a
    // person deleted and recreated under the same name would inherit the first one's objects,
    // and nothing this loop created could ever be garbage-collected.
    let Some(uid) = user.metadata.uid.clone() else {
        let status = WeeboSiUserStatus {
            observed_generation: generation,
            team: team_name,
            authentik: None,
            che: None,
            conditions: vec![condition(
                false,
                generation,
                "this object has no metadata.uid, so nothing can be owned by it".to_string(),
            )],
        };
        patch_user_status(&api, &user.name_any(), &status).await?;
        return Ok(Action::requeue(REQUEUE));
    };

    let owner = ObjectOwner {
        api_version: OWNER_API_VERSION.to_string(),
        kind: "WeeboSiUser".to_string(),
        name: user.name_any(),
        uid: uid.clone(),
    };
    let enforce = config.mode == FeatureMode::Enforce;
    let mut failures = Vec::new();

    let authentik = match plan.authentik.as_ref() {
        Some(authentik) => {
            let desired = DesiredObject {
                name: authentik.name.clone(),
                namespace: None,
                labels: BTreeMap::new(),
                spec: authentik.spec(),
                owner: owner.clone(),
            };
            provision(
                ctx.deps.authentik.as_ref(),
                &desired,
                &uid,
                enforce,
                ctx.deps.observer.as_ref(),
                &mut failures,
            )
            .await
        }
        None => None,
    };

    let che = match plan.application.as_ref() {
        Some(application) => {
            let desired = DesiredObject {
                name: application.name.clone(),
                namespace: Some(application.namespace.clone()),
                labels: BTreeMap::new(),
                spec: application.spec(),
                owner,
            };
            provision(
                ctx.deps.workspace.as_ref(),
                &desired,
                &uid,
                enforce,
                ctx.deps.observer.as_ref(),
                &mut failures,
            )
            .await
        }
        None => None,
    };

    // `Adopted` is a success: the object exists and this person can use it. `Conflict` and
    // `Absent` are not — one is two people claiming one target, the other a missing dependency,
    // and both are things somebody has to fix.
    let unhealthy: Vec<String> = [authentik.as_ref(), che.as_ref()]
        .into_iter()
        .flatten()
        .filter(|status| matches!(status.state, TargetState::Conflict | TargetState::Absent))
        .map(|status| status.message.clone())
        .collect();

    let mut problems = failures;
    problems.extend(unhealthy);

    let status = WeeboSiUserStatus {
        observed_generation: generation,
        team: team_name,
        authentik,
        che,
        conditions: vec![condition(
            problems.is_empty(),
            generation,
            if problems.is_empty() {
                match config.mode {
                    FeatureMode::DryRun => "dry run: nothing written".to_string(),
                    _ => "provisioned".to_string(),
                }
            } else {
                problems.join("; ")
            },
        )],
    };
    patch_user_status(&api, &user.name_any(), &status).await?;
    Ok(Action::requeue(REQUEUE))
}

/// Run one target through the port, turning a port failure into a reported problem rather than a
/// failed pass: the other half of this person's provisioning still has to happen, and a retry of
/// the whole object is what the requeue is for.
async fn provision(
    provisioner: &dyn Provisioner,
    desired: &DesiredObject,
    uid: &str,
    enforce: bool,
    observer: &dyn ProvisionObserver,
    failures: &mut Vec<String>,
) -> Option<TargetStatus> {
    match reconcile_target(provisioner, desired, uid, enforce, observer).await {
        Ok(status) => Some(status),
        Err(err) => {
            failures.push(err.to_string());
            None
        }
    }
}

fn read_config(config: &Arc<RwLock<Option<IdentityConfig>>>) -> Option<IdentityConfig> {
    config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

async fn singleton(client: &Client) -> Result<Option<WeeboSiConfig>, Error> {
    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    api.get_opt(SINGLETON_NAME)
        .await
        .map_err(|err| Error(format!("reading the WeeboSiConfig: {err}")))
}

async fn list_teams(client: &Client) -> Result<Vec<WeeboSiTeam>, Error> {
    let api: Api<WeeboSiTeam> = Api::all(client.clone());
    api.list(&ListParams::default())
        .await
        .map(|list| list.items)
        .map_err(|err| Error(format!("listing WeeboSiTeam objects: {err}")))
}

async fn list_users(client: &Client) -> Result<Vec<WeeboSiUser>, Error> {
    let api: Api<WeeboSiUser> = Api::all(client.clone());
    api.list(&ListParams::default())
        .await
        .map(|list| list.items)
        .map_err(|err| Error(format!("listing WeeboSiUser objects: {err}")))
}

/// Every namespace's name and labels.
///
/// Listed rather than watched, and that is a deliberate difference from the webhook's own
/// namespace cache: this loop runs once per team per change and every five minutes, where the
/// webhook answers per admission. A second reflector over every namespace in the cluster would
/// cost more memory than the list costs time.
async fn list_namespaces(client: &Client) -> Result<Vec<ObservedNamespace>, Error> {
    let api: Api<Namespace> = Api::all(client.clone());
    api.list(&ListParams::default())
        .await
        .map(|list| {
            list.items
                .into_iter()
                .map(|namespace| ObservedNamespace {
                    name: namespace.name_any(),
                    labels: namespace.metadata.labels.unwrap_or_default(),
                })
                .collect()
        })
        .map_err(|err| Error(format!("listing namespaces: {err}")))
}

/// The one condition each object carries, `Ready` or `Degraded`.
///
/// Same known simplification as [`crate::reconcile`]: `lastTransitionTime` is stamped on every
/// pass rather than only when the condition actually changes.
fn condition(ready: bool, generation: i64, message: String) -> Condition {
    Condition {
        type_: if ready { "Ready" } else { "Degraded" }.to_string(),
        status: "True".to_string(),
        reason: if ready {
            "AsExpected"
        } else {
            "NotProvisioned"
        }
        .to_string(),
        message,
        observed_generation: Some(generation),
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::now()),
    }
}

/// Two concrete writers rather than one generic one: `patch_status` needs `DeserializeOwned`,
/// and taking a `serde` dependency into this crate to spell that bound once is a worse trade than
/// two four-line functions.
async fn patch_team_status(
    api: &Api<WeeboSiTeam>,
    name: &str,
    status: &WeeboSiTeamStatus,
) -> Result<(), Error> {
    api.patch_status(
        name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&json!({ "status": status })),
    )
    .await
    .map(|_| ())
    .map_err(|err| Error(format!("patching the status of team {name}: {err}")))
}

async fn patch_user_status(
    api: &Api<WeeboSiUser>,
    name: &str,
    status: &WeeboSiUserStatus,
) -> Result<(), Error> {
    api.patch_status(
        name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&json!({ "status": status })),
    )
    .await
    .map(|_| ())
    .map_err(|err| Error(format!("patching the status of user {name}: {err}")))
}
