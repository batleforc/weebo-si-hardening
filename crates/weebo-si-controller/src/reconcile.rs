//! The `WeeboSiConfig` reconcile loop: validate, and report status — entirely derived from
//! `spec` and the feature registry, per RFC 0002's *Data and state* ("deleting it costs one
//! reconcile").
//!
//! **Known simplification**: `conditions[].lastTransitionTime` is stamped on every reconcile
//! pass rather than only when the condition's `status`/`type` actually changes from the
//! previous value — a full implementation would diff against the object's current status first.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Api, Client, ResourceExt};
use weebo_si_crd::{
    FeatureMode, FeatureState, FeatureStatus, SINGLETON_NAME, WeeboSiConfig, WeeboSiConfigStatus,
};

/// Shared reconcile context.
pub struct Ctx {
    /// The client every reconcile pass reads and writes `WeeboSiConfig` through.
    pub client: Client,
    /// Whether this replica currently holds the leader lease. `true` unconditionally when
    /// leader election is disabled (the single-replica default) — see [`crate::run`].
    pub is_leader: Arc<AtomicBool>,
}

/// Something that stopped a reconcile from completing. Never panics the loop — `kube-runtime`
/// calls [`error_policy`] and requeues.
#[derive(Debug)]
pub struct Error(pub kube::Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reconcile failed: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// One reconcile pass over one `WeeboSiConfig`.
pub async fn reconcile(config: Arc<WeeboSiConfig>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    // A non-leader observes the same watch stream (kube-runtime gives every replica one) but
    // never writes — only one replica's status patch should ever land, and "did nothing" is a
    // cheap, safe requeue rather than a wasted write that could race the real leader's.
    if !ctx.is_leader.load(Ordering::Relaxed) {
        return Ok(Action::requeue(Duration::from_secs(15)));
    }

    let api: Api<WeeboSiConfig> = Api::all(ctx.client.clone());
    let generation = config.metadata.generation.unwrap_or(0);

    if config.name_any() != SINGLETON_NAME {
        let status = degraded_status(
            generation,
            format!(
                "ignored: WeeboSiConfig must be named '{SINGLETON_NAME}', found '{}'",
                config.name_any()
            ),
        );
        patch_status(&api, &config.name_any(), status).await?;
        return Ok(Action::await_change());
    }

    let mut features = Vec::new();
    let mut violation_messages = Vec::new();

    if let Some(dwoc_pin) = &config.spec.features.dwoc_pin {
        let violations = dwoc_pin.validate(&config.spec.teams);
        let state = if violations.is_empty() {
            match dwoc_pin.mode {
                FeatureMode::Off => FeatureState::Disabled,
                FeatureMode::DryRun => FeatureState::DryRun,
                FeatureMode::Enforce => FeatureState::Active,
            }
        } else {
            FeatureState::Degraded
        };
        let message = if violations.is_empty() {
            format!(
                "{} catalogue entries, {} grants",
                dwoc_pin.catalog.entries().len(),
                dwoc_pin.grants.len()
            )
        } else {
            violations
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        };
        violation_messages.extend(violations.iter().map(|v| v.to_string()));
        features.push(FeatureStatus {
            name: "dwoc-pin".to_string(),
            state,
            message,
            observed_generation: generation,
        });
    }

    // RFC 0007's *Implementation plan*, "the `Degraded` conditions." Its `validate()` is the one
    // in this project that can catch a mistake with a supply-chain blast radius — a catalogue
    // whose two entries collide on one copy name means one template's contents silently
    // overwrite another's in every granted namespace — so a bad configuration is reported on the
    // object rather than discovered from a metric.
    if let Some(registry_config) = &config.spec.features.registry_config {
        let violations = registry_config.validate(&config.spec.teams);
        let state = if violations.is_empty() {
            match registry_config.mode {
                FeatureMode::Off => FeatureState::Disabled,
                FeatureMode::DryRun => FeatureState::DryRun,
                FeatureMode::Enforce => FeatureState::Active,
            }
        } else {
            FeatureState::Degraded
        };
        let message = if violations.is_empty() {
            format!(
                "{} catalogue entries, {} grants",
                registry_config.catalog.entries().len(),
                registry_config.grants.len()
            )
        } else {
            violations
                .iter()
                .map(|violation| violation.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        };
        violation_messages.extend(violations.iter().map(|violation| violation.to_string()));
        features.push(FeatureStatus {
            name: "registry-config".to_string(),
            state,
            message,
            observed_generation: generation,
        });
    }

    let ready = violation_messages.is_empty();
    let now =
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(k8s_openapi::jiff::Timestamp::now());
    let condition = Condition {
        type_: if ready { "Ready" } else { "Degraded" }.to_string(),
        status: "True".to_string(),
        reason: if ready {
            "AsExpected"
        } else {
            "InvalidConfiguration"
        }
        .to_string(),
        message: if ready {
            "configuration valid".to_string()
        } else {
            violation_messages.join("; ")
        },
        observed_generation: Some(generation),
        last_transition_time: now,
    };

    let status = WeeboSiConfigStatus {
        observed_generation: generation,
        features,
        conditions: vec![condition],
    };

    patch_status(&api, &config.name_any(), status).await?;
    Ok(Action::requeue(Duration::from_secs(300)))
}

fn degraded_status(generation: i64, message: String) -> WeeboSiConfigStatus {
    let now =
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(k8s_openapi::jiff::Timestamp::now());
    WeeboSiConfigStatus {
        observed_generation: generation,
        features: Vec::new(),
        conditions: vec![Condition {
            type_: "Degraded".to_string(),
            status: "True".to_string(),
            reason: "WrongName".to_string(),
            message,
            observed_generation: Some(generation),
            last_transition_time: now,
        }],
    }
}

async fn patch_status(
    api: &Api<WeeboSiConfig>,
    name: &str,
    status: WeeboSiConfigStatus,
) -> Result<(), Error> {
    let patch = serde_json::json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply("weebo-si-controller"),
        &Patch::Merge(patch),
    )
    .await
    .map_err(Error)?;
    Ok(())
}

/// `kube-runtime`'s `Controller` calls this when [`reconcile`] returns an error — logs and
/// requeues rather than propagating a panic into the reconcile loop.
pub fn error_policy(_config: Arc<WeeboSiConfig>, error: &Error, _ctx: Arc<Ctx>) -> Action {
    eprintln!("ERROR weebo-si-controller: {error}");
    Action::requeue(Duration::from_secs(30))
}
