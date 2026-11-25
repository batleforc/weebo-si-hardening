//! The admission HTTP adapter: `AdmissionReview` in, JSON Patch out — the axum router the
//! composition root (and the envtest suite) both serve, so what the envtest tier proves is the
//! same wiring production runs.

use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::port::observer::Observer;
use weebo_si_chassis::{
    AdmitOutcome, Context, Decision, DomainError, Feature, FeatureId, Mutation, Registry, Subject,
};
use weebo_si_crd::{
    DevfileContractConfig, DwocRef, NamespaceName, ResolvedNetworkProfilesConfig,
    ResolvedTeamToolsConfig,
};
use weebo_si_devfile_contract::{
    DevfileContract, DevfileWorkspace, FEATURE_ID as DEVFILE_CONTRACT_ID,
};
use weebo_si_dwoc_pin::Workspace;
use weebo_si_network_profiles::WorkspaceAdmission;
use weebo_si_team_tools::{
    FEATURE_ID as TEAM_TOOLS_ID, TeamToolsAdmission, ToolsWorkspaceAdmission,
};

use crate::extract::{
    devfile_workspace_from_object, tools_workspace_from_object, workspace_admission_from_object,
    workspace_from_object,
};
use crate::metrics::WebhookMetrics;
use crate::render::{render_patch, with_warnings};

/// Logs one admission decision — namespace, workspace name, the current and target references,
/// and the decision — per RFC 0002's *Security considerations*: "Logs carry the namespace, the
/// workspace name, the current and target references and the decision — **never the object**,
/// because a DevWorkspace template carries the user's environment variables and can carry a
/// token." Signature is the enforcement: there is no parameter here a caller could pass the
/// admitted object's `data` through, so a future call site cannot silently start logging it.
fn log_admission(
    namespace: &NamespaceName,
    workspace: &str,
    current: Option<&DwocRef>,
    mutations: &[Mutation],
    denial: Option<&str>,
) {
    let current = current
        .map(|dwoc_ref| format!("{}/{}", dwoc_ref.namespace, dwoc_ref.name))
        .unwrap_or_else(|| "<none>".to_string());
    let target = mutations
        .iter()
        .find_map(|mutation| match mutation {
            Mutation::SetConfigRef(dwoc_ref) => {
                Some(format!("{}/{}", dwoc_ref.namespace, dwoc_ref.name))
            }
            Mutation::Annotate { .. }
            | Mutation::SetString { .. }
            | Mutation::SetInt { .. }
            | Mutation::SetBool { .. } => None,
        })
        .unwrap_or_else(|| "<unchanged>".to_string());
    match denial {
        Some(reason) => tracing::info!(
            "deny namespace={namespace} workspace={workspace} current={current} reason={reason}"
        ),
        None => tracing::info!(
            "allow namespace={namespace} workspace={workspace} current={current} target={target}"
        ),
    }
}

/// Path `MutatingWebhookConfiguration.webhooks[].clientConfig` points `dwoc-pin`'s rule at, per
/// RFC 0002's *Webhook configuration*.
pub const MUTATE_DEVWORKSPACES_PATH: &str = "/mutate/v1alpha1/devworkspaces";

/// Everything the handler needs, injected once at boot — the composition root (`main.rs`) is
/// the only place naming concrete adapters, per `docs/architecture/hexagonal.md`.
pub struct AppState {
    /// Every registered feature, in declaration order.
    pub registry: Registry<Workspace>,
    /// `network-profiles`' own admission surface, run over the same request before `registry`.
    ///
    /// A second registry rather than a second entry in the first, because the two features take
    /// *different subjects*: `dwoc-pin`'s `Workspace` and `network-profiles`'
    /// `WorkspaceAdmission`, and `Registry<S>` is generic in exactly that. Merging them would
    /// mean one subject type carrying both features' fields, which is the coupling
    /// `weebo-si-network-profiles` depending on `weebo-si-dwoc-pin` — or the reverse — would
    /// introduce. `None` when `network-profiles` is not compiled into this deployment's wiring.
    pub network_profiles: Option<NetworkProfilesAdmission>,
    /// `devfile-contract` (RFC 0019), run between the `network-profiles` gate and `dwoc-pin`. A
    /// third registry for the same reason as the second: its subject is `DevfileWorkspace`
    /// (resolved D-8). `None` when not wired.
    pub devfile_contract: Option<DevfileContractAdmission>,
    /// `team-tools`' admission gate (RFC 0020), the fourth and last registry on the route: its
    /// subject is `ToolsWorkspaceAdmission`. `None` when not wired.
    pub team_tools: Option<TeamToolsRoute>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Whether a resolved DWOC reference exists.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// Counters and decision events.
    pub observer: Arc<dyn Observer + Send + Sync>,
    /// `weebo_si_admission_duration_seconds`.
    pub metrics: WebhookMetrics,
}

/// `devfile-contract`'s registry on the DevWorkspace route, from [`devfile_contract_registry`].
pub type DevfileContractAdmission = Registry<DevfileWorkspace>;

/// `network-profiles`' half of the DevWorkspace admission path — the registry holding
/// [`weebo_si_network_profiles::WorkspaceGate`], plus the live configuration the two selection
/// keys are read from.
pub struct NetworkProfilesAdmission {
    /// The gate, registered.
    pub registry: Registry<WorkspaceAdmission>,
    /// `spec.features.networkProfiles`, hot-reloaded — read fresh per request for
    /// `workspaceSelection.attribute` and `namespaceSelection.annotation`.
    pub config: Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
}

/// `team-tools`' half of the DevWorkspace admission path, from [`team_tools_route`]: the
/// registry holding [`TeamToolsAdmission`], plus the live configuration
/// `workspaceSelection.attribute` is read from per request.
pub struct TeamToolsRoute {
    /// The gate, registered.
    pub registry: Registry<ToolsWorkspaceAdmission>,
    /// `spec.features.teamTools`, hot-reloaded.
    pub config: Arc<RwLock<Option<ResolvedTeamToolsConfig>>>,
}

/// The `team-tools` gate of [`AppState::team_tools`], over the config store's live handle — one
/// builder for the composition root and the envtest suite.
pub fn team_tools_route(config: Arc<RwLock<Option<ResolvedTeamToolsConfig>>>) -> TeamToolsRoute {
    let mut registry = Registry::new();
    registry.register(TeamToolsAdmission::new(Arc::clone(&config)));
    TeamToolsRoute { registry, config }
}

/// The webhook's router. Also built by the envtest suite, pointed at real
/// `weebo-si-runtime` adapters — proving the wiring, not just the rules.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(MUTATE_DEVWORKSPACES_PATH, post(mutate_devworkspaces))
        .with_state(state)
}

async fn mutate_devworkspaces(
    State(state): State<Arc<AppState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return Json(
                AdmissionResponse::invalid("the AdmissionReview carried no request").into_review(),
            );
        }
    };

    let response = AdmissionResponse::from(&request);
    let Some(object) = &request.object else {
        // No object to mutate (e.g. a DELETE) — allow, unchanged.
        return Json(response.into_review());
    };

    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let workspace = workspace_from_object(&namespace, object);
    let refuse = |reason: String| {
        log_admission(
            &namespace,
            &workspace.name,
            workspace.config_ref.as_ref(),
            &[],
            Some(&reason),
        );
        Json(AdmissionResponse::from(&request).deny(reason).into_review())
    };

    // The order is global on this route (RFC 0019 D-14, RFC 0020 *Admission*): `network-profiles`
    // gate → `devfile-contract` → `dwoc-pin` → `team-tools`. The first denial wins and stops the
    // loop: the gate refuses a workspace that must not start, and its message explains the more
    // fundamental problem; a denied parent is refused before a pin is computed for it. Each step
    // builds its subject only when it runs; an unwired registry is skipped.
    let steps: [Option<Step<'_>>; 4] = [
        state.network_profiles.as_ref().map(|np| {
            Box::new(|| {
                let (attribute_key, annotation_key, grant_key) = {
                    let guard = np
                        .config
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    match guard.as_ref() {
                        Some(config) => (
                            config.workspace_selection.attribute.clone(),
                            config.namespace_selection.annotation.clone(),
                            config.namespace_grant.annotation.clone(),
                        ),
                        // No `networkProfiles` block at all. `FeatureGate::mode` already
                        // reports `Off` for it, so `admit` skips the gate anyway — empty keys
                        // just avoid reading the object for keys nobody configured.
                        None => (String::new(), String::new(), String::new()),
                    }
                };
                // From the cache: admission already refuses a namespace it has not observed,
                // and an empty key (`""` disables restricted grants) reads as no grant.
                let read = |key: &str| {
                    (!key.is_empty())
                        .then(|| state.namespace_view.annotation(&namespace, key))
                        .flatten()
                };
                let subject = workspace_admission_from_object(
                    &namespace,
                    object,
                    request.operation.clone(),
                    &attribute_key,
                    read(&annotation_key),
                    read(&grant_key),
                );
                run(&state, "network-profiles", &np.registry, &subject)
            }) as Step<'_>
        }),
        state.devfile_contract.as_ref().map(|registry| {
            Box::new(|| {
                let subject = devfile_workspace_from_object(
                    &namespace,
                    object,
                    request.old_object.as_ref(),
                    &request.operation,
                );
                run(&state, DEVFILE_CONTRACT_ID, registry, &subject)
            }) as Step<'_>
        }),
        Some(Box::new(|| run(&state, "dwoc-pin", &state.registry, &workspace)) as Step<'_>),
        state.team_tools.as_ref().map(|tools| {
            Box::new(|| {
                let attribute_key = tools
                    .config
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .map(|config| config.workspace_selection.attribute.clone())
                    .unwrap_or_default();
                let subject = tools_workspace_from_object(
                    &namespace,
                    object,
                    request.old_object.as_ref(),
                    &request.operation,
                    &attribute_key,
                );
                run(&state, TEAM_TOOLS_ID, &tools.registry, &subject)
            }) as Step<'_>
        }),
    ];
    // Every registry's payload is kept, in that order: one patch, and the warnings bounded once,
    // after the merge (`with_warnings`), never per registry.
    let mut mutations = Vec::new();
    let mut warnings = Vec::new();
    for step in steps.into_iter().flatten() {
        match step() {
            Ok(AdmitOutcome::Allow {
                mutations: step_mutations,
                warnings: step_warnings,
            }) => {
                mutations.extend(step_mutations);
                warnings.extend(step_warnings);
            }
            Ok(AdmitOutcome::Deny(reason)) => return refuse(reason),
            Err(err) => return refuse(err.to_string()),
        }
    }

    log_admission(
        &namespace,
        &workspace.name,
        workspace.config_ref.as_ref(),
        &mutations,
        None,
    );
    if mutations.is_empty() {
        return Json(with_warnings(response, warnings).into_review());
    }
    // The whole object, not `data`: `DynamicObject.data` has no `metadata`, so against it every
    // annotation looked like the first and replaced the object's whole annotation map.
    let body = match serde_json::to_value(object) {
        Ok(body) => body,
        Err(err) => return refuse(format!("failed to render patch: {err}")),
    };
    let response = match response.with_patch(render_patch(&body, &mutations)) {
        Ok(response) => with_warnings(response, warnings),
        Err(err) => return refuse(format!("failed to render patch: {err}")),
    };
    Json(response.into_review())
}

/// One registry of the DevWorkspace route, its subject built and admitted only when called.
type Step<'a> = Box<dyn FnOnce() -> Result<AdmitOutcome, DomainError> + 'a>;

/// `admit` one registry over its subject, timed under `feature` in
/// `weebo_si_admission_duration_seconds`. Both admission metrics read the `resource` label off
/// the subject, so the histogram and `weebo_si_admission_requests_total` agree by construction.
fn run<S: Subject>(
    state: &AppState,
    feature: &str,
    registry: &Registry<S>,
    subject: &S,
) -> Result<AdmitOutcome, DomainError> {
    let _timer = state
        .metrics
        .timer(feature, subject.resource())
        .start_timer();
    weebo_si_chassis::admit(
        registry,
        subject,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    )
}

/// `devfile-contract` with its log line (RFC 0019, *Log line*): the decision's note carries the
/// fields, and `admit()` returns no note, so the line is written here, around the feature, in
/// every mode the feature runs in — `DryRun`'s would-be outcome is read in this line. The
/// feature still never learns its mode.
struct LoggedDevfileContract(DevfileContract);

impl Feature<DevfileWorkspace> for LoggedDevfileContract {
    fn id(&self) -> FeatureId {
        self.0.id()
    }

    fn evaluate(
        &self,
        subject: &DevfileWorkspace,
        ctx: &Context<'_>,
    ) -> Result<Decision<DevfileWorkspace>, DomainError> {
        let decision = self.0.evaluate(subject, ctx)?;
        tracing::info!("{}", devfile_contract_line(subject, &decision));
        Ok(decision)
    }
}

/// The log line of one `devfile-contract` decision: never the parent URI, never the object —
/// the note holds only the verdict, reason codes, contract number and a generator excerpt.
fn devfile_contract_line(
    subject: &DevfileWorkspace,
    decision: &Decision<DevfileWorkspace>,
) -> String {
    format!(
        "{DEVFILE_CONTRACT_ID} namespace={} workspace={} decision={} {}",
        subject.namespace,
        subject.name,
        if decision.denial.is_some() {
            "deny"
        } else {
            "allow"
        },
        decision.note.as_deref().unwrap_or_default()
    )
}

/// The `devfile-contract` registry of [`AppState::devfile_contract`], over the config store's
/// live handle — built here so the composition root and the envtest suite get the logged one.
pub fn devfile_contract_registry(
    config: Arc<RwLock<Option<DevfileContractConfig>>>,
) -> DevfileContractAdmission {
    let mut registry = Registry::new();
    registry.register(LoggedDevfileContract(DevfileContract::new(config)));
    registry
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    /// A textual regression test, not a type-level one — `log_admission`'s signature already
    /// makes "pass the object through" impossible (there is no parameter to carry it), but this
    /// catches the case a future call site reads the admitted object's field access expression
    /// for some *other* reason (a new log line, a new mutation, a debug print) without that
    /// reader realizing it now sits next to the one call this file is allowed to make. Per RFC
    /// 0002's *Security considerations*: "never the object, because a DevWorkspace template
    /// carries the user's environment variables and can carry a token."
    ///
    /// The needle is assembled at runtime, not written as a literal, so this test does not count
    /// its own source as a second occurrence.
    #[test]
    fn the_admitted_object_is_serialised_in_exactly_one_place() {
        let needle = ["serde_json::to_value(", "object)"].concat();
        let source = include_str!("router.rs");
        let occurrences = source.matches(&needle).count();
        assert_eq!(
            occurrences, 1,
            "router.rs must serialise the admitted object in exactly one place — the JSON \
             Patch render call — found {occurrences} occurrences; if this is a deliberate \
             new read, it must not be a log line (see RFC 0002's Security considerations)"
        );
    }

    use std::collections::BTreeMap;

    use kube::core::admission::AdmissionResponse;
    use weebo_si_chassis::admit::MAX_WARNINGS;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_chassis::port::feature_gate::testing::FakeFeatureGate;
    use weebo_si_chassis::port::namespace_view::testing::FakeNamespaceView;
    use weebo_si_chassis::{FeatureOutcome, NamespaceFacts};
    use weebo_si_crd::{FeatureMode, OnDenied};

    use super::*;

    struct NullObserver;
    impl Observer for NullObserver {
        fn decided(&self, _: FeatureId, _: FeatureMode, _: &FeatureOutcome) {}
    }

    /// A feature that allows with `warnings` warnings and one annotation, or denies.
    struct Canned {
        id: &'static str,
        warnings: usize,
        deny: bool,
    }
    impl<S: Subject> Feature<S> for Canned {
        fn id(&self) -> FeatureId {
            FeatureId::new(self.id)
        }
        fn evaluate(&self, _: &S, _: &Context<'_>) -> Result<Decision<S>, DomainError> {
            if self.deny {
                return Ok(Decision::deny(
                    format!("{} says no", self.id),
                    None,
                    None,
                    "denied",
                ));
            }
            let mutation = Mutation::Annotate {
                key: format!("test/{}", self.id),
                value: "x".to_string(),
            };
            let warnings = (0..self.warnings)
                .map(|i| format!("{} warning {i}", self.id))
                .collect();
            Ok(Decision::new(vec![mutation], None, None, "ok").with_warnings(warnings))
        }
    }

    fn config(denied_contracts: Vec<u32>) -> DevfileContractConfig {
        DevfileContractConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            current_contract: 3,
            minimum_contract: 2,
            minimum_schema_version: None,
            denied_contracts,
            denied_parents: Vec::new(),
            on_denied: OnDenied::Deny,
        }
    }

    fn state(
        gate_warnings: usize,
        gate_denies: bool,
        denied_contracts: Vec<u32>,
        tools_denies: bool,
    ) -> Arc<AppState> {
        let mut gate = Registry::new();
        gate.register(Canned {
            id: "network-profiles",
            warnings: gate_warnings,
            deny: gate_denies,
        });
        let mut pin = Registry::new();
        pin.register(Canned {
            id: "dwoc-pin",
            warnings: 2,
            deny: false,
        });
        let mut tools = Registry::new();
        tools.register(Canned {
            id: "team-tools",
            warnings: 1,
            deny: tools_denies,
        });
        let namespace = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        };
        Arc::new(AppState {
            registry: pin,
            network_profiles: Some(NetworkProfilesAdmission {
                registry: gate,
                config: Arc::new(RwLock::new(None)),
            }),
            devfile_contract: Some(devfile_contract_registry(Arc::new(RwLock::new(Some(
                config(denied_contracts),
            ))))),
            team_tools: Some(TeamToolsRoute {
                registry: tools,
                config: Arc::new(RwLock::new(None)),
            }),
            gate: Arc::new(FakeFeatureGate::new(FeatureMode::Enforce, Vec::new())),
            namespace_view: Arc::new(FakeNamespaceView::new([(
                NamespaceName::new("user-alice"),
                namespace,
            )])),
            dwoc_catalog: Arc::new(FakeDwocCatalog::new(std::iter::empty())),
            observer: Arc::new(NullObserver),
            metrics: WebhookMetrics::register(&prometheus::Registry::new()).unwrap(),
        })
    }

    /// A `CREATE` of a devfile with no contract and a parent on a branch: two warnings.
    fn review() -> AdmissionReview<DynamicObject> {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "00000000-0000-0000-0000-000000000000",
                "kind": {"group": "workspace.devfile.io", "version": "v1alpha2", "kind": "DevWorkspace"},
                "resource": {"group": "workspace.devfile.io", "version": "v1alpha2", "resource": "devworkspaces"},
                "name": "go-api",
                "namespace": "user-alice",
                "operation": "CREATE",
                "userInfo": {},
                "object": {
                    "apiVersion": "workspace.devfile.io/v1alpha2",
                    "kind": "DevWorkspace",
                    "metadata": {"name": "go-api", "namespace": "user-alice", "annotations": {"che.eclipse.org/devfile": "schemaVersion: 2.3.0"}},
                    "spec": {"started": true, "template": {"parent": {"uri": "https://github.com/o/r/raw/refs/heads/main/devfile.yaml"}}},
                },
            },
        }))
        .unwrap()
    }

    async fn respond(state: Arc<AppState>) -> AdmissionResponse {
        let Json(review) = mutate_devworkspaces(State(state), Json(review())).await;
        review.response.unwrap()
    }

    /// D-14: the warnings are bounded once over the merged list — per-registry bounding would
    /// let 4 + 2 + 2 + 1 through.
    #[tokio::test]
    async fn warnings_are_bounded_once_after_the_merge() {
        let response = respond(state(4, false, Vec::new(), false)).await;
        assert!(response.allowed, "{:?}", response.result);
        let warnings = response.warnings.unwrap();
        assert_eq!(warnings.len(), MAX_WARNINGS);
        assert!(
            warnings[..4]
                .iter()
                .all(|w| w.starts_with("network-profiles"))
        );
        assert!(warnings[4].contains("platform-contract"), "{warnings:?}");
        assert!(warnings[5].contains("follows branch"), "{warnings:?}");

        let patch = String::from_utf8(response.patch.unwrap()).unwrap();
        // The object carries annotations: every key is added into the map, never a new map over
        // the dashboard's.
        assert!(
            !patch.contains(r#""path":"/metadata/annotations","#),
            "{patch}"
        );
        for key in [
            "test~1network-profiles",
            "hardening.weebo.io~1devfile-contract",
            "test~1dwoc-pin",
            "test~1team-tools",
        ] {
            assert!(patch.contains(key), "{key} missing from {patch}");
        }
    }

    /// RFC 0020, *Admission*: the four registries' mutations and warnings all survive the fold,
    /// in the global order — 1 + 2 + 2 + 1 warnings fit under the bound.
    #[tokio::test]
    async fn every_registry_allow_payload_is_kept() {
        let response = respond(state(1, false, Vec::new(), false)).await;
        assert!(response.allowed, "{:?}", response.result);
        let warnings = response.warnings.unwrap();
        assert_eq!(warnings.len(), 6, "{warnings:?}");
        assert_eq!(warnings[0], "network-profiles warning 0");
        assert!(warnings[1].contains("platform-contract"), "{warnings:?}");
        assert!(warnings[2].contains("follows branch"), "{warnings:?}");
        assert_eq!(
            warnings[3..],
            [
                "dwoc-pin warning 0",
                "dwoc-pin warning 1",
                "team-tools warning 0"
            ]
        );
        let patch = String::from_utf8(response.patch.unwrap()).unwrap();
        let at = |key: &str| {
            patch
                .find(key)
                .unwrap_or_else(|| panic!("{key} missing from {patch}"))
        };
        let order = [
            at("test~1network-profiles"),
            at("hardening.weebo.io~1devfile-contract"),
            at("test~1dwoc-pin"),
            at("test~1team-tools"),
        ];
        assert!(order.is_sorted(), "registries out of order: {patch}");
    }

    /// The first refusal wins: `team-tools` runs last, so any earlier denial is the message.
    #[tokio::test]
    async fn a_team_tools_denial_comes_last_in_the_order() {
        let response = respond(state(0, false, Vec::new(), true)).await;
        assert!(!response.allowed);
        assert_eq!(response.result.message, "team-tools says no");

        let response = respond(state(0, false, vec![1], true)).await;
        assert!(
            response
                .result
                .message
                .contains("platform contract 1 is denied"),
            "{}",
            response.result.message
        );

        let response = respond(state(0, true, vec![1], true)).await;
        assert_eq!(response.result.message, "network-profiles says no");
    }

    #[tokio::test]
    async fn a_devfile_contract_denial_stops_before_dwoc_pin_and_the_gate_denial_wins() {
        let response = respond(state(0, false, vec![1], false)).await;
        assert!(!response.allowed);
        assert!(
            response
                .result
                .message
                .contains("platform contract 1 is denied")
        );

        let response = respond(state(0, true, vec![1], false)).await;
        assert!(!response.allowed);
        assert_eq!(response.result.message, "network-profiles says no");
    }

    /// R1: a refusal is traceable — the line names the workspace, the decision and the reasons.
    #[test]
    fn a_denial_is_logged_with_its_reasons() {
        let subject = DevfileWorkspace {
            name: "go-api".to_string(),
            namespace: NamespaceName::new("user-alice"),
            platform_contract: None,
            generator: None,
            parent: None,
            che_devfile: None,
            stored_verdict: None,
            stored_reasons: None,
            starting: true,
        };
        let feature = DevfileContract::new(Arc::new(RwLock::new(Some(config(vec![1])))));
        let facts = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let decision = feature
            .evaluate(&subject, &Context::new(&[], &facts, &catalog))
            .unwrap();
        let line = devfile_contract_line(&subject, &decision);
        assert!(
            line.starts_with("devfile-contract namespace=user-alice workspace=go-api decision=deny devfile=unknown reasons=contract-absent,"),
            "{line}"
        );
        assert!(
            line.contains("contract-denied") && line.contains("contract=absent"),
            "{line}"
        );
    }
}
