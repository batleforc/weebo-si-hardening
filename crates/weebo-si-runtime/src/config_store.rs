//! Watch-backed `WeeboSiConfig` cache, implementing `FeatureGate`, and driving three of the six
//! metrics in RFC 0002's *Observability contract* that only a live config sync can compute:
//! `weebo_si_feature_mode`, `weebo_si_dwoc_pin_catalog_entries` and
//! `weebo_si_config_observed_generation`.
//!
//! Per RFC 0004: also the hot-reload source for `networkProfiles`/`policyGuard` and the resolved
//! enforcement `Backend`, mirroring the `dwoc_pin` handle exactly — and, for the same
//! "only a live config sync can compute this" reason, the two configuration-shaped metrics from
//! that RFC's own contract: `weebo_si_network_backend` and `weebo_si_network_profile_unsupported`.
//! The other five live in [`crate::network_metrics`], driven by the reconcile loop.

use std::sync::{Arc, RwLock};

use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};
use prometheus::{IntGauge, IntGaugeVec, Opts, Registry};
use weebo_si_crd::{
    Backend, FeatureMode, IdentityConfig, NamespaceName, PolicyGuardConfig, ResolvedDwocPinConfig,
    ResolvedEndpointAuthConfig, ResolvedFeatures, ResolvedImagePolicyConfig,
    ResolvedKubeArmorPolicyConfig, ResolvedNetworkProfilesConfig, ResolvedRegistryConfig,
    RuntimeBackend, SINGLETON_NAME, Team, WeeboSiConfig, WeeboSiTeam, team_views,
};

use weebo_si_chassis::FeatureId;
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog as _;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView as _;
use weebo_si_kubearmor_policy::{
    Capabilities as RuntimeCapabilities, resolve_backend as resolve_runtime_backend,
};
use weebo_si_network_profiles::Capabilities;
use weebo_si_network_profiles::resolve_backend;

use crate::dwoc_store::KubeDwocStore;
use crate::network_metrics::backend_label;
use crate::ns_store::KubeNsStore;

/// The default `namespaceSelection.annotation`, used until (and unless) a config overrides it.
pub const DEFAULT_ANNOTATION: &str = "hardening.weebo.io/dwoc";

fn mode_value(mode: FeatureMode) -> i64 {
    match mode {
        FeatureMode::Off => 0,
        FeatureMode::DryRun => 1,
        FeatureMode::Enforce => 2,
    }
}

/// Watch-backed `WeeboSiConfig` cache. Also drives shared config handles so every feature crate
/// sees a hot-reloaded configuration without a restart: `weebo-si-dwoc-pin`'s `DwocPin`,
/// `weebo-si-network-profiles`'s `NetworkProfiles`/`PolicyGuard`, and `weebo-si-runtime`'s own
/// [`KubeNsStore`] (via the shared `namespaceSelection.annotation` handle).
pub struct KubeConfigStore {
    teams: Arc<RwLock<Vec<Team>>>,
    dwoc_pin: Arc<RwLock<Option<ResolvedDwocPinConfig>>>,
    network_profiles: Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
    policy_guard: Arc<RwLock<Option<PolicyGuardConfig>>>,
    image_policy: Arc<RwLock<Option<ResolvedImagePolicyConfig>>>,
    kubearmor_policy: Arc<RwLock<Option<ResolvedKubeArmorPolicyConfig>>>,
    registry_config: Arc<RwLock<Option<ResolvedRegistryConfig>>>,
    endpoint_auth: Arc<RwLock<Option<ResolvedEndpointAuthConfig>>>,
    identity: Arc<RwLock<Option<IdentityConfig>>>,
    resolved_backend: Arc<RwLock<Backend>>,
    /// The engine `kubearmor-policy` resolved. A second handle rather than a variant of
    /// `resolved_backend`: the two features resolve different enums against different
    /// capabilities, and one field holding "whichever backend was resolved last" is how a
    /// `KubeArmorPolicy` ends up written for a CNI.
    resolved_runtime_backend: Arc<RwLock<RuntimeBackend>>,
    namespace_view: Arc<KubeNsStore>,
}

impl KubeConfigStore {
    /// Start watching `WeeboSiConfig`. Blocks until the initial list completes, so a caller can
    /// treat a successful return as "safe to serve admission traffic" (the `/readyz` contract).
    ///
    /// `namespace_view` is used both to serve `FeatureGate::mode`'s per-feature
    /// `namespaceSelector` narrowing (it needs a namespace's labels, which `mode`'s own
    /// signature does not carry) and, via `annotation_key`, to keep
    /// `namespaceSelection.annotation` hot-reloaded — the two are handed the same `Arc` so a
    /// sync here is visible there without either polling the other. `dwoc_catalog` is used only
    /// to compute the `weebo_si_dwoc_pin_catalog_entries` gauge. `capabilities` resolves
    /// `networkProfiles.enforcement.backend` on every sync — a snapshot from one discovery run
    /// at boot, per [`crate::kube_capabilities::KubeCapabilities`]'s own documented
    /// simplification, not re-run here.
    #[allow(
        clippy::too_many_arguments,
        reason = "the composition root's own call site"
    )]
    pub async fn spawn(
        client: Client,
        registry: &Registry,
        namespace_view: Arc<KubeNsStore>,
        annotation_key: Arc<RwLock<String>>,
        dwoc_catalog: Arc<KubeDwocStore>,
        capabilities: Arc<dyn Capabilities + Send + Sync>,
        runtime_capabilities: Arc<dyn RuntimeCapabilities + Send + Sync>,
    ) -> Result<Self, kube::Error> {
        let api: Api<WeeboSiConfig> = Api::all(client.clone());
        let team_api: Api<WeeboSiTeam> = Api::all(client);
        let (reader, writer) = reflector::store();
        let (team_reader, team_writer) = reflector::store();
        let teams = Arc::new(RwLock::new(Vec::new()));
        let dwoc_pin = Arc::new(RwLock::new(None));
        let network_profiles = Arc::new(RwLock::new(None));
        let policy_guard = Arc::new(RwLock::new(None));
        let image_policy = Arc::new(RwLock::new(None));
        let kubearmor_policy = Arc::new(RwLock::new(None));
        let registry_config = Arc::new(RwLock::new(None));
        let endpoint_auth = Arc::new(RwLock::new(None));
        let identity = Arc::new(RwLock::new(None));
        let resolved_backend = Arc::new(RwLock::new(Backend::NetworkPolicy));
        let resolved_runtime_backend = Arc::new(RwLock::new(RuntimeBackend::KubeArmor));
        let metrics = Metrics::register(registry).map_err(|err| {
            kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                err.to_string(),
            ))
        })?;

        // Two watches, one loop: a `WeeboSiTeam` changing has to re-resolve exactly what a
        // `WeeboSiConfig` changing does, per RFC 0011 — the catalogues and grants the features
        // read are the merge of both. `select` rather than two tasks so one sync can never run
        // against half of a change.
        let stream = futures_util::StreamExt::map(
            reflector::reflector(writer, watcher(api, watcher::Config::default()))
                .default_backoff(),
            |event| event.map(|_| ()),
        );
        let team_stream = futures_util::StreamExt::map(
            reflector::reflector(team_writer, watcher(team_api, watcher::Config::default()))
                .default_backoff(),
            |event| event.map(|_| ()),
        );
        let stream = futures_util::stream::select(stream, team_stream);

        let store_for_task = reader.clone();
        let team_store_for_task = team_reader.clone();
        let teams_for_task = Arc::clone(&teams);
        let dwoc_pin_for_task = Arc::clone(&dwoc_pin);
        let network_profiles_for_task = Arc::clone(&network_profiles);
        let policy_guard_for_task = Arc::clone(&policy_guard);
        let image_policy_for_task = Arc::clone(&image_policy);
        let kubearmor_policy_for_task = Arc::clone(&kubearmor_policy);
        let registry_config_for_task = Arc::clone(&registry_config);
        let endpoint_auth_for_task = Arc::clone(&endpoint_auth);
        let identity_for_task = Arc::clone(&identity);
        let resolved_backend_for_task = Arc::clone(&resolved_backend);
        let resolved_runtime_backend_for_task = Arc::clone(&resolved_runtime_backend);
        let annotation_key_for_task = Arc::clone(&annotation_key);
        let dwoc_catalog_for_task = Arc::clone(&dwoc_catalog);
        let capabilities_for_task = Arc::clone(&capabilities);
        let runtime_capabilities_for_task = Arc::clone(&runtime_capabilities);
        tokio::spawn(async move {
            let mut stream = std::pin::pin!(stream);
            loop {
                use futures_util::StreamExt;
                match stream.next().await {
                    Some(Ok(())) => sync_from_store(
                        &store_for_task,
                        &team_store_for_task,
                        &teams_for_task,
                        &dwoc_pin_for_task,
                        &network_profiles_for_task,
                        &policy_guard_for_task,
                        &image_policy_for_task,
                        &kubearmor_policy_for_task,
                        &registry_config_for_task,
                        &endpoint_auth_for_task,
                        &identity_for_task,
                        &resolved_backend_for_task,
                        &resolved_runtime_backend_for_task,
                        &annotation_key_for_task,
                        dwoc_catalog_for_task.as_ref(),
                        capabilities_for_task.as_ref(),
                        runtime_capabilities_for_task.as_ref(),
                        &metrics,
                    ),
                    Some(Err(_)) => {}
                    None => break,
                }
            }
        });

        // Only the config store is waited on. A cluster where `weebositeams` is not installed
        // yet — the first step of RFC 0011's rollout, before the chart's CRDs land — would
        // otherwise never become ready, and a hardening webhook that never becomes ready blocks
        // everything. Teams arrive with the team reflector's own first list, which is itself a
        // stream event and therefore triggers a resync.
        reader.wait_until_ready().await.map_err(|err| {
            kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                err.to_string(),
            ))
        })?;
        // The background task above owns `metrics` from the first `spawn` iteration onward, so
        // this initial sync (before the stream has necessarily yielded once) runs without it —
        // acceptable: the gauges simply start at zero until the first watch event, same as any
        // gauge before its first observation.
        sync_from_store_initial(
            &reader,
            &team_reader,
            &teams,
            &dwoc_pin,
            &network_profiles,
            &policy_guard,
            &image_policy,
            &kubearmor_policy,
            &registry_config,
            &endpoint_auth,
            &identity,
            &resolved_backend,
            &resolved_runtime_backend,
            &annotation_key,
            capabilities.as_ref(),
            runtime_capabilities.as_ref(),
        );

        Ok(Self {
            teams,
            dwoc_pin,
            network_profiles,
            policy_guard,
            image_policy,
            kubearmor_policy,
            registry_config,
            endpoint_auth,
            identity,
            resolved_backend,
            resolved_runtime_backend,
            namespace_view,
        })
    }

    /// The `Arc` the `identity` reconcile loops read, per RFC 0011. `None` until (and unless)
    /// `spec.features.identity` is present on the singleton — which is what keeps provisioning
    /// off in a cluster that never asked for it.
    pub fn identity_config(&self) -> Arc<RwLock<Option<IdentityConfig>>> {
        Arc::clone(&self.identity)
    }

    /// The `Arc` `weebo-si-dwoc-pin`'s `DwocPin::new` should be constructed with. `None` until
    /// (and unless) `spec.features.dwocPin` is present on the singleton.
    pub fn dwoc_pin_config(&self) -> Arc<RwLock<Option<ResolvedDwocPinConfig>>> {
        Arc::clone(&self.dwoc_pin)
    }

    /// The `Arc` `weebo-si-network-profiles`'s `NetworkProfiles::new` should be constructed with.
    pub fn network_profiles_config(&self) -> Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>> {
        Arc::clone(&self.network_profiles)
    }

    /// The `Arc` `weebo-si-webhook`'s `PolicyGuardState` reads `allowedIdentities` from on every
    /// request — `PolicyGuard` itself (unlike `NetworkProfiles`) is stateless per RFC 0004's
    /// *Design*, so nothing holds this handle beyond reading it fresh each time.
    pub fn policy_guard_config(&self) -> Arc<RwLock<Option<PolicyGuardConfig>>> {
        Arc::clone(&self.policy_guard)
    }

    /// The `Arc` `weebo-si-network-profiles`'s `NetworkProfiles::new` should be constructed with
    /// for its resolved `Backend`.
    pub fn resolved_backend(&self) -> Arc<RwLock<Backend>> {
        Arc::clone(&self.resolved_backend)
    }

    /// The `Arc` `weebo-si-kubearmor-policy`'s `KubeArmorPolicy::new` should be constructed
    /// with, per RFC 0006. `None` until (and unless) `spec.features.kubearmorPolicy` is present.
    pub fn kubearmor_policy_config(&self) -> Arc<RwLock<Option<ResolvedKubeArmorPolicyConfig>>> {
        Arc::clone(&self.kubearmor_policy)
    }

    /// The `Arc` `weebo-si-kubearmor-policy`'s `KubeArmorPolicy::new` should be constructed
    /// with for its resolved [`RuntimeBackend`].
    pub fn resolved_runtime_backend(&self) -> Arc<RwLock<RuntimeBackend>> {
        Arc::clone(&self.resolved_runtime_backend)
    }

    /// The `Arc` `weebo-si-registry-config`'s `RegistryConfigFeature::new` should be constructed
    /// with, per RFC 0007. `None` until (and unless) `spec.features.registryConfig` is present.
    ///
    /// **One handle, both halves**, like `image-policy`'s: the controller reconciles copies from
    /// it and the webhook's registry guard route reads the same catalogue, so the two can never
    /// disagree about what this operator owns.
    pub fn registry_config(&self) -> Arc<RwLock<Option<ResolvedRegistryConfig>>> {
        Arc::clone(&self.registry_config)
    }

    /// The `Arc` RFC 0009's admission routes and its reconcile sweep are both constructed with.
    /// **One handle, three readers** — the mutation, the guard and the controller — for the same
    /// reason `image-policy` shares one: two copies of the dialect free to disagree is a gate
    /// attached one way and pinned another.
    pub fn endpoint_auth_config(&self) -> Arc<RwLock<Option<ResolvedEndpointAuthConfig>>> {
        Arc::clone(&self.endpoint_auth)
    }

    /// The `Arc` both `weebo-si-image-policy` features are constructed with, per RFC 0005.
    /// **One handle, both halves**, so the `DevWorkspace` and `Pod` enforcement points can never
    /// disagree about the catalogue, the grants or the platform set — the same reason
    /// `network-profiles` hands one handle to its reconcile and admission halves.
    pub fn image_policy_config(&self) -> Arc<RwLock<Option<ResolvedImagePolicyConfig>>> {
        Arc::clone(&self.image_policy)
    }
}

struct Metrics {
    feature_mode: IntGaugeVec,
    catalog_entries: IntGaugeVec,
    observed_generation: IntGauge,
    network_backend: IntGaugeVec,
    network_profile_unsupported: IntGaugeVec,
    image_catalog_entries: IntGaugeVec,
}

impl Metrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let feature_mode = IntGaugeVec::new(
            Opts::new(
                "weebo_si_feature_mode",
                "0/1/2 for Off/DryRun/Enforce, by feature",
            ),
            &["feature"],
        )?;
        let catalog_entries = IntGaugeVec::new(
            Opts::new(
                "weebo_si_dwoc_pin_catalog_entries",
                "dwoc-pin catalogue entries, by whether they currently resolve",
            ),
            &["state"],
        )?;
        let observed_generation = IntGauge::new(
            "weebo_si_config_observed_generation",
            "The WeeboSiConfig generation last synced",
        )?;
        // RFC 0004's *Observability contract*. Both are properties of the *configuration* — which
        // backend resolved, and which catalogue entries that backend cannot express — so they
        // belong on the config sync rather than on a reconcile pass, whose answer would depend
        // on which namespace happened to be reconciled last.
        let network_backend = IntGaugeVec::new(
            Opts::new(
                "weebo_si_network_backend",
                "1 for the currently resolved network-profiles enforcement backend",
            ),
            &["backend"],
        )?;
        let network_profile_unsupported = IntGaugeVec::new(
            Opts::new(
                "weebo_si_network_profile_unsupported",
                "1 for a catalogue profile with no variant for the resolved backend — not \
                 applied, never approximated",
            ),
            &["profile", "backend"],
        )?;
        // RFC 0005's one configuration-shaped metric, here for the same reason the two above
        // are: how many catalogue entries parse is a property of the config, and a gauge driven
        // from an admission pass would report whichever request arrived last. It is the
        // configuration-side view of a broken pattern — it fires on an entry that stopped
        // parsing after an edit, even in a team whose workspaces nobody has restarted.
        let image_catalog_entries = IntGaugeVec::new(
            Opts::new(
                "weebo_si_image_policy_catalog_entries",
                "Catalogue entries whose every pattern parses (valid) and entries carrying at \
                 least one that does not (invalid)",
            ),
            &["state"],
        )?;
        registry.register(Box::new(feature_mode.clone()))?;
        registry.register(Box::new(catalog_entries.clone()))?;
        registry.register(Box::new(observed_generation.clone()))?;
        registry.register(Box::new(network_backend.clone()))?;
        registry.register(Box::new(network_profile_unsupported.clone()))?;
        registry.register(Box::new(image_catalog_entries.clone()))?;
        Ok(Self {
            feature_mode,
            catalog_entries,
            observed_generation,
            network_backend,
            network_profile_unsupported,
            image_catalog_entries,
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal sync helper, not a public API"
)]
fn sync_from_store_initial(
    store: &Store<WeeboSiConfig>,
    team_store: &Store<WeeboSiTeam>,
    teams: &Arc<RwLock<Vec<Team>>>,
    dwoc_pin: &Arc<RwLock<Option<ResolvedDwocPinConfig>>>,
    network_profiles: &Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
    policy_guard: &Arc<RwLock<Option<PolicyGuardConfig>>>,
    image_policy: &Arc<RwLock<Option<ResolvedImagePolicyConfig>>>,
    kubearmor_policy: &Arc<RwLock<Option<ResolvedKubeArmorPolicyConfig>>>,
    registry_config: &Arc<RwLock<Option<ResolvedRegistryConfig>>>,
    endpoint_auth: &Arc<RwLock<Option<ResolvedEndpointAuthConfig>>>,
    identity: &Arc<RwLock<Option<IdentityConfig>>>,
    resolved_backend: &Arc<RwLock<Backend>>,
    resolved_runtime_backend: &Arc<RwLock<RuntimeBackend>>,
    annotation_key: &Arc<RwLock<String>>,
    capabilities: &dyn Capabilities,
    runtime_capabilities: &dyn RuntimeCapabilities,
) {
    let Some(config) = store
        .state()
        .into_iter()
        .find(|c| c.metadata.name.as_deref() == Some(SINGLETON_NAME))
    else {
        return;
    };
    let (declared, features) = resolve(&config, team_store);
    apply_config(
        &features,
        &declared,
        teams,
        dwoc_pin,
        network_profiles,
        policy_guard,
        image_policy,
        kubearmor_policy,
        registry_config,
        endpoint_auth,
        identity,
        resolved_backend,
        resolved_runtime_backend,
        annotation_key,
        capabilities,
        runtime_capabilities,
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal sync helper, not a public API"
)]
fn sync_from_store(
    store: &Store<WeeboSiConfig>,
    team_store: &Store<WeeboSiTeam>,
    teams: &Arc<RwLock<Vec<Team>>>,
    dwoc_pin: &Arc<RwLock<Option<ResolvedDwocPinConfig>>>,
    network_profiles: &Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
    policy_guard: &Arc<RwLock<Option<PolicyGuardConfig>>>,
    image_policy: &Arc<RwLock<Option<ResolvedImagePolicyConfig>>>,
    kubearmor_policy: &Arc<RwLock<Option<ResolvedKubeArmorPolicyConfig>>>,
    registry_config: &Arc<RwLock<Option<ResolvedRegistryConfig>>>,
    endpoint_auth: &Arc<RwLock<Option<ResolvedEndpointAuthConfig>>>,
    identity: &Arc<RwLock<Option<IdentityConfig>>>,
    resolved_backend: &Arc<RwLock<Backend>>,
    resolved_runtime_backend: &Arc<RwLock<RuntimeBackend>>,
    annotation_key: &Arc<RwLock<String>>,
    dwoc_catalog: &KubeDwocStore,
    capabilities: &dyn Capabilities,
    runtime_capabilities: &dyn RuntimeCapabilities,
    metrics: &Metrics,
) {
    let Some(config) = store
        .state()
        .into_iter()
        .find(|c| c.metadata.name.as_deref() == Some(SINGLETON_NAME))
    else {
        return;
    };
    let (declared, features) = resolve(&config, team_store);
    apply_config(
        &features,
        &declared,
        teams,
        dwoc_pin,
        network_profiles,
        policy_guard,
        image_policy,
        kubearmor_policy,
        registry_config,
        endpoint_auth,
        identity,
        resolved_backend,
        resolved_runtime_backend,
        annotation_key,
        capabilities,
        runtime_capabilities,
    );

    metrics
        .observed_generation
        .set(config.metadata.generation.unwrap_or(0));

    let dwoc_pin_config = features.dwoc_pin.as_ref();
    metrics
        .feature_mode
        .with_label_values(&["dwoc-pin"])
        .set(dwoc_pin_config.map(|c| mode_value(c.mode)).unwrap_or(0));
    metrics
        .feature_mode
        .with_label_values(&["network-profiles"])
        .set(
            features
                .network_profiles
                .as_ref()
                .map(|c| mode_value(c.mode))
                .unwrap_or(0),
        );
    metrics
        .feature_mode
        .with_label_values(&["policy-guard"])
        .set(
            features
                .policy_guard
                .as_ref()
                .map(|c| mode_value(c.mode))
                .unwrap_or(0),
        );

    let (mut resolvable, mut missing) = (0i64, 0i64);
    if let Some(cfg) = dwoc_pin_config {
        for entry in cfg.catalog.entries() {
            if dwoc_catalog.resolves(&entry.target) {
                resolvable += 1;
            } else {
                missing += 1;
            }
        }
    }
    metrics
        .catalog_entries
        .with_label_values(&["resolvable"])
        .set(resolvable);
    metrics
        .catalog_entries
        .with_label_values(&["missing"])
        .set(missing);

    let backend = *resolved_backend
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for candidate in [Backend::NetworkPolicy, Backend::Cilium] {
        metrics
            .network_backend
            .with_label_values(&[backend_label(candidate)])
            .set(i64::from(candidate == backend));
    }

    metrics
        .feature_mode
        .with_label_values(&["image-policy"])
        .set(
            features
                .image_policy
                .as_ref()
                .map(|c| mode_value(c.mode))
                .unwrap_or(0),
        );

    metrics
        .feature_mode
        .with_label_values(&["kubearmor-policy"])
        .set(
            features
                .kubearmor_policy
                .as_ref()
                .map(|c| mode_value(c.mode))
                .unwrap_or(0),
        );

    metrics
        .feature_mode
        .with_label_values(&["registry-config"])
        .set(
            features
                .registry_config
                .as_ref()
                .map(|c| mode_value(c.mode))
                .unwrap_or(0),
        );

    metrics
        .feature_mode
        .with_label_values(&["endpoint-auth"])
        .set(
            features
                .endpoint_auth
                .as_ref()
                .map(|c| mode_value(c.mode))
                .unwrap_or(0),
        );

    // Set from a full recount rather than incremented, same as the gauge below: an entry whose
    // pattern was fixed must drop out of `invalid`, not keep reporting a fault that is gone.
    let (mut valid, mut invalid) = (0i64, 0i64);
    if let Some(cfg) = features.image_policy.as_ref() {
        for entry in cfg.catalog.entries() {
            // An entry is valid only if *every* pattern parses — a half-applied entry is an
            // allow-list whose contents differ from what an admin reads, so the domain refuses
            // to use one, and this gauge reports it the same way.
            if entry
                .patterns
                .iter()
                .all(|raw| weebo_si_image_policy::Pattern::parse(raw).is_ok())
            {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    metrics
        .image_catalog_entries
        .with_label_values(&["valid"])
        .set(valid);
    metrics
        .image_catalog_entries
        .with_label_values(&["invalid"])
        .set(invalid);

    // Recomputed from scratch, never incremented: a profile that gained a variant (or left the
    // catalogue) must drop back to 0 rather than keep reporting a degradation that was fixed.
    metrics.network_profile_unsupported.reset();
    if let Some(cfg) = features.network_profiles.as_ref() {
        for entry in cfg.catalog.entries() {
            metrics
                .network_profile_unsupported
                .with_label_values(&[entry.key.as_str(), backend_label(backend)])
                .set(i64::from(entry.variant(backend).is_none()));
        }
    }
}

/// The declared teams, and the configuration the features actually evaluate: the singleton
/// merged with every `WeeboSiTeam`, per RFC 0011.
///
/// Conflict messages are dropped here on purpose — this is a cache, and the `WeeboSiConfig`
/// reconcile loop is the one place that reports them, as `Degraded` conditions on the object.
fn resolve(
    config: &WeeboSiConfig,
    team_store: &Store<WeeboSiTeam>,
) -> (Vec<WeeboSiTeam>, ResolvedFeatures) {
    let declared: Vec<WeeboSiTeam> = team_store
        .state()
        .iter()
        .map(|team| (**team).clone())
        .collect();
    let (features, _conflicts) = config.spec.resolve_teams(&declared);
    (declared, features)
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal sync helper, not a public API"
)]
fn apply_config(
    features: &ResolvedFeatures,
    declared: &[WeeboSiTeam],
    teams: &Arc<RwLock<Vec<Team>>>,
    dwoc_pin: &Arc<RwLock<Option<ResolvedDwocPinConfig>>>,
    network_profiles: &Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
    policy_guard: &Arc<RwLock<Option<PolicyGuardConfig>>>,
    image_policy: &Arc<RwLock<Option<ResolvedImagePolicyConfig>>>,
    kubearmor_policy: &Arc<RwLock<Option<ResolvedKubeArmorPolicyConfig>>>,
    registry_config: &Arc<RwLock<Option<ResolvedRegistryConfig>>>,
    endpoint_auth: &Arc<RwLock<Option<ResolvedEndpointAuthConfig>>>,
    identity: &Arc<RwLock<Option<IdentityConfig>>>,
    resolved_backend: &Arc<RwLock<Backend>>,
    resolved_runtime_backend: &Arc<RwLock<RuntimeBackend>>,
    annotation_key: &Arc<RwLock<String>>,
    capabilities: &dyn Capabilities,
    runtime_capabilities: &dyn RuntimeCapabilities,
) {
    if let Ok(mut guard) = teams.write() {
        *guard = team_views(declared);
    }
    if let Ok(mut guard) = dwoc_pin.write() {
        *guard = features.dwoc_pin.clone();
    }
    if let Ok(mut guard) = network_profiles.write() {
        *guard = features.network_profiles.clone();
    }
    if let Ok(mut guard) = policy_guard.write() {
        *guard = features.policy_guard.clone();
    }
    if let Ok(mut guard) = image_policy.write() {
        *guard = features.image_policy.clone();
    }
    if let Ok(mut guard) = kubearmor_policy.write() {
        *guard = features.kubearmor_policy.clone();
    }
    if let Ok(mut guard) = registry_config.write() {
        *guard = features.registry_config.clone();
    }
    if let Ok(mut guard) = endpoint_auth.write() {
        *guard = features.endpoint_auth.clone();
    }
    if let Ok(mut guard) = identity.write() {
        *guard = features.identity.clone();
    }
    if let Ok(mut guard) = resolved_runtime_backend.write() {
        let preference = features
            .kubearmor_policy
            .as_ref()
            .map(|c| c.enforcement.backend)
            .unwrap_or_default();
        // Same reasoning as `resolved_backend` below: a cluster offering no runtime-enforcement
        // engine keeps the last resolved value rather than an `Option`, and the write sites
        // treat "nothing to write for this engine" as their own already-handled case. The
        // difference that matters is that this resolution asks a *different* capability source,
        // so a cluster with Cilium and no KubeArmor cannot resolve one from the other.
        if let Some(backend) = resolve_runtime_backend(preference, runtime_capabilities) {
            *guard = backend;
        }
    }
    if let Ok(mut guard) = resolved_backend.write() {
        let preference = features
            .network_profiles
            .as_ref()
            .map(|c| c.enforcement.backend)
            .unwrap_or_default();
        // A cluster offering neither backend is a `Degraded` condition the controller reports,
        // not something this cache can refuse to hold a value for — it keeps the last resolved
        // backend rather than an `Option`, and every write site treats "no usable variant for
        // this backend" as its own, already-handled case (see `NetworkProfiles::desired`).
        if let Some(backend) = resolve_backend(preference, capabilities) {
            *guard = backend;
        }
    }
    if let Ok(mut guard) = annotation_key.write() {
        *guard = features
            .dwoc_pin
            .as_ref()
            .map(|c| c.namespace_selection.annotation.clone())
            .unwrap_or_else(|| DEFAULT_ANNOTATION.to_string());
    }
}

impl FeatureGate for KubeConfigStore {
    fn mode(&self, feature: FeatureId, namespace: &NamespaceName) -> FeatureMode {
        let (mode, selector) = match feature.kebab() {
            "dwoc-pin" => {
                let guard = self
                    .dwoc_pin
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match guard.as_ref() {
                    Some(config) => (config.mode, config.namespace_selector.clone()),
                    None => return FeatureMode::Off,
                }
            }
            "network-profiles" => {
                let guard = self
                    .network_profiles
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match guard.as_ref() {
                    Some(config) => (config.mode, config.namespace_selector.clone()),
                    None => return FeatureMode::Off,
                }
            }
            "policy-guard" => {
                let guard = self
                    .policy_guard
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match guard.as_ref() {
                    Some(config) => (config.mode, config.namespace_selector.clone()),
                    None => return FeatureMode::Off,
                }
            }
            // One arm, both halves: RFC 0005's `DevWorkspace` and `Pod` features report the same
            // `FeatureId`, so this `mode` and this `namespaceSelector` govern both.
            "image-policy" => {
                let guard = self
                    .image_policy
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match guard.as_ref() {
                    Some(config) => (config.mode, config.namespace_selector.clone()),
                    None => return FeatureMode::Off,
                }
            }
            "kubearmor-policy" => {
                let guard = self
                    .kubearmor_policy
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match guard.as_ref() {
                    Some(config) => (config.mode, config.namespace_selector.clone()),
                    None => return FeatureMode::Off,
                }
            }
            "registry-config" => {
                let guard = self
                    .registry_config
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match guard.as_ref() {
                    Some(config) => (config.mode, config.namespace_selector.clone()),
                    None => return FeatureMode::Off,
                }
            }
            // One arm, three readers: RFC 0009's mutation, its guard and its reconcile sweep all
            // report this `FeatureId`, so one `mode` and one `namespaceSelector` govern the whole
            // feature — turning it off turns off all three at once, which is what makes the
            // rollback in *Operational considerations* one edit.
            "endpoint-auth" => {
                let guard = self
                    .endpoint_auth
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match guard.as_ref() {
                    Some(config) => (config.mode, config.namespace_selector.clone()),
                    None => return FeatureMode::Off,
                }
            }
            _ => return FeatureMode::Off,
        };

        // `namespaceSelector` narrows *within* this feature's own scope: a namespace it excludes
        // is treated as Off for this feature, regardless of the global mode. Absent selector
        // (the common case) matches everything, per RFC 0002's *Contract*.
        if let Some(selector) = selector {
            let matches = self
                .namespace_view
                .facts(namespace)
                .is_some_and(|facts| selector.matches(&facts.labels));
            if !matches {
                return FeatureMode::Off;
            }
        }

        mode
    }

    fn teams(&self) -> Vec<Team> {
        self.teams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}
