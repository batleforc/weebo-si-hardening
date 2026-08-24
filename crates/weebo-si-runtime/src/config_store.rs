//! Watch-backed `WeeboSiConfig` cache, implementing `FeatureGate`, and driving three of the six
//! metrics in RFC 0002's *Observability contract* that only a live config sync can compute:
//! `weebo_si_feature_mode`, `weebo_si_dwoc_pin_catalog_entries` and
//! `weebo_si_config_observed_generation`.

use std::sync::{Arc, RwLock};

use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};
use prometheus::{IntGauge, IntGaugeVec, Opts, Registry};
use weebo_si_crd::{
    DwocPinConfig, FeatureMode, NamespaceName, SINGLETON_NAME, Team, WeeboSiConfig,
};

use weebo_si_chassis::FeatureId;
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog as _;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView as _;

use crate::dwoc_store::KubeDwocStore;
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

/// Watch-backed `WeeboSiConfig` cache. Also drives a shared `DwocPinConfig` handle so
/// `weebo-si-dwoc-pin`'s `DwocPin` feature sees a hot-reloaded configuration without a restart,
/// and a shared `namespaceSelection.annotation` handle so [`KubeNsStore`] does too.
pub struct KubeConfigStore {
    teams: Arc<RwLock<Vec<Team>>>,
    dwoc_pin: Arc<RwLock<Option<DwocPinConfig>>>,
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
    /// to compute the `weebo_si_dwoc_pin_catalog_entries` gauge.
    pub async fn spawn(
        client: Client,
        registry: &Registry,
        namespace_view: Arc<KubeNsStore>,
        annotation_key: Arc<RwLock<String>>,
        dwoc_catalog: Arc<KubeDwocStore>,
    ) -> Result<Self, kube::Error> {
        let api: Api<WeeboSiConfig> = Api::all(client);
        let (reader, writer) = reflector::store();
        let teams = Arc::new(RwLock::new(Vec::new()));
        let dwoc_pin = Arc::new(RwLock::new(None));
        let metrics = Metrics::register(registry).map_err(|err| {
            kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                err.to_string(),
            ))
        })?;

        let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()))
            .default_backoff();

        let store_for_task = reader.clone();
        let teams_for_task = Arc::clone(&teams);
        let dwoc_pin_for_task = Arc::clone(&dwoc_pin);
        let annotation_key_for_task = Arc::clone(&annotation_key);
        let dwoc_catalog_for_task = Arc::clone(&dwoc_catalog);
        tokio::spawn(async move {
            let mut stream = std::pin::pin!(stream);
            loop {
                use futures_util::StreamExt;
                match stream.next().await {
                    Some(Ok(_)) => sync_from_store(
                        &store_for_task,
                        &teams_for_task,
                        &dwoc_pin_for_task,
                        &annotation_key_for_task,
                        dwoc_catalog_for_task.as_ref(),
                        &metrics,
                    ),
                    Some(Err(_)) => {}
                    None => break,
                }
            }
        });

        reader.wait_until_ready().await.map_err(|err| {
            kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                err.to_string(),
            ))
        })?;
        // The background task above owns `metrics` from the first `spawn` iteration onward, so
        // this initial sync (before the stream has necessarily yielded once) runs without it —
        // acceptable: the gauges simply start at zero until the first watch event, same as any
        // gauge before its first observation.
        sync_from_store_initial(&reader, &teams, &dwoc_pin, &annotation_key);

        Ok(Self {
            teams,
            dwoc_pin,
            namespace_view,
        })
    }

    /// The `Arc` `weebo-si-dwoc-pin`'s `DwocPin::new` should be constructed with. `None` until
    /// (and unless) `spec.features.dwocPin` is present on the singleton.
    pub fn dwoc_pin_config(&self) -> Arc<RwLock<Option<DwocPinConfig>>> {
        Arc::clone(&self.dwoc_pin)
    }
}

struct Metrics {
    feature_mode: IntGaugeVec,
    catalog_entries: IntGaugeVec,
    observed_generation: IntGauge,
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
        registry.register(Box::new(feature_mode.clone()))?;
        registry.register(Box::new(catalog_entries.clone()))?;
        registry.register(Box::new(observed_generation.clone()))?;
        Ok(Self {
            feature_mode,
            catalog_entries,
            observed_generation,
        })
    }
}

fn sync_from_store_initial(
    store: &Store<WeeboSiConfig>,
    teams: &Arc<RwLock<Vec<Team>>>,
    dwoc_pin: &Arc<RwLock<Option<DwocPinConfig>>>,
    annotation_key: &Arc<RwLock<String>>,
) {
    let Some(config) = store
        .state()
        .into_iter()
        .find(|c| c.metadata.name.as_deref() == Some(SINGLETON_NAME))
    else {
        return;
    };
    apply_config(&config, teams, dwoc_pin, annotation_key);
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal sync helper, not a public API"
)]
fn sync_from_store(
    store: &Store<WeeboSiConfig>,
    teams: &Arc<RwLock<Vec<Team>>>,
    dwoc_pin: &Arc<RwLock<Option<DwocPinConfig>>>,
    annotation_key: &Arc<RwLock<String>>,
    dwoc_catalog: &KubeDwocStore,
    metrics: &Metrics,
) {
    let Some(config) = store
        .state()
        .into_iter()
        .find(|c| c.metadata.name.as_deref() == Some(SINGLETON_NAME))
    else {
        return;
    };
    apply_config(&config, teams, dwoc_pin, annotation_key);

    metrics
        .observed_generation
        .set(config.metadata.generation.unwrap_or(0));

    let dwoc_pin_config = config.spec.features.dwoc_pin.as_ref();
    metrics
        .feature_mode
        .with_label_values(&["dwoc-pin"])
        .set(dwoc_pin_config.map(|c| mode_value(c.mode)).unwrap_or(0));

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
}

fn apply_config(
    config: &WeeboSiConfig,
    teams: &Arc<RwLock<Vec<Team>>>,
    dwoc_pin: &Arc<RwLock<Option<DwocPinConfig>>>,
    annotation_key: &Arc<RwLock<String>>,
) {
    if let Ok(mut guard) = teams.write() {
        *guard = config.spec.teams.clone();
    }
    if let Ok(mut guard) = dwoc_pin.write() {
        *guard = config.spec.features.dwoc_pin.clone();
    }
    if let Ok(mut guard) = annotation_key.write() {
        *guard = config
            .spec
            .features
            .dwoc_pin
            .as_ref()
            .map(|c| c.namespace_selection.annotation.clone())
            .unwrap_or_else(|| DEFAULT_ANNOTATION.to_string());
    }
}

impl FeatureGate for KubeConfigStore {
    fn mode(&self, feature: FeatureId, namespace: &NamespaceName) -> FeatureMode {
        if feature.kebab() != "dwoc-pin" {
            return FeatureMode::Off;
        }
        let guard = self
            .dwoc_pin
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(config) = guard.as_ref() else {
            return FeatureMode::Off;
        };

        // `namespaceSelector` narrows *within* the webhook's own scope: a namespace it excludes
        // is treated as Off for this feature, regardless of the global mode. Absent selector
        // (the common case) matches everything, per RFC 0002's *Contract*.
        if let Some(selector) = &config.namespace_selector {
            let matches = self
                .namespace_view
                .facts(namespace)
                .is_some_and(|facts| selector.matches(&facts.labels));
            if !matches {
                return FeatureMode::Off;
            }
        }

        config.mode
    }

    fn teams(&self) -> Vec<Team> {
        self.teams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}
