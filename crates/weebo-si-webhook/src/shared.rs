//! What every feature's admission routes may use, built once by the composition root
//! (`weebo-si-operator webhook`) and handed to each adapters crate's `admission_routes`
//! (RFC 0012). Adding a feature adds one call, not a field.

use std::sync::Arc;

use weebo_si_runtime::{KubeConfigStore, KubeDwocStore, KubeNsStore, PrometheusObserver};

use crate::metrics::WebhookMetrics;

/// The shared half of every admission route.
pub struct AdmissionShared {
    /// The `WeeboSiConfig`/`WeeboSiTeam` cache: the feature gate and every feature's live config.
    pub config_store: Arc<KubeConfigStore>,
    /// Every namespace's labels and selection annotation.
    pub ns_store: Arc<KubeNsStore>,
    /// Every `DevWorkspaceOperatorConfig`, for the `dwoc-pin` catalogue check.
    pub dwoc_store: Arc<KubeDwocStore>,
    /// `weebo_si_admission_requests_total` and the decision events.
    pub observer: Arc<PrometheusObserver>,
    /// `weebo_si_admission_duration_seconds`, `weebo_si_admission_unguarded_total`.
    pub metrics: WebhookMetrics,
    /// The registry `/metrics` serves; a feature with series of its own registers them here.
    pub prometheus: prometheus::Registry,
    /// The controller's own `system:serviceaccount:<ns>:<name>` — the one writer a guard never
    /// locks out (`--operator-identity`).
    pub operator_identity: String,
}
