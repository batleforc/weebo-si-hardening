//! Watch-backed outbound adapters, shared by `weebo-si-webhook` and `weebo-si-controller` —
//! mirrors `crd_runtime` being depended on by both `api` and `controller` in proxyauthk8s.

pub mod config_store;
pub mod dwoc_store;
pub mod image_metrics;
pub mod kube_canary;
pub mod kube_capabilities;
pub mod kube_policy_store;
pub mod kube_template_store;
pub mod network_metrics;
pub mod ns_store;
pub mod prometheus;

pub use config_store::KubeConfigStore;
pub use dwoc_store::KubeDwocStore;
pub use image_metrics::ImageMetrics;
pub use kube_canary::{CLIENT_POD, DEFAULT_CANARY_IMAGE, DENY_POLICY, KubeCanary, SERVER_POD};
pub use kube_capabilities::KubeCapabilities;
pub use kube_policy_store::KubePolicyStore;
pub use kube_template_store::KubeTemplateStore;
pub use network_metrics::NetworkMetrics;
pub use ns_store::KubeNsStore;
pub use prometheus::PrometheusObserver;
