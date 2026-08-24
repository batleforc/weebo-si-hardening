//! Watch-backed outbound adapters, shared by `weebo-si-webhook` and `weebo-si-controller` —
//! mirrors `crd_runtime` being depended on by both `api` and `controller` in proxyauthk8s.

pub mod config_store;
pub mod dwoc_store;
pub mod ns_store;
pub mod prometheus;

pub use config_store::KubeConfigStore;
pub use dwoc_store::KubeDwocStore;
pub use ns_store::KubeNsStore;
pub use prometheus::PrometheusObserver;
