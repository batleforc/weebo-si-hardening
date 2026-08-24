//! `Capabilities` implementation: a one-shot apiserver discovery snapshot, per RFC 0004's
//! *Design*: "`Auto` resolves to the most capable backend the apiserver advertises."
//!
//! **Known simplification**: discovery runs once, at boot. A cluster where a CNI's CRD is
//! installed *after* this process starts is not noticed until a restart — the same limitation
//! `weebo-si-operator backends` (a one-shot manual check) already has by design, and consistent
//! with `Capabilities` describing "what this cluster is," a much slower-moving fact than
//! `WeeboSiConfig` or a `Namespace`.

use kube::Client;
use kube::discovery::Discovery;
use weebo_si_crd::Backend;
use weebo_si_network_profiles::Capabilities;

/// The API group `CiliumNetworkPolicy` lives in — present only when Cilium's CRDs are installed.
const CILIUM_GROUP: &str = "cilium.io";

/// A one-shot snapshot of which backends this cluster offers.
pub struct KubeCapabilities {
    cilium_offered: bool,
}

impl KubeCapabilities {
    /// Run discovery once and snapshot the result.
    ///
    /// `NetworkPolicy` (`networking.k8s.io/v1`) is a built-in resource on every conformant
    /// Kubernetes apiserver since 1.7 — this adapter reports it offered unconditionally rather
    /// than spending a discovery round-trip confirming what is never actually absent.
    /// `CiliumNetworkPolicy` is a CRD Cilium installs, so its presence is the one real question:
    /// `Discovery::has_group` is enough to answer it, since a coarse "this cluster runs Cilium's
    /// CRDs" is exactly what `Capabilities::offers` promises — not a check of any particular
    /// verb or version.
    pub async fn discover(client: Client) -> Result<Self, kube::Error> {
        let discovery = Discovery::new(client).filter(&[CILIUM_GROUP]).run().await?;
        Ok(Self {
            cilium_offered: discovery.has_group(CILIUM_GROUP),
        })
    }
}

impl Capabilities for KubeCapabilities {
    fn offers(&self, backend: Backend) -> bool {
        match backend {
            Backend::NetworkPolicy => true,
            Backend::Cilium => self.cilium_offered,
        }
    }
}
