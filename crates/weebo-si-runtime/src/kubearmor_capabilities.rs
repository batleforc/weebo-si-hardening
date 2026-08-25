//! `Capabilities` implementation for `kubearmor-policy`: a one-shot apiserver discovery snapshot.
//!
//! **This answers one of the two questions `weebo-si-operator backends kubearmor` prints**, and
//! it is the cluster-wide one: does the apiserver serve the `KubeArmorPolicy` CRD at all. The
//! per-node question — will a policy written here actually be enforced where a pod lands — is
//! [`crate::KubeNodeEnforcerView`]'s, and RFC 0006's *Architecture* is explicit that only the
//! first is knowable before writing anything.
//!
//! **Known simplification**, shared with [`crate::KubeCapabilities`]: discovery runs once, at
//! boot. A cluster where KubeArmor is installed *after* this process starts is not noticed until
//! a restart — consistent with `Capabilities` describing "what this cluster is," a much
//! slower-moving fact than `WeeboSiConfig` or a `Namespace`.

use kube::Client;
use kube::discovery::Discovery;
use weebo_si_crd::RuntimeBackend;
use weebo_si_kubearmor_policy::Capabilities;

use crate::kubearmor_template_store::KUBEARMOR_GROUP;

/// A one-shot snapshot of whether this cluster serves KubeArmor's CRDs.
pub struct KubeArmorCapabilities {
    kubearmor_offered: bool,
}

impl KubeArmorCapabilities {
    /// Run discovery once and snapshot the result.
    ///
    /// `Discovery::has_group` is enough: a coarse "this cluster runs KubeArmor's CRDs" is exactly
    /// what [`Capabilities::offers`] promises — not a check of any particular verb or version.
    pub async fn discover(client: Client) -> Result<Self, kube::Error> {
        let discovery = Discovery::new(client)
            .filter(&[KUBEARMOR_GROUP])
            .run()
            .await?;
        Ok(Self {
            kubearmor_offered: discovery.has_group(KUBEARMOR_GROUP),
        })
    }

    /// Build a snapshot from an already-known answer — for the CLI, which runs its own discovery
    /// to print both questions at once, and for tests.
    pub fn from_offered(kubearmor_offered: bool) -> Self {
        Self { kubearmor_offered }
    }
}

impl Capabilities for KubeArmorCapabilities {
    fn offers(&self, backend: RuntimeBackend) -> bool {
        match backend {
            RuntimeBackend::KubeArmor => self.kubearmor_offered,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn a_cluster_without_the_crd_offers_nothing() {
        // The one behaviour that matters: `resolve_backend` must get `None` here rather than an
        // engine that is not installed, so nothing is written at all.
        let caps = KubeArmorCapabilities::from_offered(false);
        assert!(!caps.offers(RuntimeBackend::KubeArmor));
    }

    #[test]
    fn a_cluster_with_the_crd_offers_kubearmor() {
        let caps = KubeArmorCapabilities::from_offered(true);
        assert!(caps.offers(RuntimeBackend::KubeArmor));
    }
}
