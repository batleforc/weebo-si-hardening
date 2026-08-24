//! The static registry `weebo-si-operator features` prints — "what does this build actually
//! contain," answerable from the image rather than from the source tree, per RFC 0002's *CLI*
//! contract. Composition-root knowledge: it names every feature crate this binary links, which
//! no single feature or chassis crate is entitled to know about itself.

/// What `weebo-si-operator features` prints for one feature.
pub struct FeatureDescriptor {
    /// The feature's kebab-case identifier.
    pub id: &'static str,
    /// The RFC that introduced this feature.
    pub rfc: &'static str,
    /// The Kubernetes resource this feature acts on.
    pub resource: &'static str,
}

/// Every feature this build knows about.
pub const REGISTERED: &[FeatureDescriptor] = &[
    FeatureDescriptor {
        id: "dwoc-pin",
        rfc: "RFC 0002",
        resource: "DevWorkspace",
    },
    FeatureDescriptor {
        id: "network-profiles",
        rfc: "RFC 0004",
        resource: "Namespace, DevWorkspace",
    },
    FeatureDescriptor {
        id: "policy-guard",
        rfc: "RFC 0004",
        resource: "NetworkPolicy, CiliumNetworkPolicy",
    },
];
