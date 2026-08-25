//! The `WeeboSiConfig` CRD — its schema, and the config it carries.
//!
//! Per RFC 0002's amendment: the CRD struct tree *is* the domain model here, not a projection of
//! a kube-free layer underneath it. This crate stays free of `kube::Client`, `axum`, and `async`
//! so a `crd`-printing subcommand never links the webhook or controller's dependencies, and so
//! every type here is a plain, deterministic value the rest of the workspace can trust without
//! doing any I/O.

pub mod dwoc;
pub mod dwoc_pin;
pub mod feature_mode;
pub mod image_policy;
pub mod kubearmor_policy;
pub mod labels;
pub mod namespace;
pub mod network_profiles;
pub mod policy_guard;
pub mod registry_config;
pub mod selector;
pub mod spec;
pub mod team;

pub use dwoc::DwocRef;
pub use dwoc_pin::{
    Catalog, CatalogEntry, CatalogKey, ConfigViolation, DwocPinConfig, Grant, NamespaceSelection,
    OnMissingTarget, OnUnknownKey,
};
pub use feature_mode::FeatureMode;
pub use image_policy::{
    Entry, EntryKey, ImageCatalog, ImageGrant, ImageNamespaceSelection, ImagePolicyConfig,
    ImagePolicyConfigViolation, ImageWorkspaceSelection, PlatformConfig, RESERVED_VARIABLES,
    VariableBinding, is_legal_variable_name,
};
pub use kubearmor_policy::{
    DefaultPosture, KUBEARMOR_CAPABILITIES_POSTURE_ANNOTATION, KUBEARMOR_FILE_POSTURE_ANNOTATION,
    KUBEARMOR_NETWORK_POSTURE_ANNOTATION, KubeArmorPolicyConfig, KubeArmorPolicyConfigViolation,
    Posture, RuntimeBackend, RuntimeEnforcement, RuntimeEnforcementBackend,
    RuntimeNamespaceSelection, RuntimeProfile, RuntimeProfileCatalog, RuntimeProfileGrant,
    RuntimeProfileKey, RuntimeWorkspaceSelection,
};
pub use labels::{
    BACKEND_LABEL, CANARY_LABEL, DEVWORKSPACE_ID_LABEL, KUBEARMOR_ENFORCER_LABEL, MANAGED_BY_LABEL,
    MANAGED_BY_VALUE, PROFILE_LABEL,
};
pub use namespace::NamespaceName;
pub use network_profiles::{
    Backend, Canary, Enforcement, EnforcementBackend, NetworkProfilesConfig,
    NetworkProfilesConfigViolation, OnNotGranted, Profile, ProfileCatalog, ProfileGrant,
    ProfileKey, ProfileNamespaceSelection, TemplateRef, Variant, WorkspaceSelection,
};
pub use policy_guard::PolicyGuardConfig;
pub use registry_config::{
    Ecosystem, RegistryCatalog, RegistryConfig, RegistryConfigViolation, RegistryEntry,
    RegistryGrant, RegistryKey, RegistryNamespaceSelection, RegistrySource, SourceKind, copy_name,
};
pub use selector::{Expression, Operator, Selector};
pub use spec::{
    FeatureState, FeatureStatus, Features, SINGLETON_NAME, WeeboSiConfig, WeeboSiConfigSpec,
    WeeboSiConfigStatus,
};
pub use team::{Team, TeamName};
