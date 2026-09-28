//! `Provisioner` over the real apiserver — the adapter that writes RFC 0011's two provisioned
//! kinds, `authentik.weebo.io/v1alpha1 AuthentikUser` and `argoproj.io/v1alpha1 Application`.
//!
//! **Dynamic, not typed.** Both kinds belong to other projects; depending on their Rust types
//! would mean depending on their whole schemas and recompiling this operator when either moves.
//! The domain hands over a `spec` it rendered as JSON and this adapter wraps it in the metadata
//! it owns — name, namespace, the managed-by label and the `ownerReference`.
//!
//! **No `delete`, anywhere.** What this operator creates carries an `ownerReference` to the
//! `WeeboSiUser` it was created for, so deletion happens through garbage collection and this
//! adapter never needs a verb that could remove somebody else's object.

use std::sync::atomic::{AtomicBool, Ordering};

use kube::api::{Api, ApiResource, DynamicObject, ObjectMeta, Patch, PatchParams, TypeMeta};
use kube::core::GroupVersionKind;
use kube::discovery::Discovery;
use kube::{Client, ResourceExt};
use weebo_si_chassis::DomainError;
use weebo_si_crd::MANAGED_BY_LABEL;
use weebo_si_identity::port::{DesiredObject, Observation, PortFuture, Provisioner};

/// The group the `AuthentikUser` CRD lives in — [batleforc/weebo-authentik][repo].
///
/// [repo]: https://github.com/batleforc/weebo-authentik
pub const AUTHENTIK_GROUP: &str = "authentik.weebo.io";
/// Argo CD's own group.
pub const ARGO_GROUP: &str = "argoproj.io";
/// The `apiVersion` of the owner reference every created object carries.
pub const OWNER_API_VERSION: &str = "hardening.weebo.io/v1alpha1";
/// The field manager this adapter applies as.
const FIELD_MANAGER: &str = "weebo-si-operator";

/// One provisioned kind, over a live cluster.
pub struct KubeProvisioner {
    client: Client,
    resource: ApiResource,
    kind: &'static str,
    group: &'static str,
    /// Whether this cluster serves the kind at all. Discovered lazily and cached once true: a
    /// cluster that gains the CRD while this process runs starts working without a restart,
    /// while a cluster that has it pays one discovery call at boot and none afterwards.
    served: AtomicBool,
}

impl KubeProvisioner {
    /// The `AuthentikUser` handle. Cluster-scoped, like the upstream CRD.
    pub fn authentik_user(client: Client) -> Self {
        let gvk = GroupVersionKind::gvk(AUTHENTIK_GROUP, "v1alpha1", "AuthentikUser");
        Self {
            client,
            resource: ApiResource::from_gvk_with_plural(&gvk, "authentikusers"),
            kind: "AuthentikUser",
            group: AUTHENTIK_GROUP,
            served: AtomicBool::new(false),
        }
    }

    /// The Argo CD `Application` handle. Namespaced — always in the one namespace
    /// `spec.features.identity.che.applicationNamespace` names.
    pub fn argo_application(client: Client) -> Self {
        let gvk = GroupVersionKind::gvk(ARGO_GROUP, "v1alpha1", "Application");
        Self {
            client,
            resource: ApiResource::from_gvk_with_plural(&gvk, "applications"),
            kind: "Application",
            group: ARGO_GROUP,
            served: AtomicBool::new(false),
        }
    }

    /// Whether this cluster serves the kind, re-discovering only while the answer is still no.
    async fn is_served(&self) -> bool {
        if self.served.load(Ordering::Relaxed) {
            return true;
        }
        let discovered = Discovery::new(self.client.clone())
            .filter(&[self.group])
            .run()
            .await
            .map(|discovery| discovery.has_group(self.group))
            .unwrap_or(false);
        if discovered {
            self.served.store(true, Ordering::Relaxed);
        }
        discovered
    }

    fn api(&self, namespace: Option<&str>) -> Api<DynamicObject> {
        match namespace {
            Some(namespace) => Api::namespaced_with(self.client.clone(), namespace, &self.resource),
            None => Api::all_with(self.client.clone(), &self.resource),
        }
    }
}

impl Provisioner for KubeProvisioner {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn observe<'a>(
        &'a self,
        name: &'a str,
        namespace: Option<&'a str>,
    ) -> PortFuture<'a, Observation> {
        Box::pin(async move {
            match self.api(namespace).get_opt(name).await {
                Ok(Some(object)) => Ok(Observation::Present {
                    owner_uid: owner_uid(&object),
                    spec: object
                        .data
                        .get("spec")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                }),
                // A cluster with no such CRD answers exactly like a cluster with no such object,
                // and in two different shapes: `get_opt` maps a well-formed 404 to `None`, while
                // an unknown API path 404s with a body it cannot parse as a `Status` and comes
                // back as an error. Discovery is what tells "create it" from "a dependency is
                // missing", and the difference matters — the second must never be retried as a
                // write.
                Ok(None) => {
                    if self.is_served().await {
                        Ok(Observation::Missing)
                    } else {
                        Ok(Observation::KindAbsent)
                    }
                }
                Err(err) => {
                    if self.is_served().await {
                        Err(DomainError::PortFailed(format!(
                            "reading {}/{name}: {err}",
                            self.kind
                        )))
                    } else {
                        Ok(Observation::KindAbsent)
                    }
                }
            }
        })
    }

    fn apply<'a>(&'a self, desired: &'a DesiredObject) -> PortFuture<'a, ()> {
        Box::pin(async move {
            let mut labels = desired.labels.clone();
            labels.insert(
                MANAGED_BY_LABEL.to_string(),
                weebo_si_crd::MANAGED_BY_VALUE.to_string(),
            );

            let object = DynamicObject {
                types: Some(TypeMeta {
                    api_version: format!("{}/{}", self.resource.group, self.resource.version),
                    kind: self.kind.to_string(),
                }),
                metadata: ObjectMeta {
                    name: Some(desired.name.clone()),
                    namespace: desired.namespace.clone(),
                    labels: Some(labels),
                    owner_references: Some(vec![
                        k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                            api_version: desired.owner.api_version.clone(),
                            kind: desired.owner.kind.clone(),
                            name: desired.owner.name.clone(),
                            uid: desired.owner.uid.clone(),
                            block_owner_deletion: None,
                            controller: Some(true),
                        },
                    ]),
                    ..Default::default()
                },
                data: serde_json::json!({ "spec": desired.spec }),
            };

            self.api(desired.namespace.as_deref())
                .patch(
                    &desired.name,
                    &PatchParams::apply(FIELD_MANAGER).force(),
                    &Patch::Apply(&object),
                )
                .await
                .map(|_| ())
                .map_err(|err| {
                    DomainError::PortFailed(format!(
                        "writing {}/{}: {err}",
                        self.kind, desired.name
                    ))
                })
        })
    }
}

/// The `WeeboSiUser` uid owning `object`, if one does.
///
/// By uid and never by name: a person deleted and recreated under the same name must not inherit
/// the objects of the first one, which is the whole reason [`DesiredObject`] carries a uid at all.
fn owner_uid(object: &DynamicObject) -> Option<String> {
    object
        .owner_references()
        .iter()
        .find(|owner| owner.kind == "WeeboSiUser" && owner.api_version == OWNER_API_VERSION)
        .map(|owner| owner.uid.clone())
}
