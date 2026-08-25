//! `ObjectStore` implementation for the `ConfigMap`/`Secret` copies `registry-config` writes:
//! server-side apply, one field manager, a label-filtered cluster-wide watch. Mirrors
//! [`crate::kube_policy_store`] and [`crate::kubearmor_policy_store`], per RFC 0007's *Design*
//! and RFC 0004's *Security considerations*, "The label is the ownership boundary."
//!
//! **The label filter matters more here than in either sibling.** A workspace namespace is full
//! of `ConfigMap`s that are none of this operator's business — Che's, the user's, the service
//! account's CA bundle — and a watch that saw them would compute a `Delete` for every one of
//! them on the first pass. The `labelSelector` is applied server-side, so the objects never
//! reach this process at all.

use std::future::Future;
use std::pin::Pin;

use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams};
use kube::core::NamespaceResourceScope;
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, Resource};
use serde_json::{Value, json};
use weebo_si_chassis::DomainError;
use weebo_si_crd::{
    MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, PROFILE_LABEL, RegistryKey, SourceKind,
};
use weebo_si_registry_config::{Applied, Diff, ManagedObject, ObjectKey, ObjectStore, tally};

use crate::registry_template_store::{config_map_body, copied_metadata, secret_body};

/// Every write from this adapter goes through server-side apply under this one manager — the
/// same one every other store in this operator uses, since a rolling update must never produce
/// two managers fighting over objects it alone writes.
const FIELD_MANAGER: &str = "weebo-si-operator";

/// The `apiVersion` every object this adapter writes carries.
const API_VERSION: &str = "v1";

/// The labels this adapter adds to a copy, on top of the template's own.
fn owned_labels(entry: &RegistryKey) -> [(String, String); 2] {
    [
        (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
        (PROFILE_LABEL.to_string(), entry.as_str().to_string()),
    ]
}

/// Watch-backed `ObjectStore` over the `ConfigMap` and `Secret` copies this operator owns,
/// cluster-wide, filtered server-side to its own managed objects.
pub struct KubeRegistryObjectStore {
    client: Client,
    config_maps: Store<ConfigMap>,
    secrets: Store<Secret>,
}

impl KubeRegistryObjectStore {
    /// Start watching every managed `ConfigMap` and `Secret`, cluster-wide. Blocks until both
    /// initial lists complete.
    pub async fn spawn(client: Client) -> Result<Self, kube::Error> {
        let selector = format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}");
        let config_maps = spawn_managed_reflector::<ConfigMap>(client.clone(), &selector).await?;
        let secrets = spawn_managed_reflector::<Secret>(client.clone(), &selector).await?;
        Ok(Self {
            client,
            config_maps,
            secrets,
        })
    }

    /// Read a live copy back into the domain's own shape.
    ///
    /// Uses exactly the projection [`crate::registry_template_store`] applies to a template. Two
    /// filters that disagreed would make every reconcile pass see a difference that is not one,
    /// and rewrite every copy in the fleet forever.
    fn from_object(
        meta: &ObjectMeta,
        kind: SourceKind,
        body: Option<ObjectBodyBytes>,
    ) -> Option<ManagedObject> {
        let entry = RegistryKey::new(meta.labels.as_ref()?.get(PROFILE_LABEL)?.clone());
        let (labels, annotations) = copied_metadata(meta);
        Some(ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new(meta.namespace.clone()?),
                name: meta.name.clone()?,
            },
            kind,
            entry,
            labels,
            annotations,
            body: body?,
        })
    }

    fn managed(&self, ns: Option<&NamespaceName>) -> Vec<ManagedObject> {
        let in_scope = |namespace: Option<&str>| match ns {
            Some(wanted) => namespace == Some(wanted.as_str()),
            None => true,
        };

        let config_maps = self
            .config_maps
            .state()
            .into_iter()
            .filter(|object| in_scope(object.metadata.namespace.as_deref()))
            .filter_map(|object| {
                Self::from_object(
                    &object.metadata,
                    SourceKind::ConfigMap,
                    config_map_body(&object),
                )
            });
        let secrets = self
            .secrets
            .state()
            .into_iter()
            .filter(|object| in_scope(object.metadata.namespace.as_deref()))
            .filter_map(|object| {
                Self::from_object(&object.metadata, SourceKind::Secret, secret_body(&object))
            });
        config_maps.chain(secrets).collect()
    }

    async fn apply_object(&self, object: &ManagedObject) -> Result<(), DomainError> {
        let document = apply_document(object)?;
        match object.kind {
            SourceKind::ConfigMap => {
                let api: Api<ConfigMap> =
                    Api::namespaced(self.client.clone(), object.key.namespace.as_str());
                patch(&api, &object.key.name, document).await
            }
            SourceKind::Secret => {
                let api: Api<Secret> =
                    Api::namespaced(self.client.clone(), object.key.namespace.as_str());
                patch(&api, &object.key.name, document).await
            }
        }
    }

    async fn delete(&self, key: &ObjectKey, kind: SourceKind) -> Result<(), DomainError> {
        match kind {
            SourceKind::ConfigMap => {
                let api: Api<ConfigMap> =
                    Api::namespaced(self.client.clone(), key.namespace.as_str());
                delete(&api, &key.name).await
            }
            SourceKind::Secret => {
                let api: Api<Secret> = Api::namespaced(self.client.clone(), key.namespace.as_str());
                delete(&api, &key.name).await
            }
        }
    }
}

/// The bytes a body carries — an alias, so [`KubeRegistryObjectStore::from_object`]'s signature
/// says what it takes without this module naming the domain type twice.
type ObjectBodyBytes = weebo_si_registry_config::ObjectBody;

/// The full apply document for one copy: the payload the template carried, plus the metadata
/// this adapter owns.
///
/// Split out from [`KubeRegistryObjectStore::apply_object`] so the document this operator sends
/// can be asserted without an apiserver — which is where the "the copy carries the template's
/// mount annotations verbatim, plus our two labels, and nothing else" property is actually
/// checked.
fn apply_document(object: &ManagedObject) -> Result<Value, DomainError> {
    // The one place in this process that holds decoded template bytes, and it holds them from
    // here to the `patch` call below — RFC 0007's *Data and state*: "the adapter holds them
    // between a `get` and an `apply`."
    let payload: Value = serde_json::from_slice(&object.body.clone().into_bytes())
        .map_err(|err| DomainError::PortFailed(format!("malformed template body: {err}")))?;

    let mut labels = object.labels.clone();
    labels.extend(owned_labels(&object.entry));

    let mut document = json!({
        "apiVersion": API_VERSION,
        "kind": object.kind.as_str(),
        "metadata": {
            "name": object.key.name,
            "namespace": object.key.namespace.as_str(),
            "labels": labels,
            "annotations": object.annotations,
        },
    });

    // Merged rather than nested under a fixed key: a `ConfigMap`'s payload is `data` +
    // `binaryData` and a `Secret`'s is `data` + `type`, and those are top-level fields of the
    // object, not a sub-document.
    if let (Value::Object(document), Value::Object(payload)) = (&mut document, payload) {
        for (key, value) in payload {
            document.insert(key, value);
        }
    }
    Ok(document)
}

async fn patch<K>(api: &Api<K>, name: &str, document: Value) -> Result<(), DomainError>
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    api.patch(
        name,
        // `.force()`, matching `kubearmor-policy`'s store and for a sharper version of its
        // reason. Server-side apply refuses to overwrite a field another manager owns, so the
        // moment someone runs `kubectl edit` on a managed copy, every subsequent apply from this
        // controller fails with a 409 and the drift this brick exists to correct becomes the
        // drift it can no longer correct.
        //
        // `network-profiles` can afford not to force because `policy-guard` denies that edit at
        // admission first. This brick's guard rule ships at `failurePolicy: Ignore` (RFC 0007's
        // *Operational considerations*), which is exactly the choice to let some edits through
        // during a webhook outage — so this store must be able to put its own object back on its
        // own. Forcing is safe the way the label makes it safe: this adapter only ever applies
        // to objects it built, in namespaces this feature reconciles, carrying its own
        // managed-by label.
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(document),
    )
    .await
    .map_err(|err| DomainError::PortFailed(err.to_string()))?;
    Ok(())
}

async fn delete<K>(api: &Api<K>, name: &str) -> Result<(), DomainError>
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        // Deleting an object that is already gone is the outcome we wanted, not a failure — this
        // is what keeps a repeated Enforce pass over a namespace idempotent.
        Err(kube::Error::Api(err)) if err.code == 404 => Ok(()),
        Err(err) => Err(DomainError::PortFailed(err.to_string())),
    }
}

async fn spawn_managed_reflector<K>(
    client: Client,
    label_selector: &str,
) -> Result<Store<K>, kube::Error>
where
    K: Resource<DynamicType = (), Scope = NamespaceResourceScope>
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + serde::de::DeserializeOwned
        + 'static,
{
    let api: Api<K> = Api::all(client);
    let (reader, writer) = reflector::store::<K>();
    let config = watcher::Config::default().labels(label_selector);
    let stream = reflector::reflector(writer, watcher(api, config)).default_backoff();
    tokio::spawn(async move {
        use futures_util::StreamExt;
        let mut stream = std::pin::pin!(stream);
        while stream.next().await.is_some() {}
    });
    reader.wait_until_ready().await.map_err(|err| {
        kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
            err.to_string(),
        ))
    })?;
    Ok(reader)
}

impl ObjectStore for KubeRegistryObjectStore {
    fn managed_in(&self, ns: &NamespaceName) -> Vec<ManagedObject> {
        self.managed(Some(ns))
    }

    /// Free: the watch caches already hold exactly this population, filtered server-side by the
    /// ownership label — so "everything this operator owns, cluster-wide" costs no apiserver
    /// round-trip, which is what makes recomputing the gauge from a full snapshot affordable.
    fn managed_everywhere(&self) -> Vec<ManagedObject> {
        self.managed(None)
    }

    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>> {
        Box::pin(async move {
            for diff in diffs {
                match diff {
                    Diff::Create(object) | Diff::Update(object) => {
                        self.apply_object(object).await?
                    }
                    Diff::Delete { key, backend } => self.delete(key, *backend).await?,
                    Diff::Unchanged(_) => {}
                }
            }
            Ok(tally(diffs))
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_registry_config::ObjectBody;

    use super::*;

    fn object(kind: SourceKind, payload: &str) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: "weebo-si-internal-npm-weebo-npmrc".to_string(),
            },
            kind,
            entry: RegistryKey::new("internal-npm"),
            labels: BTreeMap::from([(
                "controller.devfile.io/mount-to-devworkspace".to_string(),
                "true".to_string(),
            )]),
            annotations: BTreeMap::from([
                (
                    "controller.devfile.io/mount-as".to_string(),
                    "subpath".to_string(),
                ),
                (
                    "controller.devfile.io/mount-path".to_string(),
                    "/home/user".to_string(),
                ),
            ]),
            body: ObjectBody::opaque(payload.as_bytes().to_vec()),
        }
    }

    #[test]
    fn the_copy_carries_the_ownership_labels_this_operator_writes() {
        let document = apply_document(&object(SourceKind::ConfigMap, "{}")).unwrap();
        let labels = document.pointer("/metadata/labels").unwrap();
        assert_eq!(
            labels.get("hardening.weebo.io/managed-by").unwrap(),
            "weebo-si-operator"
        );
        assert_eq!(
            labels.get("hardening.weebo.io/profile").unwrap(),
            "internal-npm"
        );
    }

    #[test]
    fn the_copy_carries_the_templates_automount_label_and_annotations_verbatim() {
        // Without these the copy is an object nobody mounts, which is indistinguishable from a
        // working configuration until a build fails.
        let document = apply_document(&object(SourceKind::ConfigMap, "{}")).unwrap();
        assert_eq!(
            document
                .pointer("/metadata/labels/controller.devfile.io~1mount-to-devworkspace")
                .and_then(Value::as_str),
            Some("true")
        );
        assert_eq!(
            document
                .pointer("/metadata/annotations/controller.devfile.io~1mount-as")
                .and_then(Value::as_str),
            Some("subpath")
        );
    }

    #[test]
    fn the_payload_is_merged_at_the_top_level_not_nested() {
        // A `ConfigMap`'s `data` is a field of the object, not a sub-document. Nesting it would
        // produce an object the apiserver accepts and DevWorkspace Operator mounts as nothing.
        let document = apply_document(&object(
            SourceKind::ConfigMap,
            r#"{"data":{".npmrc":"registry=x"}}"#,
        ))
        .unwrap();
        assert_eq!(
            document.pointer("/data/.npmrc").and_then(Value::as_str),
            Some("registry=x")
        );
    }

    #[test]
    fn a_secret_copy_names_the_secret_kind_and_carries_its_type() {
        let document = apply_document(&object(
            SourceKind::Secret,
            r#"{"data":{".npmrc":"dG9rZW4="},"type":"Opaque"}"#,
        ))
        .unwrap();
        assert_eq!(document.get("kind").and_then(Value::as_str), Some("Secret"));
        assert_eq!(document.get("type").and_then(Value::as_str), Some("Opaque"));
    }

    #[test]
    fn the_document_reaches_nothing_outside_metadata_and_the_payload() {
        // The security property: this adapter writes objects into namespaces it does not own. A
        // document that carried an `ownerReference`, a `resourceVersion` or a `status` would be
        // this operator claiming more than a copy — RFC 0007's *Managed objects*: "It never
        // preserves `metadata.ownerReferences`, `resourceVersion`, or `uid` — a copy is a new
        // object, not a mirror of one."
        let document =
            apply_document(&object(SourceKind::ConfigMap, r#"{"data":{"a":"b"}}"#)).unwrap();
        let mut keys: Vec<&str> = document
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["apiVersion", "data", "kind", "metadata"]);

        let mut metadata_keys: Vec<&str> = document
            .pointer("/metadata")
            .and_then(Value::as_object)
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        metadata_keys.sort_unstable();
        assert_eq!(
            metadata_keys,
            vec!["annotations", "labels", "name", "namespace"]
        );
    }

    #[test]
    fn a_malformed_body_is_a_port_failure_rather_than_a_half_written_object() {
        assert!(matches!(
            apply_document(&object(SourceKind::ConfigMap, "not json")),
            Err(DomainError::PortFailed(_))
        ));
    }
}
