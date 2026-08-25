//! Watch-backed `ConfigMap`/`Secret` template cache, implementing `registry-config`'s
//! `TemplateStore` — one namespace, mirroring [`crate::kube_template_store`]'s shape for
//! `network-profiles`.
//!
//! **This is the first adapter in this project that reads `Secret` objects**, and the whole of
//! the handling that makes RFC 0007's *Architecture* claim true lives between here and
//! [`crate::registry_object_store`]: the decoded bytes exist inside
//! [`weebo_si_registry_config::ObjectBody`], which the domain can compare and clone but cannot
//! print or borrow, and they leave it again only in the store's `apply`.
//!
//! **Known simplification**, inherited from [`crate::kube_template_store`]: a template edit is
//! picked up by the next reconcile pass that reads it (the watch keeps the cache fresh), but
//! nothing here *triggers* a re-reconcile of every namespace using it — that trigger belongs to
//! the controller's watch wiring, not this cache.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{Api, ObjectMeta};
use kube::core::NamespaceResourceScope;
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, Resource};
use serde::Serialize;
use serde_json::Value;
use weebo_si_crd::{SourceKind, TemplateRef};
use weebo_si_registry_config::{ObjectBody, Template, TemplateStore};

/// The label/annotation prefix this operator owns. Keys carrying it are *not* copied from a
/// template — they are provenance the adapter writes onto the copy itself, and preserving an
/// admin's hand-written `hardening.weebo.io/managed-by` would let a template claim ownership of
/// something this operator never wrote.
pub const OWNED_PREFIX: &str = "hardening.weebo.io/";

/// `kubectl apply`'s bookkeeping annotation, stripped from both a template and a live copy.
///
/// It carries a serialized snapshot of the *whole object at the time of the last apply* —
/// including, for a `Secret`, its `data`. Copying it would put a second, stale copy of the
/// credential in the workspace namespace, and diffing on it would rewrite every copy every time
/// an admin re-applied a template without changing it. Stripped on both sides of the diff so the
/// two agree.
const LAST_APPLIED_ANNOTATION: &str = "kubectl.kubernetes.io/last-applied-configuration";

/// The subset of an object's metadata that travels into a copy.
///
/// `pub(crate)` rather than private: [`crate::registry_object_store`] reads a live copy back
/// through the same projection, and a diff whose two sides filtered differently would report a
/// change on every pass forever.
pub(crate) fn copied_metadata(
    meta: &ObjectMeta,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let filter = |map: Option<&BTreeMap<String, String>>| -> BTreeMap<String, String> {
        map.map(|entries| {
            entries
                .iter()
                .filter(|(key, _)| !key.starts_with(OWNED_PREFIX))
                .filter(|(key, _)| key.as_str() != LAST_APPLIED_ANNOTATION)
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
    };
    (
        filter(meta.labels.as_ref()),
        filter(meta.annotations.as_ref()),
    )
}

/// Serialize the payload fields of an object into an opaque body.
///
/// The fields are named rather than "everything but metadata" on purpose: a live object carries
/// `apiVersion`, `kind` and a `status` this operator has no business copying, and an
/// all-but-metadata projection would put the apiserver's own bookkeeping into the diff.
fn body_from(fields: &[(&str, Option<Value>)]) -> Option<ObjectBody> {
    let mut map = serde_json::Map::new();
    for (name, value) in fields {
        if let Some(value) = value {
            map.insert((*name).to_string(), value.clone());
        }
    }
    serde_json::to_vec(&Value::Object(map))
        .ok()
        .map(ObjectBody::opaque)
}

fn value_of<T: Serialize>(field: Option<&T>) -> Option<Value> {
    field.and_then(|value| serde_json::to_value(value).ok())
}

/// A `ConfigMap`'s payload: `data` and `binaryData`, and nothing else.
pub(crate) fn config_map_body(object: &ConfigMap) -> Option<ObjectBody> {
    body_from(&[
        ("data", value_of(object.data.as_ref())),
        ("binaryData", value_of(object.binary_data.as_ref())),
    ])
}

/// A `Secret`'s payload: `data` and `type`.
///
/// **No `stringData`.** It is a write-only convenience field: the apiserver merges it into `data`
/// and never serves it back, so a template authored with `stringData` reaches this adapter as
/// `data`. Reading it here would mean a template and its own copy disagreed about which field
/// held the payload, and the diff would rewrite the copy on every pass.
pub(crate) fn secret_body(object: &Secret) -> Option<ObjectBody> {
    body_from(&[
        ("data", value_of(object.data.as_ref())),
        ("type", value_of(object.type_.as_ref())),
    ])
}

/// Watch-backed template cache over `ConfigMap` and `Secret`, scoped to one namespace.
///
/// Two reflectors rather than one dynamic watch: both are core types with generated structs, and
/// naming them keeps the payload projection above typed rather than a set of JSON pointers.
pub struct KubeRegistryTemplateStore {
    config_maps: Store<ConfigMap>,
    secrets: Store<Secret>,
}

impl KubeRegistryTemplateStore {
    /// Start watching `ConfigMap` and `Secret` templates in `namespace`. Blocks until both
    /// initial lists complete.
    ///
    /// Scoped to the operator's own namespace, never cluster-wide: the templates live where the
    /// `WeeboSiConfig` that names them does, and a cluster-wide `Secret` watch would be this
    /// operator holding every credential in the cluster in memory.
    pub async fn spawn(client: Client, namespace: &str) -> Result<Self, kube::Error> {
        let config_maps = spawn_reflector::<ConfigMap>(client.clone(), namespace).await?;
        let secrets = spawn_reflector::<Secret>(client, namespace).await?;
        Ok(Self {
            config_maps,
            secrets,
        })
    }
}

async fn spawn_reflector<K>(client: Client, namespace: &str) -> Result<Store<K>, kube::Error>
where
    K: Resource<DynamicType = (), Scope = NamespaceResourceScope>
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + serde::de::DeserializeOwned
        + 'static,
{
    let api: Api<K> = Api::namespaced(client, namespace);
    let (reader, writer) = reflector::store::<K>();
    let stream =
        reflector::reflector(writer, watcher(api, watcher::Config::default())).default_backoff();
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

impl TemplateStore for KubeRegistryTemplateStore {
    fn template(&self, kind: SourceKind, template_ref: &TemplateRef) -> Option<Template> {
        // `kind` decides which cache is consulted, and nothing else: a `ConfigMap` and a `Secret`
        // may legitimately share a `{name, namespace}`, and an entry naming one must never be
        // handed the other.
        let (meta, body) = match kind {
            SourceKind::ConfigMap => {
                let object = find(&self.config_maps, template_ref, |o: &ConfigMap| &o.metadata)?;
                let body = config_map_body(&object)?;
                (object.metadata.clone(), body)
            }
            SourceKind::Secret => {
                let object = find(&self.secrets, template_ref, |o: &Secret| &o.metadata)?;
                let body = secret_body(&object)?;
                (object.metadata.clone(), body)
            }
        };
        let (labels, annotations) = copied_metadata(&meta);
        Some(Template {
            labels,
            annotations,
            body,
        })
    }
}

fn find<K>(
    store: &Store<K>,
    template_ref: &TemplateRef,
    meta: impl Fn(&K) -> &ObjectMeta,
) -> Option<K>
where
    K: Resource<DynamicType = ()> + Clone + 'static,
{
    store
        .state()
        .into_iter()
        .find(|object| {
            let meta = meta(object);
            meta.name.as_deref() == Some(template_ref.name.as_str())
                && meta.namespace.as_deref() == Some(template_ref.namespace.as_str())
        })
        .map(|object| (*object).clone())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use k8s_openapi::ByteString;

    use super::*;

    fn meta(labels: &[(&str, &str)], annotations: &[(&str, &str)]) -> ObjectMeta {
        let map = |pairs: &[(&str, &str)]| -> Option<BTreeMap<String, String>> {
            Some(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            )
        };
        ObjectMeta {
            labels: map(labels),
            annotations: map(annotations),
            ..ObjectMeta::default()
        }
    }

    #[test]
    fn the_automount_label_and_annotations_are_copied() {
        let (labels, annotations) = copied_metadata(&meta(
            &[("controller.devfile.io/mount-to-devworkspace", "true")],
            &[("controller.devfile.io/mount-as", "subpath")],
        ));
        assert_eq!(
            labels.get("controller.devfile.io/mount-to-devworkspace"),
            Some(&"true".to_string())
        );
        assert_eq!(
            annotations.get("controller.devfile.io/mount-as"),
            Some(&"subpath".to_string())
        );
    }

    #[test]
    fn this_operators_own_keys_are_never_copied_from_a_template() {
        // A template that hand-wrote `managed-by` would otherwise claim ownership of an object
        // this operator never wrote — and, worse, the copy would then carry a label the adapter
        // sets itself, making the diff depend on which of the two won.
        let (labels, annotations) = copied_metadata(&meta(
            &[("hardening.weebo.io/managed-by", "someone-else")],
            &[("hardening.weebo.io/profile", "made-up")],
        ));
        assert!(labels.is_empty(), "{labels:?}");
        assert!(annotations.is_empty(), "{annotations:?}");
    }

    #[test]
    fn kubectls_last_applied_annotation_is_stripped() {
        // For a Secret it is a second, stale copy of the credential; for anything it is a
        // guaranteed diff on every re-apply.
        let (_, annotations) = copied_metadata(&meta(
            &[],
            &[(
                "kubectl.kubernetes.io/last-applied-configuration",
                "{\"data\":{\".npmrc\":\"c2VjcmV0\"}}",
            )],
        ));
        assert!(annotations.is_empty(), "{annotations:?}");
    }

    #[test]
    fn an_object_with_no_metadata_maps_at_all_projects_to_empty_maps() {
        let (labels, annotations) = copied_metadata(&ObjectMeta::default());
        assert!(labels.is_empty());
        assert!(annotations.is_empty());
    }

    #[test]
    fn a_config_maps_body_carries_data_and_binary_data_and_nothing_else() {
        let object = ConfigMap {
            metadata: meta(&[("irrelevant", "yes")], &[]),
            data: Some(BTreeMap::from([(
                ".npmrc".to_string(),
                "registry=https://batlehub.internal/npm/".to_string(),
            )])),
            binary_data: Some(BTreeMap::from([(
                "bundle.crt".to_string(),
                ByteString(b"der".to_vec()),
            )])),
            ..ConfigMap::default()
        };
        let rendered: Value =
            serde_json::from_slice(&config_map_body(&object).unwrap().into_bytes()).unwrap();
        assert_eq!(
            rendered.as_object().map(serde_json::Map::len),
            Some(2),
            "only data and binaryData: {rendered}"
        );
        assert_eq!(
            rendered.pointer("/data/.npmrc").and_then(Value::as_str),
            Some("registry=https://batlehub.internal/npm/")
        );
    }

    #[test]
    fn a_config_map_with_no_data_at_all_still_has_a_body() {
        // Legal, and occasionally intentional. An empty body must be a body, not a `None` that
        // would read as "the template has not landed".
        let rendered: Value =
            serde_json::from_slice(&config_map_body(&ConfigMap::default()).unwrap().into_bytes())
                .unwrap();
        assert_eq!(rendered, serde_json::json!({}));
    }

    #[test]
    fn a_secrets_body_carries_data_and_type_but_never_string_data() {
        // `stringData` is write-only — the apiserver merges it into `data` and never serves it
        // back. Projecting it would make a template and its own copy disagree about which field
        // holds the payload, and the diff would rewrite the copy on every pass.
        let object = Secret {
            metadata: ObjectMeta::default(),
            data: Some(BTreeMap::from([(
                ".npmrc".to_string(),
                ByteString(b"//batlehub.internal/npm/:_authToken=t".to_vec()),
            )])),
            string_data: Some(BTreeMap::from([(
                "ignored".to_string(),
                "never-read".to_string(),
            )])),
            type_: Some("Opaque".to_string()),
            ..Secret::default()
        };
        let rendered: Value =
            serde_json::from_slice(&secret_body(&object).unwrap().into_bytes()).unwrap();
        assert_eq!(rendered.get("type").and_then(Value::as_str), Some("Opaque"));
        assert!(rendered.get("data").is_some());
        assert!(
            rendered.get("stringData").is_none(),
            "stringData must never reach a body: {rendered}"
        );
    }

    #[test]
    fn two_reads_of_the_same_object_produce_byte_identical_bodies() {
        // The property the whole diff rests on: `serde_json::Map` is ordered, so a body is a
        // stable rendering rather than one that depends on iteration order. Without it every
        // reconcile pass would see a changed body and rewrite every copy in the fleet.
        let object = ConfigMap {
            data: Some(BTreeMap::from([
                ("z".to_string(), "1".to_string()),
                ("a".to_string(), "2".to_string()),
                ("m".to_string(), "3".to_string()),
            ])),
            ..ConfigMap::default()
        };
        assert_eq!(
            config_map_body(&object).unwrap().into_bytes(),
            config_map_body(&object).unwrap().into_bytes()
        );
    }
}
