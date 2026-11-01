//! The two stores of RFC 0014's *Data and state*, over watch caches:
//!
//! * [`KubeQuotaTemplateStore`]: `ResourceQuota` and `LimitRange` in the template namespace only.
//! * [`KubeManagedQuotaStore`]: the managed copies cluster-wide, filtered server-side by the
//!   management label, plus a metadata-only watch of every quota and `LimitRange` to count the
//!   foreign ones. A metadata watch carries no `spec`, and those objects are small and rare.
//!
//! Writes are server-side apply under [`FIELD_MANAGER`], forced, and deletes re-read the live
//! object and pin the delete to its uid, like every other store in this operator.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use k8s_openapi::api::core::v1::{LimitRange, ResourceQuota};
use kube::api::{Api, DeleteParams, Patch, PatchParams};
use kube::core::PartialObjectMeta;
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, Resource};
use serde_json::{Value, json};
use weebo_si_chassis::managed::{Applied, Diff, tally};
use weebo_si_chassis::{DomainError, ObjectKey};
use weebo_si_crd::{
    MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, PROFILE_LABEL, QuotaProfileKey, TemplateRef,
};
use weebo_si_resource_quotas::{
    FIELD_MANAGER, ForeignObjects, LimitRangeTemplate, ManagedQuotaObject, ManagedQuotaStore,
    QuotaKind, QuotaTemplate, QuotaTemplateStore, QuotaUsage,
};

/// `spec` of an object, as the JSON the domain copies.
fn spec_of<K: serde::Serialize>(spec: Option<&K>) -> Value {
    spec.and_then(|spec| serde_json::to_value(spec).ok())
        .unwrap_or_else(|| json!({}))
}

async fn spawn_reflector<K>(
    api: Api<K>,
    config: watcher::Config,
    component: &'static str,
) -> Result<Store<K>, kube::Error>
where
    K: Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + serde::de::DeserializeOwned
        + 'static,
{
    let (reader, writer) = reflector::store::<K>();
    let stream = reflector::reflector(writer, watcher(api, config)).default_backoff();
    tokio::spawn(weebo_si_runtime::watch::drive(component, stream));
    reader.wait_until_ready().await.map_err(|err| {
        kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
            err.to_string(),
        ))
    })?;
    Ok(reader)
}

/// The templates, from the template namespace.
pub struct KubeQuotaTemplateStore {
    namespace: NamespaceName,
    quotas: Store<ResourceQuota>,
    limit_ranges: Store<LimitRange>,
}

impl KubeQuotaTemplateStore {
    /// Watch `ResourceQuota` and `LimitRange` in `namespace`. Blocks until both lists complete.
    pub async fn spawn(client: Client, namespace: &NamespaceName) -> Result<Self, kube::Error> {
        let quotas = spawn_reflector(
            Api::<ResourceQuota>::namespaced(client.clone(), namespace.as_str()),
            watcher::Config::default(),
            "quota-templates",
        )
        .await?;
        let limit_ranges = spawn_reflector(
            Api::<LimitRange>::namespaced(client, namespace.as_str()),
            watcher::Config::default(),
            "limitrange-templates",
        )
        .await?;
        Ok(Self {
            namespace: namespace.clone(),
            quotas,
            limit_ranges,
        })
    }

    /// The two caches, for a trigger that re-reconciles every namespace when a template changes.
    pub fn stores(&self) -> (Store<ResourceQuota>, Store<LimitRange>) {
        (self.quotas.clone(), self.limit_ranges.clone())
    }
}

impl QuotaTemplateStore for KubeQuotaTemplateStore {
    fn quota(&self, template: &TemplateRef) -> Option<QuotaTemplate> {
        if template.namespace != self.namespace {
            return None;
        }
        let object = self
            .quotas
            .get(&reflector::ObjectRef::new(&template.name).within(self.namespace.as_str()))?;
        Some(QuotaTemplate {
            spec: spec_of(object.spec.as_ref()),
        })
    }

    fn limit_range(&self, template: &TemplateRef) -> Option<LimitRangeTemplate> {
        if template.namespace != self.namespace {
            return None;
        }
        let object = self
            .limit_ranges
            .get(&reflector::ObjectRef::new(&template.name).within(self.namespace.as_str()))?;
        Some(LimitRangeTemplate {
            spec: spec_of(object.spec.as_ref()),
        })
    }
}

/// The managed copies and the foreign counts.
pub struct KubeManagedQuotaStore {
    client: Client,
    quotas: Store<ResourceQuota>,
    limit_ranges: Store<LimitRange>,
    all_quotas: Store<PartialObjectMeta<ResourceQuota>>,
    all_limit_ranges: Store<PartialObjectMeta<LimitRange>>,
}

fn managed_label(labels: Option<&BTreeMap<String, String>>) -> bool {
    labels
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .is_some_and(|value| value == MANAGED_BY_VALUE)
}

impl KubeManagedQuotaStore {
    /// Start the four watches. Blocks until every initial list completes.
    pub async fn spawn(client: Client) -> Result<Self, kube::Error> {
        let managed =
            watcher::Config::default().labels(&format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}"));
        let quotas = spawn_reflector(
            Api::<ResourceQuota>::all(client.clone()),
            managed.clone(),
            "managed-quotas",
        )
        .await?;
        let limit_ranges = spawn_reflector(
            Api::<LimitRange>::all(client.clone()),
            managed,
            "managed-limitranges",
        )
        .await?;
        let all_quotas = spawn_reflector(
            Api::<PartialObjectMeta<ResourceQuota>>::all(client.clone()),
            watcher::Config::default(),
            "all-quotas",
        )
        .await?;
        let all_limit_ranges = spawn_reflector(
            Api::<PartialObjectMeta<LimitRange>>::all(client.clone()),
            watcher::Config::default(),
            "all-limitranges",
        )
        .await?;
        Ok(Self {
            client,
            quotas,
            limit_ranges,
            all_quotas,
            all_limit_ranges,
        })
    }

    /// The managed quota and `LimitRange` caches, for a trigger that puts an edited copy back.
    pub fn stores(&self) -> (Store<ResourceQuota>, Store<LimitRange>) {
        (self.quotas.clone(), self.limit_ranges.clone())
    }

    async fn apply_object(&self, object: &ManagedQuotaObject) -> Result<(), DomainError> {
        let document = apply_document(object);
        let params = PatchParams::apply(FIELD_MANAGER).force();
        let namespace = object.key.namespace.as_str();
        let result = match object.kind {
            QuotaKind::ResourceQuota => {
                Api::<ResourceQuota>::namespaced(self.client.clone(), namespace)
                    .patch(&object.key.name, &params, &Patch::Apply(document))
                    .await
                    .map(|_| ())
            }
            QuotaKind::LimitRange => Api::<LimitRange>::namespaced(self.client.clone(), namespace)
                .patch(&object.key.name, &params, &Patch::Apply(document))
                .await
                .map(|_| ()),
        };
        result.map_err(|err| {
            DomainError::PortFailed(format!("applying {}/{}: {err}", namespace, object.key.name))
        })
    }

    async fn delete(&self, key: &ObjectKey, kind: QuotaKind) -> Result<(), DomainError> {
        let namespace = key.namespace.as_str();
        match kind {
            QuotaKind::ResourceQuota => {
                delete(
                    &Api::<ResourceQuota>::namespaced(self.client.clone(), namespace),
                    &key.name,
                )
                .await
            }
            QuotaKind::LimitRange => {
                delete(
                    &Api::<LimitRange>::namespaced(self.client.clone(), namespace),
                    &key.name,
                )
                .await
            }
        }
    }
}

/// The apply document: the template's `spec` under a fixed name, with the two ownership labels and
/// nothing of the template's own metadata.
pub fn apply_document(object: &ManagedQuotaObject) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": object.kind.as_str(),
        "metadata": {
            "name": object.key.name,
            "namespace": object.key.namespace.as_str(),
            "labels": {
                MANAGED_BY_LABEL: MANAGED_BY_VALUE,
                PROFILE_LABEL: object.profile.as_str(),
            },
        },
        "spec": object.spec,
    })
}

async fn delete<K>(api: &Api<K>, name: &str) -> Result<(), DomainError>
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    // Re-read and pin to the uid: a same-named object somebody else created since the cache was
    // filled is not ours to delete.
    let live = match api.get_opt(name).await {
        Ok(Some(live)) => live,
        Ok(None) => return Ok(()),
        Err(err) => return Err(DomainError::PortFailed(err.to_string())),
    };
    if !managed_label(live.meta().labels.as_ref()) {
        tracing::warn!(
            "resource-quotas not deleting {name}: the live object does not carry \
             {MANAGED_BY_LABEL}={MANAGED_BY_VALUE}"
        );
        return Ok(());
    }
    let params = DeleteParams {
        preconditions: Some(kube::api::Preconditions {
            uid: live.meta().uid.clone(),
            resource_version: None,
        }),
        ..DeleteParams::default()
    };
    match api.delete(name, &params).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(err)) if err.code == 404 => Ok(()),
        Err(err) => Err(DomainError::PortFailed(err.to_string())),
    }
}

/// A live managed object back in the domain's shape. `None` for one without the profile label,
/// which this store then does not report as managed and the diff never touches.
fn managed_object<K: Resource>(
    object: &K,
    kind: QuotaKind,
    spec: Value,
) -> Option<ManagedQuotaObject> {
    let meta = object.meta();
    let profile = meta.labels.as_ref()?.get(PROFILE_LABEL)?;
    Some(ManagedQuotaObject {
        key: ObjectKey {
            namespace: NamespaceName::new(meta.namespace.clone()?),
            name: meta.name.clone()?,
        },
        kind,
        profile: QuotaProfileKey::new(profile.clone()),
        spec,
        uid: meta.uid.clone(),
    })
}

impl ManagedQuotaStore for KubeManagedQuotaStore {
    fn managed_in(&self, namespace: &NamespaceName) -> Vec<ManagedQuotaObject> {
        let here =
            |meta: &kube::api::ObjectMeta| meta.namespace.as_deref() == Some(namespace.as_str());
        let quotas = self
            .quotas
            .state()
            .into_iter()
            .filter(|object| here(&object.metadata))
            .filter_map(|object| {
                managed_object(
                    object.as_ref(),
                    QuotaKind::ResourceQuota,
                    spec_of(object.spec.as_ref()),
                )
            });
        let limits = self
            .limit_ranges
            .state()
            .into_iter()
            .filter(|object| here(&object.metadata))
            .filter_map(|object| {
                managed_object(
                    object.as_ref(),
                    QuotaKind::LimitRange,
                    spec_of(object.spec.as_ref()),
                )
            });
        quotas.chain(limits).collect()
    }

    fn usage_in(&self, namespace: &NamespaceName) -> Option<QuotaUsage> {
        let quota = self.quotas.get(
            &reflector::ObjectRef::new(weebo_si_resource_quotas::QUOTA_NAME)
                .within(namespace.as_str()),
        )?;
        let status = quota.status.as_ref()?;
        let render = |map: Option<
            &BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>,
        >| {
            map.map(|map| {
                map.iter()
                    .map(|(key, value)| (key.clone(), value.0.clone()))
                    .collect()
            })
            .unwrap_or_default()
        };
        Some(QuotaUsage {
            hard: render(status.hard.as_ref()),
            used: render(status.used.as_ref()),
        })
    }

    fn foreign_in(&self, namespace: &NamespaceName) -> ForeignObjects {
        let foreign = |meta: &kube::api::ObjectMeta| {
            meta.namespace.as_deref() == Some(namespace.as_str())
                && !managed_label(meta.labels.as_ref())
        };
        ForeignObjects {
            quotas: self
                .all_quotas
                .state()
                .iter()
                .filter(|object| foreign(&object.metadata))
                .count(),
            limit_ranges: self
                .all_limit_ranges
                .state()
                .iter()
                .filter(|object| foreign(&object.metadata))
                .count(),
        }
    }

    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff<ManagedQuotaObject>],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>> {
        Box::pin(async move {
            for diff in diffs {
                match diff {
                    Diff::Create(object) | Diff::Update(object) => {
                        self.apply_object(object).await?
                    }
                    Diff::Delete { key, backend, .. } => self.delete(key, *backend).await?,
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
    use super::*;

    #[test]
    fn the_apply_document_carries_the_spec_and_only_our_two_labels() {
        let object = ManagedQuotaObject::desired(
            &NamespaceName::new("user-bob"),
            QuotaKind::ResourceQuota,
            &QuotaProfileKey::new("standard"),
            json!({"hard": {"pods": "20"}}),
        );
        let document = apply_document(&object);
        assert_eq!(document["kind"], "ResourceQuota");
        assert_eq!(document["metadata"]["name"], "weebo-quota");
        assert_eq!(document["metadata"]["labels"].as_object().unwrap().len(), 2);
        assert_eq!(document["metadata"]["labels"][PROFILE_LABEL], "standard");
        assert_eq!(document["spec"]["hard"]["pods"], "20");
        assert!(document["metadata"].get("annotations").is_none());
    }

    #[test]
    fn only_the_management_label_makes_an_object_ours() {
        let labels = BTreeMap::from([(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string())]);
        assert!(managed_label(Some(&labels)));
        assert!(!managed_label(None));
        let other = BTreeMap::from([(MANAGED_BY_LABEL.to_string(), "someone".to_string())]);
        assert!(!managed_label(Some(&other)));
    }
}
