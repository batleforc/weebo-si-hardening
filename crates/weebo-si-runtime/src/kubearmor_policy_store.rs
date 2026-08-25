//! `PolicyStore` implementation for `KubeArmorPolicy`: server-side apply, one field manager, a
//! label-filtered cluster-wide watch. Mirrors [`crate::kube_policy_store`] for
//! `kubearmor-policy`, per RFC 0006's *Design* and RFC 0004's *Security considerations*, "The
//! label is the ownership boundary."

use std::future::Future;
use std::pin::Pin;

use kube::Client;
use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use serde_json::{Value, json};
use weebo_si_chassis::DomainError;
use weebo_si_crd::{
    BACKEND_LABEL, DEVWORKSPACE_ID_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName,
    PROFILE_LABEL, RuntimeBackend, RuntimeProfileKey,
};
use weebo_si_kubearmor_policy::{
    Applied, BaselineView, Diff, ManagedObject, ObjectKey, PodSelector, PolicyStore, RuleBody,
};

use crate::kubearmor_template_store::{SELECTOR_FIELD, kubearmor_policy_resource};

/// Every write from this adapter goes through server-side apply under this one manager — the
/// same one `network-profiles`' store uses, since a rolling update of one operator must never
/// produce two managers fighting over objects it alone writes.
const FIELD_MANAGER: &str = "weebo-si-operator";

/// The `apiVersion` every object this adapter writes carries.
const API_VERSION: &str = "security.kubearmor.com/v1";

fn backend_label_value(backend: RuntimeBackend) -> &'static str {
    match backend {
        RuntimeBackend::KubeArmor => "KubeArmor",
    }
}

/// The `selector` a managed object is written with.
///
/// `PodSelector::Empty` becomes `{"matchLabels": {}}` rather than `{}`: KubeArmor's own CRD makes
/// `matchLabels` the selector's only shape, and an empty map selects **every pod in the policy's
/// own namespace** — which is exactly the baseline's meaning, and is why the baseline needs no
/// label of its own to select on.
///
/// The distinction matters more than it looks: if an empty map selected *nothing*, every
/// namespace baseline this operator writes would be silently inert while every metric read
/// healthy — the failure mode RFC 0006's *Bypass* section is about. It is confirmed behaviour,
/// not an inference from the CRD schema, which is why it is written down here rather than left
/// to the shape of the JSON.
fn selector_json(pod_selector: &PodSelector) -> Value {
    match pod_selector {
        PodSelector::Empty => json!({"matchLabels": {}}),
        PodSelector::DevWorkspaceId(id) => json!({"matchLabels": {DEVWORKSPACE_ID_LABEL: id}}),
    }
}

/// The pod selector a live object actually carries, read back from its own `selector.matchLabels`.
/// Anything that is not the one workspace-scoped shape this adapter writes reads back as
/// [`PodSelector::Empty`] — a foreign object could never carry the management label in the first
/// place (the watch is label-filtered), so this only has to recognise this adapter's own output.
fn pod_selector_from_match_labels(value: Option<&Value>) -> PodSelector {
    let id = value
        .and_then(|v| v.get("matchLabels"))
        .and_then(|labels| labels.get(DEVWORKSPACE_ID_LABEL))
        .and_then(Value::as_str);
    match id {
        Some(id) => PodSelector::DevWorkspaceId(id.to_string()),
        None => PodSelector::Empty,
    }
}

fn labels_json(profile: &RuntimeProfileKey, backend: RuntimeBackend) -> Value {
    json!({
        MANAGED_BY_LABEL: MANAGED_BY_VALUE,
        PROFILE_LABEL: profile.as_str(),
        BACKEND_LABEL: backend_label_value(backend),
    })
}

/// Watch-backed `PolicyStore` over `KubeArmorPolicy`, cluster-wide, filtered server-side to this
/// operator's own managed objects.
pub struct KubeArmorPolicyStore {
    client: Client,
    policies: Store<DynamicObject>,
}

impl KubeArmorPolicyStore {
    /// Start watching every managed `KubeArmorPolicy`, cluster-wide. Blocks until the initial
    /// list completes.
    pub async fn spawn(client: Client) -> Result<Self, kube::Error> {
        let label_selector = format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}");
        let resource = kubearmor_policy_resource();
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
        let writer = reflector::store::Writer::<DynamicObject>::new(resource);
        let reader = writer.as_reader();
        let watcher_config = watcher::Config::default().labels(&label_selector);
        let stream = reflector::reflector(writer, watcher(api, watcher_config)).default_backoff();
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

        Ok(Self {
            client,
            policies: reader,
        })
    }

    fn from_object(obj: &DynamicObject) -> Option<ManagedObject> {
        let labels = obj.metadata.labels.as_ref()?;
        let profile = RuntimeProfileKey::new(labels.get(PROFILE_LABEL)?.clone());
        let mut spec = obj.data.get("spec")?.clone();
        let pod_selector = pod_selector_from_match_labels(spec.get(SELECTOR_FIELD));
        if let Value::Object(map) = &mut spec {
            map.remove(SELECTOR_FIELD);
        }
        Some(ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new(obj.metadata.namespace.clone()?),
                name: obj.metadata.name.clone()?,
            },
            backend: RuntimeBackend::KubeArmor,
            profile,
            pod_selector,
            body: RuleBody::opaque(serde_json::to_vec(&spec).ok()?),
        })
    }

    async fn apply_object(&self, obj: &ManagedObject) -> Result<(), DomainError> {
        let mut spec: Value = serde_json::from_slice(obj.body.as_bytes())
            .map_err(|err| DomainError::PortFailed(format!("malformed rule body: {err}")))?;
        if let Value::Object(map) = &mut spec {
            map.insert(SELECTOR_FIELD.to_string(), selector_json(&obj.pod_selector));
        }
        let apply = json!({
            "apiVersion": API_VERSION,
            "kind": "KubeArmorPolicy",
            "metadata": {
                "name": obj.key.name,
                "namespace": obj.key.namespace.as_str(),
                "labels": labels_json(&obj.profile, obj.backend),
            },
            "spec": spec,
        });
        let resource = kubearmor_policy_resource();
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), obj.key.namespace.as_str(), &resource);
        api.patch(
            &obj.key.name,
            // `.force()`, and this is a deliberate difference from `network-profiles`' store,
            // found by the envtest suite rather than reasoned about in advance.
            //
            // Server-side apply refuses to overwrite a field another manager owns. The moment
            // someone runs `kubectl edit` on a managed object, that someone becomes the manager
            // of the fields they touched, and every subsequent apply from this controller fails
            // with a 409 — which means **the drift this brick exists to correct is exactly the
            // drift it would stop being able to correct**, permanently, with the object left in
            // the edited state and a reconcile error on every pass.
            //
            // `network-profiles` can afford not to force because `policy-guard` denies that edit
            // at admission before a field manager is ever created. Nothing guards
            // `kubearmorpolicies` today (see RFC 0006's *Unresolved questions*), so this store
            // must be able to put its own object back on its own. Forcing is safe in exactly the
            // way the label makes it safe: this adapter only ever applies to objects it built,
            // in namespaces this feature reconciles, carrying its own managed-by label.
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(apply),
        )
        .await
        .map_err(|err| DomainError::PortFailed(err.to_string()))?;
        Ok(())
    }

    async fn delete(&self, key: &ObjectKey, backend: RuntimeBackend) -> Result<(), DomainError> {
        match backend {
            RuntimeBackend::KubeArmor => {}
        }
        let resource = kubearmor_policy_resource();
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), key.namespace.as_str(), &resource);
        match api.delete(&key.name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            // Deleting an object that is already gone is the outcome we wanted, not a failure —
            // this is what keeps a repeated Enforce pass over a namespace idempotent.
            Err(kube::Error::Api(err)) if err.code == 404 => Ok(()),
            Err(err) => Err(DomainError::PortFailed(err.to_string())),
        }
    }
}

/// The baseline is the object whose selector governs *every* pod in the namespace — read off
/// [`PodSelector`] rather than off the object's name, so a rename in the naming scheme cannot
/// silently turn this check into "always false".
impl BaselineView for KubeArmorPolicyStore {
    fn has_baseline(&self, ns: &NamespaceName) -> bool {
        self.managed_in(ns)
            .iter()
            .any(|obj| obj.pod_selector == PodSelector::Empty)
    }
}

impl PolicyStore for KubeArmorPolicyStore {
    fn managed_in(&self, ns: &NamespaceName) -> Vec<ManagedObject> {
        self.policies
            .state()
            .iter()
            .filter(|obj| obj.metadata.namespace.as_deref() == Some(ns.as_str()))
            .filter_map(|obj| Self::from_object(obj))
            .collect()
    }

    /// Free: the watch cache already holds exactly this population, filtered server-side by the
    /// ownership label — so "everything this operator owns, cluster-wide" costs no apiserver
    /// round-trip, which is what makes recomputing the gauge from a full snapshot affordable.
    fn managed_everywhere(&self) -> Vec<ManagedObject> {
        self.policies
            .state()
            .iter()
            .filter_map(|obj| Self::from_object(obj))
            .collect()
    }

    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>> {
        Box::pin(async move {
            for diff in diffs {
                match diff {
                    Diff::Create(obj) | Diff::Update(obj) => self.apply_object(obj).await?,
                    Diff::Delete { key, backend } => self.delete(key, *backend).await?,
                    Diff::Unchanged(_) => {}
                }
            }
            Ok(weebo_si_kubearmor_policy::tally(diffs))
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
    fn the_baseline_selector_is_an_empty_match_labels_not_an_empty_selector() {
        // KubeArmor's CRD makes `matchLabels` the selector's only shape. `{}` would be a
        // selector with no `matchLabels` at all, which is not the same document.
        assert_eq!(
            selector_json(&PodSelector::Empty),
            json!({"matchLabels": {}})
        );
    }

    #[test]
    fn a_workspace_selector_names_the_devworkspace_id_label() {
        assert_eq!(
            selector_json(&PodSelector::DevWorkspaceId("workspacede4f56".to_string())),
            json!({"matchLabels": {"controller.devfile.io/devworkspace_id": "workspacede4f56"}})
        );
    }

    #[test]
    fn a_selector_round_trips_through_the_shape_this_adapter_writes_and_reads_back() {
        // The property the diff depends on: an object this adapter wrote, read back from the
        // watch cache, must produce the same `PodSelector` it was built from — otherwise every
        // reconcile pass sees a selector change and rewrites every policy in the fleet.
        for selector in [
            PodSelector::Empty,
            PodSelector::DevWorkspaceId("workspacede4f56".to_string()),
        ] {
            let written = selector_json(&selector);
            assert_eq!(pod_selector_from_match_labels(Some(&written)), selector);
        }
    }

    #[test]
    fn an_object_with_no_selector_at_all_reads_back_as_the_baseline_selector() {
        assert_eq!(pod_selector_from_match_labels(None), PodSelector::Empty);
    }

    #[test]
    fn the_managed_labels_carry_ownership_provenance_and_dialect() {
        assert_eq!(
            labels_json(
                &RuntimeProfileKey::new("git-write"),
                RuntimeBackend::KubeArmor
            ),
            json!({
                "hardening.weebo.io/managed-by": "weebo-si-operator",
                "hardening.weebo.io/profile": "git-write",
                "hardening.weebo.io/backend": "KubeArmor",
            })
        );
    }
}
