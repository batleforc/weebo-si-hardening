//! The template cache: the five template kinds in the template namespace (RFC 0020, *Data and
//! state*), as [`ToolTemplate`] values. A static cache: `/readyz` waits for it, nothing else.

use kube::Client;
use kube::api::{Api, DynamicObject};
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::{WatchStreamExt, watcher};
use serde_json::Value;
use weebo_si_crd::{NamespaceName, ToolTemplateRef};
use weebo_si_team_tools::{ToolObjectKind, ToolTemplate, ToolTemplateStore};

use crate::objects::resource;

/// The kinds a template may be (RFC 0020, *Validation*). A `Certificate` is generated, never
/// templated (Resolved, 10).
const TEMPLATE_KINDS: [ToolObjectKind; 5] = [
    ToolObjectKind::Deployment,
    ToolObjectKind::StatefulSet,
    ToolObjectKind::Service,
    ToolObjectKind::ConfigMap,
    ToolObjectKind::CiliumNetworkPolicy,
];

/// Start a namespaced reflector of `kind` and return its reader. Does not wait for the list.
pub(crate) fn spawn_reflector(
    client: Client,
    namespace: Option<&str>,
    kind: ToolObjectKind,
    config: watcher::Config,
    component: &'static str,
) -> (Store<DynamicObject>, tokio::task::JoinHandle<()>) {
    let resource = resource(kind);
    let api: Api<DynamicObject> = match namespace {
        Some(namespace) => Api::namespaced_with(client, namespace, &resource),
        None => Api::all_with(client, &resource),
    };
    let writer = reflector::store::Writer::<DynamicObject>::new(resource);
    let reader = writer.as_reader();
    let stream = reflector::reflector(writer, watcher(api, config)).default_backoff();
    let task = tokio::spawn(weebo_si_runtime::watch::drive(component, stream));
    (reader, task)
}

/// The templates, one watch per kind.
pub struct KubeToolTemplateStore {
    namespace: NamespaceName,
    stores: Vec<(ToolObjectKind, Store<DynamicObject>)>,
}

impl KubeToolTemplateStore {
    /// Watch the template kinds in `namespace` (`CiliumNetworkPolicy` only when the CRD is
    /// served). Blocks until every initial list completes.
    pub async fn spawn(
        client: Client,
        namespace: &NamespaceName,
        cilium: bool,
    ) -> Result<Self, kube::Error> {
        let mut stores = Vec::new();
        for kind in TEMPLATE_KINDS {
            if kind == ToolObjectKind::CiliumNetworkPolicy && !cilium {
                continue;
            }
            let (reader, _task) = spawn_reflector(
                client.clone(),
                Some(namespace.as_str()),
                kind,
                watcher::Config::default(),
                "team-tool-templates",
            );
            reader.wait_until_ready().await.map_err(|err| {
                kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                    err.to_string(),
                ))
            })?;
            stores.push((kind, reader));
        }
        Ok(Self {
            namespace: namespace.clone(),
            stores,
        })
    }

    /// Every cached template's `kind/name@resourceVersion` (one namespace), for the controller's
    /// change trigger.
    pub fn versions(&self) -> Vec<String> {
        self.stores
            .iter()
            .flat_map(|(kind, store)| {
                store.state().into_iter().map(move |object| {
                    format!(
                        "{}/{}@{}",
                        kind.as_str(),
                        object.metadata.name.as_deref().unwrap_or_default(),
                        object
                            .metadata
                            .resource_version
                            .as_deref()
                            .unwrap_or_default()
                    )
                })
            })
            .collect()
    }
}

/// A template object as the domain reads it.
pub(crate) fn to_template(kind: ToolObjectKind, object: &DynamicObject) -> Option<ToolTemplate> {
    let mut body = match &object.data {
        Value::Object(body) => body.clone(),
        _ => serde_json::Map::new(),
    };
    body.remove("status");
    Some(ToolTemplate {
        kind: kind.as_str().to_string(),
        name: object.metadata.name.clone()?,
        namespace: NamespaceName::new(object.metadata.namespace.clone()?),
        labels: object.metadata.labels.clone().unwrap_or_default(),
        annotations: object.metadata.annotations.clone().unwrap_or_default(),
        body: Value::Object(body),
    })
}

impl ToolTemplateStore for KubeToolTemplateStore {
    fn template(&self, template: &ToolTemplateRef) -> Option<ToolTemplate> {
        if template.namespace != self.namespace {
            return None;
        }
        let kind = ToolObjectKind::from_kind(&template.kind)?;
        let (_, store) = self
            .stores
            .iter()
            .find(|(candidate, _)| *candidate == kind)?;
        let reference =
            ObjectRef::new_with(&template.name, resource(kind)).within(self.namespace.as_str());
        to_template(kind, store.get(&reference)?.as_ref())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_template_keeps_its_body_and_drops_its_status() {
        let object: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": "buildkitd", "namespace": "weebo-si-hardening-templates",
                         "labels": {"app": "buildkitd"}},
            "spec": {"replicas": 0},
            "status": {"replicas": 0},
        }))
        .unwrap();
        let template = to_template(ToolObjectKind::StatefulSet, &object).unwrap();
        assert_eq!(template.kind, "StatefulSet");
        assert_eq!(template.body, json!({"spec": {"replicas": 0}}));
        assert_eq!(
            template.labels.get("app").map(String::as_str),
            Some("buildkitd")
        );
    }
}
