//! `NodeEnforcerView` implementation: the join of a workspace's pods against their nodes'
//! `kubearmor.io/enforcer` labels, behind one port.
//!
//! This is the adapter RFC 0006 spends its *Architecture* asymmetry paragraph on. Two watches,
//! both read-only, both projected down before anything is stored:
//!
//! - **`Pod`**, filtered server-side to workspace pods (`controller.devfile.io/devworkspace_id`)
//!   and projected to `{namespace, workspace_id, node_name}` — never the spec, never the env,
//!   never a mounted volume. Per RFC 0006's *Security considerations → Secrets*: "The `Pod` watch
//!   reads labels and annotations only... never the pod spec, never env vars, never mounted
//!   volumes." `spec.nodeName` is the one spec field that travels, and it travels because the
//!   join has no other way to name the node.
//! - **`Node`**, **cluster-scoped** — this project's first watch outside its own CRD that is not
//!   namespaced — projected to `{name, enforcer_label}` and nothing else.
//!
//! The projection is done in the watch stream, before the reflector stores anything, so the
//! bounded-projection claim is a property of what is in memory rather than of how the reader
//! happens to be written. Kubernetes RBAC has no field-level grant for `Node`, so this boundary
//! is in code and reviewed as code — the same trade `NamespaceFacts` already accepts.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use k8s_openapi::api::core::v1::{Node, Pod};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};
use weebo_si_crd::{DEVWORKSPACE_ID_LABEL, KUBEARMOR_ENFORCER_LABEL, NamespaceName};
use weebo_si_kubearmor_policy::{Enforcement, EnforcementSubjects, NodeEnforcerView};

/// One workspace pod, projected to the three strings the join needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PodFacts {
    namespace: String,
    workspace_id: String,
    node_name: Option<String>,
}

/// Strip a `Pod` down to what the join reads, in the watch stream, before it reaches the store.
///
/// Everything not named here is dropped: containers, volumes, env, status, annotations. A
/// reviewer checking RFC 0006's "never the pod spec" claim reads this function and nothing else.
fn project_pod(pod: &mut Pod) {
    let node_name = pod.spec.as_ref().and_then(|spec| spec.node_name.clone());
    let workspace_id = pod
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(DEVWORKSPACE_ID_LABEL).cloned());

    pod.spec = None;
    pod.status = None;
    pod.metadata.annotations = None;
    pod.metadata.managed_fields = None;
    pod.metadata.owner_references = None;
    pod.metadata.finalizers = None;

    // The two values that must survive, carried in the one place a projected object still has:
    // its own labels. `node_name` is not a label on the real object — writing it into the
    // projection is what lets `spec` be dropped entirely.
    let mut labels = std::collections::BTreeMap::new();
    if let Some(workspace_id) = workspace_id {
        labels.insert(DEVWORKSPACE_ID_LABEL.to_string(), workspace_id);
    }
    if let Some(node_name) = node_name {
        labels.insert(PROJECTED_NODE_NAME_KEY.to_string(), node_name);
    }
    pod.metadata.labels = Some(labels);
}

/// The key `project_pod` stashes `spec.nodeName` under inside the projected object's labels.
/// Not a real label on any object in the cluster — the leading `_` makes it invalid as a
/// Kubernetes label key, so it can never collide with one the apiserver would accept.
const PROJECTED_NODE_NAME_KEY: &str = "_projected/node-name";

/// Strip a `Node` down to its name and the one label this brick reads.
fn project_node(node: &mut Node) {
    let enforcer = node
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(KUBEARMOR_ENFORCER_LABEL).cloned());

    node.spec = None;
    node.status = None;
    node.metadata.annotations = None;
    node.metadata.managed_fields = None;
    node.metadata.owner_references = None;

    let mut labels = std::collections::BTreeMap::new();
    if let Some(enforcer) = enforcer {
        labels.insert(KUBEARMOR_ENFORCER_LABEL.to_string(), enforcer);
    }
    node.metadata.labels = Some(labels);
}

/// Read the enforcement state out of a node's projected label. An absent or empty label is
/// [`Enforcement::NotEnforced`] — KubeArmor's own way of saying it found no usable LSM there, and
/// per RFC 0006 a state that must be *visible*, not silent.
fn enforcement_from_label(enforcer: Option<&String>) -> Enforcement {
    match enforcer.map(String::as_str) {
        Some(value) if !value.is_empty() => Enforcement::Enforced(value.to_string()),
        _ => Enforcement::NotEnforced,
    }
}

/// Watch-backed join of workspace pods against their nodes' enforcer labels.
pub struct KubeNodeEnforcerView {
    pods: Store<Pod>,
    nodes: Store<Node>,
    /// Node name → enforcer label, rebuilt on read from the node store. Held behind a lock only
    /// so a read can memoise it within one call; never a second source of truth.
    scratch: Arc<RwLock<HashMap<String, String>>>,
}

impl KubeNodeEnforcerView {
    /// Start both watches — workspace pods cluster-wide (label-filtered server-side) and every
    /// node — and block until both initial lists complete.
    pub async fn spawn(client: Client) -> Result<Self, kube::Error> {
        let pods: Api<Pod> = Api::all(client.clone());
        let (pod_reader, pod_writer) = reflector::store();
        let pod_config = watcher::Config::default().labels(DEVWORKSPACE_ID_LABEL);
        let pod_stream =
            reflector::reflector(pod_writer, watcher(pods, pod_config).modify(project_pod))
                .default_backoff();
        tokio::spawn(async move {
            use futures_util::StreamExt;
            let mut stream = std::pin::pin!(pod_stream);
            while stream.next().await.is_some() {}
        });

        let nodes: Api<Node> = Api::all(client);
        let (node_reader, node_writer) = reflector::store();
        let node_stream = reflector::reflector(
            node_writer,
            watcher(nodes, watcher::Config::default()).modify(project_node),
        )
        .default_backoff();
        tokio::spawn(async move {
            use futures_util::StreamExt;
            let mut stream = std::pin::pin!(node_stream);
            while stream.next().await.is_some() {}
        });

        for ready in [
            pod_reader.wait_until_ready().await,
            node_reader.wait_until_ready().await,
        ] {
            ready.map_err(|err| {
                kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                    err.to_string(),
                ))
            })?;
        }

        Ok(Self {
            pods: pod_reader,
            nodes: node_reader,
            scratch: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn pod_facts(&self, ns: &NamespaceName, workspace_id: &str) -> Option<PodFacts> {
        self.pods.state().iter().find_map(|pod| {
            let labels = pod.metadata.labels.as_ref()?;
            let id = labels.get(DEVWORKSPACE_ID_LABEL)?;
            if id != workspace_id || pod.metadata.namespace.as_deref() != Some(ns.as_str()) {
                return None;
            }
            Some(PodFacts {
                namespace: ns.as_str().to_string(),
                workspace_id: id.clone(),
                node_name: labels.get(PROJECTED_NODE_NAME_KEY).cloned(),
            })
        })
    }

    fn enforcer_for_node(&self, node_name: &str) -> Option<String> {
        {
            let cached = self
                .scratch
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(value) = cached.get(node_name) {
                return Some(value.clone());
            }
        }
        let found = self.nodes.state().iter().find_map(|node| {
            if node.metadata.name.as_deref() != Some(node_name) {
                return None;
            }
            node.metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(KUBEARMOR_ENFORCER_LABEL).cloned())
        })?;
        self.scratch
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(node_name.to_string(), found.clone());
        Some(found)
    }

    fn clear_memo(&self) {
        self.scratch
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    fn running_workspaces(&self) -> Vec<(NamespaceName, String)> {
        let mut seen = Vec::new();
        for pod in self.pods.state().iter() {
            let (Some(namespace), Some(labels)) = (
                pod.metadata.namespace.as_deref(),
                pod.metadata.labels.as_ref(),
            ) else {
                continue;
            };
            let Some(id) = labels.get(DEVWORKSPACE_ID_LABEL) else {
                continue;
            };
            let entry = (NamespaceName::new(namespace.to_string()), id.clone());
            if !seen.contains(&entry) {
                seen.push(entry);
            }
        }
        seen
    }
}

/// The roster the controller's gauge tick iterates, so it never has to list pods itself — both
/// answers come from the same watch caches the join already holds.
impl EnforcementSubjects for KubeNodeEnforcerView {
    fn workspaces(&self) -> Vec<(NamespaceName, String)> {
        self.running_workspaces()
    }

    /// Drop the memoised node→enforcer answers, so a node relabelled by KubeArmor's operator (an
    /// LSM that became available after a reboot, or one that stopped being) is picked up on the
    /// next sweep rather than never.
    fn invalidate(&self) {
        self.clear_memo();
    }
}

impl NodeEnforcerView for KubeNodeEnforcerView {
    fn enforcement(&self, ns: &NamespaceName, workspace_id: &str) -> Enforcement {
        // No pod, or a pod the scheduler has not placed yet: `Unknown`, never a `0`. The gauge
        // publishes no sample at all rather than one that reads as "this workspace is
        // unenforced".
        let Some(facts) = self.pod_facts(ns, workspace_id) else {
            return Enforcement::Unknown;
        };
        let Some(node_name) = facts.node_name else {
            return Enforcement::Unknown;
        };
        // A node that is not in the cache is also `Unknown` rather than `NotEnforced`: "we have
        // not seen that node" and "that node cannot enforce" are different claims, and only the
        // second one should ever page anybody.
        if !self
            .nodes
            .state()
            .iter()
            .any(|node| node.metadata.name.as_deref() == Some(node_name.as_str()))
        {
            return Enforcement::Unknown;
        }
        enforcement_from_label(self.enforcer_for_node(&node_name).as_ref())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use k8s_openapi::api::core::v1::{NodeSpec, NodeStatus, PodSpec, PodStatus};
    use kube::api::ObjectMeta;

    use super::*;

    fn workspace_pod() -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some("workspace-pod".to_string()),
                namespace: Some("user-alice".to_string()),
                labels: Some(
                    [(
                        DEVWORKSPACE_ID_LABEL.to_string(),
                        "workspacede4f56".to_string(),
                    )]
                    .into(),
                ),
                annotations: Some([("secret-ish".to_string(), "value".to_string())].into()),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec {
                node_name: Some("node-1".to_string()),
                ..PodSpec::default()
            }),
            status: Some(PodStatus::default()),
        }
    }

    #[test]
    fn projecting_a_pod_drops_the_spec_and_keeps_the_node_name() {
        // RFC 0006's *Secrets*: "never the pod spec, never env vars, never mounted volumes."
        // The node name survives because the join has no other way to name the node.
        let mut pod = workspace_pod();
        project_pod(&mut pod);
        assert!(pod.spec.is_none(), "the spec must not reach the store");
        assert!(pod.status.is_none());
        assert!(pod.metadata.annotations.is_none());
        let labels = pod.metadata.labels.unwrap();
        assert_eq!(
            labels.get(PROJECTED_NODE_NAME_KEY).map(String::as_str),
            Some("node-1")
        );
        assert_eq!(
            labels.get(DEVWORKSPACE_ID_LABEL).map(String::as_str),
            Some("workspacede4f56")
        );
    }

    #[test]
    fn the_projected_node_name_key_can_never_collide_with_a_real_label() {
        // A Kubernetes label key's name part must start with an alphanumeric, so no object in a
        // cluster can carry this key — the projection cannot be spoofed by labelling a pod.
        assert!(PROJECTED_NODE_NAME_KEY.starts_with('_'));
    }

    #[test]
    fn an_unscheduled_pod_projects_with_no_node_name() {
        let mut pod = workspace_pod();
        pod.spec = Some(PodSpec::default());
        project_pod(&mut pod);
        assert!(
            !pod.metadata
                .labels
                .unwrap()
                .contains_key(PROJECTED_NODE_NAME_KEY)
        );
    }

    #[test]
    fn projecting_a_node_keeps_only_the_enforcer_label() {
        let mut node = Node {
            metadata: ObjectMeta {
                name: Some("node-1".to_string()),
                labels: Some(
                    [
                        (KUBEARMOR_ENFORCER_LABEL.to_string(), "bpf".to_string()),
                        (
                            "topology.kubernetes.io/region".to_string(),
                            "eu-west".to_string(),
                        ),
                    ]
                    .into(),
                ),
                ..ObjectMeta::default()
            },
            spec: Some(NodeSpec::default()),
            status: Some(NodeStatus::default()),
        };
        project_node(&mut node);
        assert!(node.spec.is_none());
        assert!(node.status.is_none());
        let labels = node.metadata.labels.unwrap();
        assert_eq!(labels.len(), 1, "one label out, nothing else: {labels:?}");
        assert_eq!(
            labels.get(KUBEARMOR_ENFORCER_LABEL).map(String::as_str),
            Some("bpf")
        );
    }

    #[test]
    fn a_node_naming_its_lsm_is_enforced_and_the_gauge_reads_one() {
        let enforcement = enforcement_from_label(Some(&"apparmor".to_string()));
        assert_eq!(enforcement, Enforcement::Enforced("apparmor".to_string()));
        assert_eq!(enforcement.gauge(), Some(1.0));
    }

    #[test]
    fn a_node_with_no_enforcer_label_is_not_enforced_rather_than_unknown() {
        // The node is in the cache and KubeArmor found nothing usable there. That is a fact
        // worth a `0`, not a missing sample.
        assert_eq!(enforcement_from_label(None), Enforcement::NotEnforced);
    }

    #[test]
    fn an_empty_enforcer_label_is_treated_as_no_enforcer() {
        assert_eq!(
            enforcement_from_label(Some(&String::new())),
            Enforcement::NotEnforced
        );
    }
}
