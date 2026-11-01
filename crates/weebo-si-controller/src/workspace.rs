//! What the reconcile loops over workspaces share: reading a `DevWorkspace`'s id and owner
//! reference, the `held` warning every template-driven feature logs, and how soon a namespace the
//! gate answered `Off` for is looked at again.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::Stream;

use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use weebo_si_chassis::managed::{ObjectKey, Owner};
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_crd::{DEVWORKSPACE_ID_LABEL, NamespaceName};

/// How soon a namespace the feature does not reach is looked at again.
pub const OFF_RECHECK: Duration = Duration::from_secs(60);

/// How soon a namespace the namespace index has not seen yet is looked at again.
pub const UNINDEXED_RECHECK: Duration = Duration::from_millis(500);

/// When to reconcile again a namespace the gate answered `Off` for, given whether the namespace
/// index held it **before** the gate was asked.
///
/// The gate reads the namespace's labels from the shared namespace index, a watch of its own. A
/// loop's watch can deliver a new namespace before that index has it, and the gate then answers
/// `Off` for a namespace the feature does reach. Waiting [`OFF_RECHECK`] then leaves a new
/// workspace namespace without its baseline for a minute: `perf_envtest` saw it for about 1% of
/// 500 namespaces created at once. A namespace the index had not seen is retried after half a
/// second instead (a retry costs one index lookup, and the lag it waits out is short); one it had
/// seen really is out of scope, and keeps the slow recheck.
///
/// Sample `indexed` before calling the gate, never after: the index can receive the namespace
/// between the two reads, and a lookup made after an `Off` would then read "seen" and pick the
/// slow recheck for exactly the namespace the gate could not see. Sampled first, "seen" means the
/// gate saw it too — a live namespace never leaves the index.
pub fn off_recheck(indexed: bool) -> Duration {
    if indexed {
        OFF_RECHECK
    } else {
        UNINDEXED_RECHECK
    }
}

/// How often [`config_changes`] looks at a feature's configuration handle.
pub const CONFIG_POLL: Duration = Duration::from_secs(2);

/// A stream that yields once each time `handle` holds a different value than at its last look —
/// for `Controller::reconcile_all_on`, so a feature that only watches `Namespace` objects
/// re-reconciles every namespace when its configuration changes.
///
/// Without it, a `mode: Off`, a new ceiling or a team's new level reaches a namespace only at its
/// next periodic requeue, minutes later. Polled rather than pushed: the handle is the one the
/// config store already rewrites on every sync, and comparing two clones every two seconds is the
/// whole cost.
pub fn config_changes<T>(handle: Arc<RwLock<Option<T>>>) -> impl Stream<Item = ()> + Send
where
    T: Clone + PartialEq + Send + Sync + 'static,
{
    let read = move || {
        handle
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    };
    let first = read();
    futures_util::stream::unfold((first, read), |(mut last, read)| async move {
        loop {
            tokio::time::sleep(CONFIG_POLL).await;
            let now = read();
            if now != last {
                last = now;
                return Some(((), (last, read)));
            }
        }
    })
}

/// Whether the namespace index holds `namespace` — the sample [`off_recheck`] takes.
pub fn indexed(view: &dyn NamespaceView, namespace: &NamespaceName) -> bool {
    view.facts(namespace).is_some()
}

/// The DevWorkspace's id — the value its pods carry as `controller.devfile.io/devworkspace_id`,
/// which every profile object selects on.
///
/// DevWorkspace Operator records it on the `DevWorkspace` itself as `status.devworkspaceId`, and
/// puts the label on the objects it *creates* (pods, Deployments, Services), not on the
/// `DevWorkspace`. Status first; the label is still honoured for an object that carries one.
/// `None` until DWO has assigned it.
pub fn devworkspace_id(obj: &DynamicObject) -> Option<String> {
    obj.data
        .pointer("/status/devworkspaceId")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| {
            obj.metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(DEVWORKSPACE_ID_LABEL))
                .filter(|id| !id.is_empty())
                .cloned()
        })
}

/// The `DevWorkspace` GVK, matching this repo's own convention (see
/// `charts/weebo-si-operator/templates/mutatingwebhookconfiguration.yaml`) rather than upstream
/// DevWorkspace Operator's actual group — consistent with every other reference to this resource
/// in this codebase.
pub fn devworkspace_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk("workspace.devfile.io", "v1alpha2", "DevWorkspace");
    ApiResource::from_gvk_with_plural(&gvk, "devworkspaces")
}

/// The DevWorkspace `obj` as the [`Owner`] every profile object written for it is
/// garbage-collected with — RFC 0004's "Profile objects carry an `ownerReference` to their
/// DevWorkspace."
///
/// `apiVersion` and `kind` come from [`devworkspace_resource`] — the resource this controller
/// actually watches and read `obj`'s `uid` from — rather than from a second hard-coded string:
/// the garbage collector resolves an owner through exactly the `apiVersion` written, and one that
/// named a different resource than the one the `uid` belongs to would read as "owner gone" and
/// delete the workspace's policies out from under it. `None` when the object carries no name or
/// uid, which no object read from the apiserver ever lacks.
pub fn devworkspace_owner(obj: &DynamicObject) -> Option<Owner> {
    let resource = devworkspace_resource();
    Some(Owner {
        api_version: resource.api_version,
        kind: resource.kind,
        name: obj.metadata.name.clone()?,
        uid: obj.metadata.uid.clone()?,
    })
}

/// One line per object a pass *held* — its template did not resolve (deleted, or not yet in the
/// watch cache), so the live copy was neither updated nor deleted. Without this line a template
/// deleted by mistake is invisible: every metric reads healthy while the enforced policy quietly
/// stops tracking its template.
///
/// Shared by `network-profiles`, `kubearmor-policy` and `registry-config`, whose
/// `ReconcileOutcome::held` means the same thing.
pub fn held_warnings(feature: &str, held: &[ObjectKey]) -> Vec<String> {
    held.iter()
        .map(|key| {
            format!(
                "feature={feature} object={}/{} result=held — \
                 template unresolved, live object left untouched",
                key.namespace, key.name
            )
        })
        .collect()
}

/// Log [`held_warnings`] at `WARN`.
pub fn warn_held(feature: &str, held: &[ObjectKey]) {
    for line in held_warnings(feature, held) {
        tracing::warn!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::namespace_view::testing::FakeNamespaceView;

    use super::*;

    #[test]
    fn a_namespace_the_index_has_not_seen_is_retried_in_seconds() {
        let view = FakeNamespaceView::new([]);
        assert_eq!(
            off_recheck(indexed(&view, &NamespaceName::new("new-user-che"))),
            UNINDEXED_RECHECK
        );
    }

    #[test]
    fn a_namespace_the_index_has_seen_keeps_the_slow_recheck() {
        let name = NamespaceName::new("out-of-scope");
        let view = FakeNamespaceView::new([(name.clone(), NamespaceFacts::default())]);
        assert_eq!(off_recheck(indexed(&view, &name)), OFF_RECHECK);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod config_changes_tests {
    use futures_util::StreamExt;

    use super::*;

    #[tokio::test]
    async fn a_change_yields_and_a_rewrite_of_the_same_value_does_not() {
        let handle = Arc::new(RwLock::new(Some(1)));
        let mut changes = Box::pin(config_changes(Arc::clone(&handle)));

        *handle.write().unwrap() = Some(1);
        let quiet = tokio::time::timeout(CONFIG_POLL * 2, changes.next()).await;
        assert!(quiet.is_err(), "the same value is not a change");

        *handle.write().unwrap() = Some(2);
        let changed = tokio::time::timeout(CONFIG_POLL * 3, changes.next()).await;
        assert_eq!(changed.unwrap(), Some(()));
    }
}
