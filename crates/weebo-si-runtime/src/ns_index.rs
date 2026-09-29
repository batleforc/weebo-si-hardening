//! A namespace → object-reference index kept alongside a reflector [`Store`].
//!
//! `Store` only offers "get by key" and "snapshot everything", so "everything this operator owns
//! in *this* namespace" used to be a full cluster-wide snapshot filtered down on every call —
//! once per DevWorkspace admission (`has_baseline`) and once per namespace reconcile, so O(N)
//! per call and O(N²) per resync. This index answers the namespace question directly.
//!
//! It is fed from the same watch stream as the store, **before** the store sees each event (see
//! [`NsIndex::observe`]), and mirrors the reflector's own buffering: an `Init`..`InitDone`
//! re-list is collected aside and swapped in at `InitDone`, exactly when the store swaps its own
//! contents. So by the time `Store::wait_until_ready` returns, the index already holds the full
//! initial list. The objects themselves are always read back from the store — the index holds
//! keys only — so the index can at worst lag the store by the one event in flight, never serve
//! an object the store has dropped.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, PoisonError, RwLock};

use kube::Resource;
use kube::runtime::reflector::{ObjectRef, Store};
use kube::runtime::watcher;

type Refs<K> = HashMap<String, HashSet<ObjectRef<K>>>;

struct Inner<K: Resource> {
    live: Refs<K>,
    /// Collected between `Init` and `InitDone`, then swapped in whole.
    buffer: Option<Refs<K>>,
}

/// Namespace → keys of the objects the watch holds there. Cheap to clone; clones share state.
pub(crate) struct NsIndex<K: Resource>
where
    K::DynamicType: Clone + Eq + Hash,
{
    dyntype: K::DynamicType,
    inner: Arc<RwLock<Inner<K>>>,
}

impl<K: Resource> Clone for NsIndex<K>
where
    K::DynamicType: Clone + Eq + Hash,
{
    fn clone(&self) -> Self {
        Self {
            dyntype: self.dyntype.clone(),
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K: Resource> NsIndex<K>
where
    K::DynamicType: Clone + Eq + Hash,
{
    /// An empty index for objects of `dyntype` — the same one the paired store's writer was
    /// built with, so the keys this index hands out look up in that store.
    pub(crate) fn new(dyntype: K::DynamicType) -> Self {
        Self {
            dyntype,
            inner: Arc::new(RwLock::new(Inner {
                live: HashMap::new(),
                buffer: None,
            })),
        }
    }

    fn key(&self, obj: &K) -> (String, ObjectRef<K>) {
        (
            obj.meta().namespace.clone().unwrap_or_default(),
            ObjectRef::from_obj_with(obj, self.dyntype.clone()),
        )
    }

    /// Fold one watch event in. Call it on the stream *before* `reflector` so the index is never
    /// behind the store at readiness.
    pub(crate) fn observe(&self, event: &watcher::Event<K>) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        match event {
            watcher::Event::Apply(obj) => {
                let (ns, key) = self.key(obj);
                inner.live.entry(ns).or_default().insert(key);
            }
            watcher::Event::Delete(obj) => {
                let (ns, key) = self.key(obj);
                if let Some(keys) = inner.live.get_mut(&ns) {
                    keys.remove(&key);
                    if keys.is_empty() {
                        inner.live.remove(&ns);
                    }
                }
            }
            watcher::Event::Init => inner.buffer = Some(HashMap::new()),
            watcher::Event::InitApply(obj) => {
                let (ns, key) = self.key(obj);
                inner
                    .buffer
                    .get_or_insert_with(HashMap::new)
                    .entry(ns)
                    .or_default()
                    .insert(key);
            }
            watcher::Event::InitDone => {
                if let Some(buffer) = inner.buffer.take() {
                    inner.live = buffer;
                }
            }
        }
    }

    /// Every object `store` currently holds in namespace `ns`.
    pub(crate) fn objects_in(&self, store: &Store<K>, ns: &str) -> Vec<Arc<K>>
    where
        K: Clone,
    {
        let keys: Vec<ObjectRef<K>> = {
            let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
            inner
                .live
                .get(ns)
                .map(|keys| keys.iter().cloned().collect())
                .unwrap_or_default()
        };
        keys.iter().filter_map(|key| store.get(key)).collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use k8s_openapi::api::networking::v1::NetworkPolicy;
    use kube::api::{ApiResource, DynamicObject, GroupVersionKind, ObjectMeta};
    use kube::runtime::reflector::store::Writer;

    use super::*;

    fn np(ns: &str, name: &str) -> NetworkPolicy {
        NetworkPolicy {
            metadata: ObjectMeta {
                namespace: Some(ns.to_string()),
                name: Some(name.to_string()),
                ..ObjectMeta::default()
            },
            ..NetworkPolicy::default()
        }
    }

    /// Feed `event` to the index, then the store — the order the adapters wire them in.
    fn feed<K>(index: &NsIndex<K>, writer: &mut Writer<K>, event: watcher::Event<K>)
    where
        K: Resource + Clone + 'static,
        K::DynamicType: Clone + Eq + Hash,
    {
        index.observe(&event);
        writer.apply_watcher_event(&event);
    }

    fn names<K: Resource>(objects: &[Arc<K>]) -> Vec<String> {
        let mut names: Vec<String> = objects
            .iter()
            .filter_map(|obj| obj.meta().name.clone())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn it_answers_per_namespace_and_follows_applies_and_deletes() {
        let index = NsIndex::<NetworkPolicy>::new(());
        let mut writer = Writer::<NetworkPolicy>::default();
        let store = writer.as_reader();
        feed(&index, &mut writer, watcher::Event::Init);
        feed(
            &index,
            &mut writer,
            watcher::Event::InitApply(np("a", "base")),
        );
        feed(
            &index,
            &mut writer,
            watcher::Event::InitApply(np("a", "git")),
        );
        feed(
            &index,
            &mut writer,
            watcher::Event::InitApply(np("b", "base")),
        );
        feed(&index, &mut writer, watcher::Event::InitDone);

        assert_eq!(names(&index.objects_in(&store, "a")), ["base", "git"]);
        assert_eq!(names(&index.objects_in(&store, "b")), ["base"]);
        assert!(index.objects_in(&store, "c").is_empty());

        feed(&index, &mut writer, watcher::Event::Apply(np("c", "base")));
        feed(&index, &mut writer, watcher::Event::Delete(np("a", "git")));
        feed(&index, &mut writer, watcher::Event::Apply(np("a", "base")));
        assert_eq!(names(&index.objects_in(&store, "a")), ["base"]);
        assert_eq!(names(&index.objects_in(&store, "c")), ["base"]);
    }

    #[test]
    fn a_relist_replaces_the_index_at_init_done_like_the_store() {
        let index = NsIndex::<NetworkPolicy>::new(());
        let mut writer = Writer::<NetworkPolicy>::default();
        let store = writer.as_reader();
        feed(&index, &mut writer, watcher::Event::Init);
        feed(
            &index,
            &mut writer,
            watcher::Event::InitApply(np("a", "gone")),
        );
        feed(&index, &mut writer, watcher::Event::InitDone);

        feed(&index, &mut writer, watcher::Event::Init);
        feed(
            &index,
            &mut writer,
            watcher::Event::InitApply(np("a", "kept")),
        );
        // Mid-relist, the old contents are still what is served — by both.
        assert_eq!(names(&index.objects_in(&store, "a")), ["gone"]);
        feed(&index, &mut writer, watcher::Event::InitDone);
        assert_eq!(names(&index.objects_in(&store, "a")), ["kept"]);
    }

    #[test]
    fn dynamic_object_keys_look_up_in_a_store_built_with_the_same_resource() {
        // `ObjectRef` equality includes the `ApiResource`: the index must build its keys with
        // the one the store's writer was given, or every lookup would silently miss.
        let resource = ApiResource::from_gvk_with_plural(
            &GroupVersionKind::gvk("security.kubearmor.com", "v1", "KubeArmorPolicy"),
            "kubearmorpolicies",
        );
        let index = NsIndex::<DynamicObject>::new(resource.clone());
        let mut writer = Writer::<DynamicObject>::new(resource.clone());
        let store = writer.as_reader();
        let obj = DynamicObject::new("base", &resource).within("a");
        feed(&index, &mut writer, watcher::Event::Init);
        feed(&index, &mut writer, watcher::Event::InitApply(obj));
        feed(&index, &mut writer, watcher::Event::InitDone);
        assert_eq!(names(&index.objects_in(&store, "a")), ["base"]);
    }
}
