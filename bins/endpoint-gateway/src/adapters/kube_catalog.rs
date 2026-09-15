//! The host index, fed by watches — RFC 0009's *Request cost*, "compile at write time, not at
//! read time".
//!
//! Three informers (`WeeboSiConfig`, `Namespace`, `Ingress`) and one rebuild. Every event marks
//! the index dirty; a rebuild task compiles every indexed object once and swaps the result in
//! whole. A request then clones an `Arc` and reads, which is the entire per-request cost of
//! "which policy answers for this host".
//!
//! Rebuilding *everything* on any event rather than patching one entry is deliberate: the
//! catalogue, the grants and the overrides are cluster-wide inputs, so a `WeeboSiConfig` edit
//! changes every policy at once, and one code path that is always correct beats two where the
//! incremental one is subtly not. A rebuild is a few milliseconds for ten thousand endpoints,
//! and it happens on an informer event rather than on a request.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client, ResourceExt};
use weebo_si_crd::{
    ACCESS_ANNOTATION, ALLOW_GROUPS_ANNOTATION, ALLOW_USERS_ANNOTATION, DEVWORKSPACE_ID_LABEL,
    EndpointAuthConfig, RULES_ANNOTATION, SINGLETON_NAME, Team, UPSTREAM_ANNOTATION, WeeboSiConfig,
};
use weebo_si_endpoint_auth::compile::{
    Catalogue, CompileSettings, Grant, Override, OverrideMatch, RawEndpoint,
};
use weebo_si_endpoint_auth::host::{Host, HostScope};
use weebo_si_endpoint_auth::identity::{NamespaceName, TeamName, Username};
use weebo_si_endpoint_auth::index::{CatalogLookup, HostIndex, IndexedEndpoint, ObjectRef};
use weebo_si_endpoint_auth::policy::{CatalogueKey, Delegation, EndpointPolicy, Provenance};
use weebo_si_endpoint_auth::port::{EndpointCatalog, Teams};

/// The index, plus the two derived maps a decision reads beside it.
#[derive(Default)]
struct Snapshot {
    index: HostIndex,
    /// username → team, derived from namespace ownership. A team's members are the owners of its
    /// namespaces, so this is computed here rather than claimed anywhere.
    teams: HashMap<String, TeamName>,
    /// How many objects failed to compile, and are therefore indexed closed.
    refused: usize,
    /// Every group some endpoint in the cluster actually names — RFC 0009's *Group claims*:
    /// sealing **all** of a caller's groups is how a 4 KB cookie limit turns into a login loop
    /// nobody can diagnose, so a session carries only the groups that could change a verdict.
    interesting_groups: BTreeSet<String>,
    /// A hash of that set. A session sealed under a different one predates a group somebody has
    /// since delegated to, so it is re-proved rather than judged on a stale list.
    groups_generation: u64,
}

/// Watch-backed [`EndpointCatalog`] and [`Teams`].
pub struct KubeCatalog {
    snapshot: Arc<RwLock<Arc<Snapshot>>>,
    scope: HostScope,
    generation: Arc<AtomicU64>,
    ready: Arc<std::sync::atomic::AtomicBool>,
}

impl KubeCatalog {
    /// Start the watches and the rebuild loop. Returns once the first index is built, which is
    /// also when `/readyz` may start answering: a cold replica must not answer "allow" from an
    /// empty cache.
    pub async fn spawn(
        client: Client,
        scope: HostScope,
        settings: CompileSettings,
        namespace_label: Option<(String, String)>,
    ) -> Result<Arc<Self>, kube::Error> {
        let configs: Api<WeeboSiConfig> = Api::all(client.clone());
        let namespaces: Api<Namespace> = Api::all(client.clone());
        let ingresses: Api<Ingress> = Api::all(client);

        let namespace_config = match namespace_label.as_ref() {
            Some((key, value)) => watcher::Config::default().labels(&format!("{key}={value}")),
            None => watcher::Config::default(),
        };

        let (config_store, config_writer) = reflector::store();
        let (namespace_store, namespace_writer) = reflector::store();
        let (ingress_store, ingress_writer) = reflector::store();

        let notify = Arc::new(tokio::sync::Notify::new());
        spawn_reflector(
            reflector::reflector(config_writer, watcher(configs, watcher::Config::default())),
            Arc::clone(&notify),
        );
        spawn_reflector(
            reflector::reflector(
                namespace_writer,
                watcher(namespaces, namespace_config.clone()),
            ),
            Arc::clone(&notify),
        );
        spawn_reflector(
            reflector::reflector(
                ingress_writer,
                watcher(ingresses, watcher::Config::default()),
            ),
            Arc::clone(&notify),
        );

        // Every watch must have listed before this replica answers anything: an index built
        // from a half-synced store is an index that denies hosts it would otherwise allow, which
        // is why `/readyz` and not just `/healthz` is wired to this.
        config_store.wait_until_ready().await.map_err(not_ready)?;
        namespace_store
            .wait_until_ready()
            .await
            .map_err(not_ready)?;
        ingress_store.wait_until_ready().await.map_err(not_ready)?;

        let catalog = Arc::new(Self {
            snapshot: Arc::new(RwLock::new(Arc::new(Snapshot::default()))),
            scope,
            generation: Arc::new(AtomicU64::new(0)),
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });

        let rebuild = Arc::clone(&catalog);
        let stores = Stores {
            configs: config_store,
            namespaces: namespace_store,
            ingresses: ingress_store,
        };
        rebuild.rebuild(&stores, &settings);
        tokio::spawn(async move {
            loop {
                // A short debounce: a `WeeboSiConfig` edit and the resync that follows it are one
                // change, and rebuilding twice for it wastes a rebuild without being wrong.
                notify.notified().await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                rebuild.rebuild(&stores, &settings);
            }
        });
        Ok(catalog)
    }

    /// Whether the first index has been built. `/readyz` reads this, and a `false` keeps this
    /// replica out of the rotation rather than letting it deny every request in the cluster.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// How many hosts are indexed — `weebo_si_endpoint_auth_indexed_endpoints`.
    pub fn len(&self) -> usize {
        self.read().index.len()
    }

    /// How many objects are indexed closed because they did not compile.
    pub fn refused(&self) -> usize {
        self.read().refused
    }

    /// Contested hosts — always either an attack or a bug, never routine.
    pub fn conflicts(&self) -> usize {
        self.read().index.conflicts().len()
    }

    /// Keep only the groups some endpoint names, capped at `max`.
    ///
    /// Verdict-neutral at a point in time — a group nothing names cannot change any decision —
    /// and the generation below is what handles the "at a point in time" part.
    pub fn filter_groups(
        &self,
        groups: impl IntoIterator<Item = String>,
        max: usize,
    ) -> Vec<String> {
        let snapshot = self.read();
        groups
            .into_iter()
            .filter(|group| snapshot.interesting_groups.contains(group))
            .take(max)
            .collect()
    }

    /// The generation of the interesting set. A session carrying a different one is re-proved.
    pub fn groups_generation(&self) -> u64 {
        self.read().groups_generation
    }

    /// How many groups are interesting at all — typically a handful, which is the point.
    pub fn interesting_group_count(&self) -> usize {
        self.read().interesting_groups.len()
    }

    fn read(&self) -> Arc<Snapshot> {
        self.snapshot
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .unwrap_or_default()
    }

    fn rebuild(&self, stores: &Stores, settings: &CompileSettings) {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let config = stores
            .configs
            .state()
            .into_iter()
            .find(|config| config.metadata.name.as_deref() == Some(SINGLETON_NAME));
        let Some(config) = config else {
            // No `WeeboSiConfig` at all: index nothing. Every host is then unknown, which denies
            // — the same answer as a feature switched off, reached without guessing a policy.
            self.store(Snapshot::default());
            return;
        };
        let teams = config.spec.teams.clone();
        let Some(feature) = config.spec.features.endpoint_auth.clone() else {
            self.store(Snapshot::default());
            return;
        };

        let (catalogue, overrides) = translate(&feature);
        let owners = owners_of(&stores.namespaces, &feature, &teams);
        let mut team_of_user: HashMap<String, TeamName> = HashMap::new();
        for owner in owners.values() {
            if let (Some(team), username) = (owner.team.as_ref(), &owner.username) {
                team_of_user.insert(username.clone(), TeamName::new(team.as_str()));
            }
        }

        let mut endpoints = Vec::new();
        let mut refused = 0_usize;
        for ingress in stores.ingresses.state() {
            let namespace = ingress.namespace().unwrap_or_default();
            let Some(owner) = owners.get(&namespace) else {
                // A namespace this gateway knows nothing about — not a Che workspace namespace,
                // or one with no owner annotation. Indexing its hosts would mean indexing a
                // policy with no owner, which is a policy nobody can be checked against.
                continue;
            };
            let raw = raw_endpoint(&ingress, owner);
            let grant = grant_for(&feature, owner.team.as_ref());
            let compiled = weebo_si_endpoint_auth::compile::compile(
                &raw, &catalogue, &grant, &overrides, settings, generation,
            );
            let policy = match compiled {
                Ok(policy) => policy,
                Err(err) => {
                    refused += 1;
                    println!(
                        "WARN endpoint-gateway: {namespace}/{} does not compile ({err}); indexed closed",
                        ingress.name_any()
                    );
                    EndpointPolicy::closed(&raw, generation)
                }
            };
            let policy = Arc::new(policy);
            for host in hosts_of(&ingress) {
                let Ok(host) = Host::parse(&host) else {
                    continue;
                };
                if !self.scope.governs(&host) {
                    continue;
                }
                endpoints.push(IndexedEndpoint {
                    host,
                    object: ObjectRef::new(&namespace, &ingress.name_any()),
                    policy: Arc::clone(&policy),
                });
            }
        }

        // The interesting set, computed from the policies just compiled: the union of every
        // `allow-groups` in the cluster. A group nobody delegates to is a group no session needs
        // to carry.
        let interesting_groups: BTreeSet<String> = endpoints
            .iter()
            .flat_map(|endpoint| endpoint.policy.allow_groups.iter())
            .map(|group| group.as_str().to_owned())
            .collect();
        // A cheap order-independent hash of the set: two rebuilds that produce the same groups
        // must produce the same generation, or every rebuild would re-authenticate everybody.
        let groups_generation = interesting_groups.iter().fold(1_u64, |acc, group| {
            acc.wrapping_mul(31).wrapping_add(fnv(group))
        });

        let index = HostIndex::build(generation, endpoints);
        for conflict in index.conflicts() {
            println!(
                "WARN endpoint-gateway: host {} is claimed by {} objects; every request for it is denied",
                conflict.host,
                conflict.claimants.len()
            );
        }
        self.store(Snapshot {
            index,
            teams: team_of_user,
            refused,
            interesting_groups,
            groups_generation,
        });
    }

    fn store(&self, snapshot: Snapshot) {
        if let Ok(mut current) = self.snapshot.write() {
            *current = Arc::new(snapshot);
        }
        self.ready.store(true, Ordering::Relaxed);
    }
}

/// FNV-1a over a group name — small, stable across processes, and not a security boundary: this
/// hash decides when to re-authenticate, never who gets in.
fn fnv(value: &str) -> u64 {
    /// FNV-1a's offset basis and prime, named rather than inlined so the constants read as the
    /// published ones rather than as two magic numbers.
    const OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;

    value.bytes().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    })
}

struct Stores {
    configs: Store<WeeboSiConfig>,
    namespaces: Store<Namespace>,
    ingresses: Store<Ingress>,
}

/// What a namespace's annotations say about who owns it.
struct Owner {
    username: String,
    team: Option<weebo_si_crd::TeamName>,
}

fn spawn_reflector<S, K>(stream: S, notify: Arc<tokio::sync::Notify>)
where
    S: futures_util::Stream<Item = Result<watcher::Event<K>, watcher::Error>> + Send + 'static,
    K: Clone + std::fmt::Debug + Send + 'static,
{
    tokio::spawn(async move {
        let stream = stream.default_backoff();
        let mut stream = std::pin::pin!(stream);
        while stream.next().await.is_some() {
            notify.notify_one();
        }
    });
}

fn not_ready(err: impl std::fmt::Display) -> kube::Error {
    kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
        err.to_string(),
    ))
}

/// Which namespaces have an owner, and which team that owner is in.
fn owners_of(
    namespaces: &Store<Namespace>,
    feature: &EndpointAuthConfig,
    teams: &[Team],
) -> HashMap<String, Owner> {
    namespaces
        .state()
        .into_iter()
        .filter_map(|namespace| {
            let name = namespace.metadata.name.clone()?;
            let username = namespace
                .metadata
                .annotations
                .as_ref()?
                .get(&feature.owner.namespace_annotation)?
                .clone();
            let labels: BTreeMap<String, String> = namespace
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            // First match wins, exactly like every other feature's team resolution — and
            // evaluated here, on a namespace event, rather than per request.
            let team = teams
                .iter()
                .find(|team| team.namespace_selector.matches(&labels))
                .map(|team| team.name.clone());
            Some((name, Owner { username, team }))
        })
        .collect()
}

fn hosts_of(ingress: &Ingress) -> Vec<String> {
    ingress
        .spec
        .as_ref()
        .and_then(|spec| spec.rules.as_ref())
        .map(|rules| rules.iter().filter_map(|rule| rule.host.clone()).collect())
        .unwrap_or_default()
}

fn raw_endpoint(ingress: &Ingress, owner: &Owner) -> RawEndpoint {
    let annotations = ingress.annotations();
    RawEndpoint {
        namespace: NamespaceName::new(ingress.namespace().unwrap_or_default()),
        owner: Username::new(owner.username.clone()),
        team: owner.team.as_ref().map(|team| TeamName::new(team.as_str())),
        access: annotations.get(ACCESS_ANNOTATION).cloned(),
        allow_users: annotations.get(ALLOW_USERS_ANNOTATION).cloned(),
        allow_groups: annotations.get(ALLOW_GROUPS_ANNOTATION).cloned(),
        rules: annotations.get(RULES_ANNOTATION).cloned(),
        upstream: annotations.get(UPSTREAM_ANNOTATION).cloned(),
        provenance: if ingress.labels().contains_key(DEVWORKSPACE_ID_LABEL) {
            Provenance::Devfile
        } else {
            Provenance::Author
        },
    }
}

/// Translate the operator's configuration vocabulary into the decision's.
///
/// Two vocabularies rather than one shared type, because the decision crate must stay free of
/// `kube` and `schemars` — RFC 0009's *Request cost* argues the dependency direction, and this
/// function is the whole cost of it: a dozen lines, once per rebuild.
fn translate(feature: &EndpointAuthConfig) -> (Catalogue, Vec<Override>) {
    let entries = feature.catalog.iter().map(|entry| {
        (
            CatalogueKey::new(entry.key.as_str()),
            entry.anonymous,
            entry
                .delegation
                .iter()
                .map(|kind| match kind {
                    weebo_si_crd::DelegationKind::Team => Delegation::Team,
                    weebo_si_crd::DelegationKind::UsersAndGroups => Delegation::UsersAndGroups,
                })
                .collect::<BTreeSet<_>>(),
        )
    });
    let catalogue = Catalogue::new(entries).unwrap_or_default();

    let overrides = feature
        .overrides
        .iter()
        .map(|over| Override {
            // A `namespaceSelector` override is resolved by the operator, whose namespace
            // informer holds the labels; here only the user form is matched, and an override
            // carrying a selector matches by its user list or not at all.
            matcher: OverrideMatch::Users(over.matcher.users.clone()),
            allowed: over.allowed.as_ref().map(|keys| {
                keys.iter()
                    .map(|key| CatalogueKey::new(key.as_str()))
                    .collect()
            }),
            default: over
                .default
                .as_ref()
                .map(|key| CatalogueKey::new(key.as_str())),
            delegation: over.delegation.as_ref().map(|kinds| {
                kinds
                    .iter()
                    .map(|kind| match kind {
                        weebo_si_crd::DelegationKind::Team => Delegation::Team,
                        weebo_si_crd::DelegationKind::UsersAndGroups => Delegation::UsersAndGroups,
                    })
                    .collect()
            }),
        })
        .collect();
    (catalogue, overrides)
}

fn grant_for(feature: &EndpointAuthConfig, team: Option<&weebo_si_crd::TeamName>) -> Grant {
    let grant = feature.grant_for(team);
    Grant {
        allowed: grant
            .allowed
            .iter()
            .map(|key| CatalogueKey::new(key.as_str()))
            .collect(),
        default: CatalogueKey::new(grant.default.as_str()),
    }
}

impl EndpointCatalog for KubeCatalog {
    fn policy_for(&self, host: &Host) -> CatalogLookup {
        self.read().index.lookup(host)
    }

    fn scope(&self) -> &HostScope {
        &self.scope
    }
}

impl Teams for KubeCatalog {
    fn team_of(&self, username: &Username) -> Option<TeamName> {
        self.read().teams.get(username.as_str()).cloned()
    }
}
