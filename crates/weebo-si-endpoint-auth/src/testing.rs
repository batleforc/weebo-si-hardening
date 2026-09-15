//! In-memory fakes for this crate's ports, plus the fixtures the tables are built from.
//!
//! Behind a `testing` feature so a downstream crate — the gateway binary's own tests, the
//! conformance suite — gets the same fakes rather than writing a second set that drifts. The
//! fakes are deliberately dumb: a map and a `Mutex`. Anything cleverer would be a second
//! implementation of the thing under test.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use crate::compile::{Catalogue, CompileSettings, Grant, RawEndpoint};
use crate::host::{ClientAddress, Host, HostScope};
use crate::identity::{Claims, NamespaceName, SessionId, TeamName, Username};
use crate::index::{CatalogLookup, HostIndex, IndexedEndpoint, ObjectRef};
use crate::policy::{
    AccessProfile, BearerMode, CatalogueKey, Delegation, EndpointPolicy, Provenance,
};
use crate::port::{
    Clock, EndpointCatalog, OpenedSession, RevocationStore, ServiceAccountIdentity, SessionCodec,
    Teams, TokenOutcome, TokenVerifier, WorkloadIdentity,
};
use crate::time::Timestamp;

/// A closed policy for `namespace`, owned by the user the namespace is named after.
pub fn policy_for(namespace: &str, _name: &str) -> EndpointPolicy {
    EndpointPolicy {
        namespace: NamespaceName::new(namespace),
        owner: Username::new(namespace.trim_start_matches("user-")),
        team: None,
        profile: AccessProfile::private(),
        allow_users: BTreeSet::new(),
        allow_groups: BTreeSet::new(),
        bearer: BearerMode::Reject,
        rules: Vec::new(),
        provenance: Provenance::Devfile,
        upstream: None,
        generation: 1,
    }
}

/// The catalogue every test uses: RFC 0009's own four keys.
pub fn catalogue() -> Catalogue {
    #[allow(
        clippy::expect_used,
        reason = "a fixture that does not build is the test suite failing to start, and the \
                  message names which key is wrong"
    )]
    Catalogue::new([
        (CatalogueKey::new("private"), false, BTreeSet::new()),
        (
            CatalogueKey::new("team"),
            false,
            BTreeSet::from([Delegation::Team]),
        ),
        (
            CatalogueKey::new("shared"),
            false,
            BTreeSet::from([Delegation::Team, Delegation::UsersAndGroups]),
        ),
        (CatalogueKey::new("open"), true, BTreeSet::new()),
    ])
    .expect("the fixture catalogue must build")
}

/// A grant of every key, defaulting to `private`.
pub fn full_grant() -> Grant {
    Grant {
        allowed: BTreeSet::from([
            CatalogueKey::new("private"),
            CatalogueKey::new("team"),
            CatalogueKey::new("shared"),
            CatalogueKey::new("open"),
        ]),
        default: CatalogueKey::new("private"),
    }
}

/// An endpoint object with no annotations at all — the default a developer writes nothing for.
pub fn raw_endpoint(namespace: &str, owner: &str) -> RawEndpoint {
    RawEndpoint {
        namespace: NamespaceName::new(namespace),
        owner: Username::new(owner),
        team: None,
        access: None,
        allow_users: None,
        allow_groups: None,
        rules: None,
        upstream: None,
        provenance: Provenance::Devfile,
    }
}

/// Compile with the fixture catalogue, a full grant and no overrides.
pub fn compile_fixture(raw: &RawEndpoint) -> Result<EndpointPolicy, crate::compile::CompileError> {
    crate::compile::compile(
        raw,
        &catalogue(),
        &full_grant(),
        &[],
        &CompileSettings::default(),
        1,
    )
}

/// An [`EndpointCatalog`] over a swappable index — swappable because "a policy change alters the
/// next request" is a property with a test, and the test needs to change one.
pub struct FakeCatalog {
    index: Mutex<HostIndex>,
    scope: HostScope,
}

impl FakeCatalog {
    /// One host, one policy, under `.weebo.si`.
    pub fn one(host: &str, policy: EndpointPolicy) -> Self {
        #[allow(
            clippy::expect_used,
            reason = "a fixture host that does not parse is a test bug, named here"
        )]
        let host = Host::parse(host).expect("fixture host must parse");
        let namespace = policy.namespace.as_str().to_owned();
        Self::with(
            [IndexedEndpoint {
                host,
                object: ObjectRef::new(&namespace, "api"),
                policy: std::sync::Arc::new(policy),
            }],
            1,
        )
    }

    /// An index built from whatever the test needs.
    pub fn with(endpoints: impl IntoIterator<Item = IndexedEndpoint>, generation: u64) -> Self {
        #[allow(
            clippy::expect_used,
            reason = "the fixture scope is a constant and must build"
        )]
        let scope =
            HostScope::new(".weebo.si", ["che.weebo.si", "auth.weebo.si"]).expect("fixture scope");
        Self {
            index: Mutex::new(HostIndex::build(generation, endpoints)),
            scope,
        }
    }

    /// Replace the index, the way an informer event does.
    pub fn swap(&self, host: &str, policy: EndpointPolicy, generation: u64) {
        #[allow(
            clippy::expect_used,
            reason = "a fixture host that does not parse is a test bug, named here"
        )]
        let host = Host::parse(host).expect("fixture host must parse");
        let namespace = policy.namespace.as_str().to_owned();
        let rebuilt = HostIndex::build(
            generation,
            [IndexedEndpoint {
                host,
                object: ObjectRef::new(&namespace, "api"),
                policy: std::sync::Arc::new(policy),
            }],
        );
        if let Ok(mut index) = self.index.lock() {
            *index = rebuilt;
        }
    }
}

impl EndpointCatalog for FakeCatalog {
    fn policy_for(&self, host: &Host) -> CatalogLookup {
        match self.index.lock() {
            Ok(index) => index.lookup(host),
            Err(_) => CatalogLookup::Unknown,
        }
    }

    fn scope(&self) -> &HostScope {
        &self.scope
    }
}

/// Cookies this fake knows how to open, by their sealed value.
#[derive(Default)]
pub struct FakeSessions {
    opened: HashMap<String, OpenedSession>,
}

impl FakeSessions {
    /// A codec that opens `cookie` into `claims`, valid until `expires_at`.
    pub fn with(cookie: &str, claims: Claims, expires_at: Timestamp) -> Self {
        let mut opened = HashMap::new();
        opened.insert(cookie.to_owned(), OpenedSession { claims, expires_at });
        Self { opened }
    }
}

impl SessionCodec for FakeSessions {
    fn open_host_session(
        &self,
        _host: &Host,
        sealed: &str,
        now: Timestamp,
    ) -> Option<OpenedSession> {
        self.opened
            .get(sealed)
            .filter(|session| !now.is_at_or_after(session.expires_at))
            .cloned()
    }
}

/// Tokens this fake recognises, by their raw value, and how many times it was asked.
#[derive(Default)]
pub struct FakeTokens {
    known: HashMap<String, TokenOutcome>,
    calls: Mutex<u32>,
}

impl FakeTokens {
    /// A verifier that knows one token.
    pub fn with(token: &str, outcome: TokenOutcome) -> Self {
        let mut known = HashMap::new();
        known.insert(token.to_owned(), outcome);
        Self {
            known,
            calls: Mutex::new(0),
        }
    }

    /// How many verifications actually happened — the number an identity cache exists to keep
    /// down, and therefore the number a test asserts on.
    pub fn calls(&self) -> u32 {
        self.calls.lock().map(|calls| *calls).unwrap_or_default()
    }
}

impl TokenVerifier for FakeTokens {
    fn verify(&self, token: &str, _now: Timestamp) -> TokenOutcome {
        if let Ok(mut calls) = self.calls.lock() {
            *calls += 1;
        }
        self.known
            .get(token)
            .cloned()
            .unwrap_or(TokenOutcome::Foreign)
    }
}

/// Pod addresses and service-account tokens this fake resolves.
#[derive(Default)]
pub struct FakeWorkloads {
    addresses: HashMap<String, NamespaceName>,
    tokens: HashMap<String, ServiceAccountIdentity>,
}

impl FakeWorkloads {
    /// An address that belongs to `namespace`.
    pub fn address(address: &str, namespace: &str) -> Self {
        Self {
            addresses: HashMap::from([(address.to_owned(), NamespaceName::new(namespace))]),
            tokens: HashMap::new(),
        }
    }

    /// A service-account token that belongs to `namespace`.
    pub fn service_account(token: &str, namespace: &str, expires_at: Timestamp) -> Self {
        Self {
            addresses: HashMap::new(),
            tokens: HashMap::from([(
                token.to_owned(),
                ServiceAccountIdentity {
                    namespace: NamespaceName::new(namespace),
                    expires_at,
                },
            )]),
        }
    }
}

impl WorkloadIdentity for FakeWorkloads {
    fn namespace_of_address(&self, address: &ClientAddress) -> Option<NamespaceName> {
        self.addresses.get(address.as_str()).cloned()
    }

    fn namespace_of_service_account(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Option<ServiceAccountIdentity> {
        self.tokens
            .get(token)
            .filter(|identity| !now.is_at_or_after(identity.expires_at))
            .cloned()
    }
}

/// Revoked session ids.
#[derive(Default)]
pub struct FakeRevocations {
    revoked: Mutex<BTreeSet<String>>,
}

impl FakeRevocations {
    /// Revoke one session, the way a back-channel logout does.
    pub fn revoke(&self, session: &str) {
        if let Ok(mut revoked) = self.revoked.lock() {
            revoked.insert(session.to_owned());
        }
    }
}

impl RevocationStore for FakeRevocations {
    fn is_revoked(&self, session: &SessionId) -> bool {
        self.revoked
            .lock()
            .map(|revoked| revoked.contains(session.as_str()))
            .unwrap_or(false)
    }
}

/// Team membership, as the namespace informer would have derived it.
#[derive(Default)]
pub struct FakeTeams {
    members: Mutex<HashMap<String, TeamName>>,
}

impl FakeTeams {
    /// One member.
    pub fn with(username: &str, team: &str) -> Self {
        let teams = Self::default();
        teams.put(username, team);
        teams
    }

    /// Put somebody in a team — or move them, which is the interesting direction.
    pub fn put(&self, username: &str, team: &str) {
        if let Ok(mut members) = self.members.lock() {
            members.insert(username.to_owned(), TeamName::new(team));
        }
    }

    /// Take somebody out of every team.
    pub fn remove(&self, username: &str) {
        if let Ok(mut members) = self.members.lock() {
            members.remove(username);
        }
    }
}

impl Teams for FakeTeams {
    fn team_of(&self, username: &Username) -> Option<TeamName> {
        self.members
            .lock()
            .ok()
            .and_then(|members| members.get(username.as_str()).cloned())
    }
}

/// A clock a test moves by hand.
pub struct FixedClock(Mutex<Timestamp>);

impl FixedClock {
    /// A clock reading `secs`.
    pub fn at(secs: u64) -> Self {
        Self(Mutex::new(Timestamp::from_secs(secs)))
    }

    /// Move it forward.
    pub fn advance(&self, secs: u64) {
        if let Ok(mut now) = self.0.lock() {
            *now = now.plus_secs(secs);
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
            .lock()
            .map(|now| *now)
            .unwrap_or(Timestamp::from_secs(0))
    }
}
