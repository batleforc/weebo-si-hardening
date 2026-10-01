//! The gateway's configuration file — RFC 0009's *What the admin installs*, rendered by the
//! chart from `WeeboSiConfig` so that one source of truth has two readers.
//!
//! Every field a decision reads is here or in an annotation; nothing in this file is consulted
//! per request beyond what the composition root turned into a value at boot. The one exception
//! that is not an exception: [`GatewayConfig::hosts`] becomes a [`HostScope`] once, and the
//! `HostScope` is what `/auth` reads.

use std::path::Path;

use serde::{Deserialize, Serialize};
use weebo_si_endpoint_auth::bearer::{BearerRules, RulesError};
use weebo_si_endpoint_auth::compile::{CompileSettings, UnknownKey};
use weebo_si_endpoint_auth::host::{HostScope, ScopeError};
use weebo_si_endpoint_auth::policy::BearerMode;

/// The whole configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Where to listen. The gateway speaks plain HTTP in-cluster: its own `Ingress` terminates
    /// TLS, and the forward-auth hop is a keep-alive connection from the controller, which is
    /// where RFC 0009's *Request cost* says the cost of that hop is paid once rather than once
    /// per request.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Where `/metrics` is served, on a listener of its own. Empty (the default, for
    /// compatibility) serves it on `listen` beside everything else; the chart sets a separate
    /// port so that nothing routed to the main one — the public `Ingress` included — can reach
    /// it.
    #[serde(default)]
    pub metrics_listen: String,
    /// The identity provider's issuer URL — the same client Che already uses.
    pub issuer: String,
    /// A PEM bundle of extra root certificates, trusted for every outbound HTTPS call — issuer
    /// discovery, JWKS, the token and introspection endpoints, the self-origin probe — **in
    /// addition to** the built-in Mozilla roots, never instead of them. Empty (the default)
    /// trusts the built-in roots only. The way to reach an identity provider behind a private
    /// CA; an unreadable file or one holding no certificate is a refusal to start.
    #[serde(default)]
    pub extra_ca_file: String,
    /// The OIDC client id.
    pub client_id: String,
    /// The environment variable holding the client secret. Never the secret itself: a
    /// configuration file is a `ConfigMap`, and a `ConfigMap` is not a place for one.
    #[serde(default = "default_secret_env")]
    pub client_secret_env: String,
    /// The one registered redirect URI.
    pub redirect_url: String,
    /// Which claims carry the username and the groups.
    pub claims: ClaimsConfig,
    /// Which hosts this gateway answers for.
    pub hosts: HostsConfig,
    /// Cookie lifetimes.
    #[serde(default)]
    pub session: SessionConfig,
    /// What happens to an `Authorization` header this cluster did not mint.
    #[serde(default)]
    pub bearer: BearerConfig,
    /// Whether, and how, a workspace may prove it is itself.
    #[serde(default)]
    pub self_origin: SelfOriginConfig,
    /// A genuine CORS preflight is answered without a login redirect.
    #[serde(default = "yes")]
    pub preflight: bool,
    /// Whether this deployment **carries** traffic as well as deciding about it.
    ///
    /// `true` only where the router has no external-auth hook — OpenShift — because it is a
    /// different operational shape: the gateway is then on the data path of every WebSocket,
    /// upload and streamed response, and a bug in it can corrupt an application's answer. Off by
    /// default so that turning it on is a decision somebody made rather than one they inherited.
    #[serde(default)]
    pub reverse_proxy: bool,
    /// Path-rule limits.
    #[serde(default)]
    pub rules: RulesConfig,
    /// The identity caches — RFC 0009's *Request cost*.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Whether the gate answers its verdict or only records it.
    #[serde(default)]
    pub enforcement: Enforcement,
    /// Whether a `403` names the owner so the caller knows whom to ask.
    #[serde(default = "yes")]
    pub reveal_owner: bool,
    /// The namespace holding the revocation `ConfigMap`, and its name.
    #[serde(default)]
    pub backchannel_logout: BackchannelConfig,
    /// How often a session in use re-proves itself at the token endpoint.
    #[serde(default)]
    pub revalidation: RevalidationConfig,
    /// The self-origin probe.
    #[serde(default)]
    pub probe: ProbeConfig,
    /// What gets logged — RFC 0009's *What gets logged, because 200 assets is 200 decisions*.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// The login surface's per-address limit.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

/// How often one address may reach the endpoints that do cryptography per call.
///
/// RFC 0009's *The login surface is a surface*: `/oidc/start`, `/oidc/callback`, `/host-session`
/// and `/oidc/backchannel-logout` are reachable by anyone who can resolve this gateway's host, and
/// three of them do public-key or symmetric work per request. `/auth` is exempt — the ingress
/// controller is its only caller, and the peer check protects it instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Calls per minute per address, with a burst of the same size. `0` turns the limiter off.
    ///
    /// Generous on purpose. The key is the address the controller stated, and **where it states
    /// none, every caller shares one bucket** — so a number tuned to one browser would become a
    /// cluster-wide sign-in cap the day the client-address header goes missing. This is far above
    /// any real person's rate and still bounds the cost of a flood.
    #[serde(default = "default_login_rate")]
    pub login_per_address_per_minute: u32,
    /// Back-channel logout calls per minute per address, with a burst of the same size, on a
    /// bucket of its own. `0` turns this limiter off.
    ///
    /// Separate from the login limit (second-pass finding 5): every call comes from the identity
    /// provider's egress address, so a realm-wide logout — an admin ending every session, a user
    /// disabled with many devices — is a burst from *one* address, and sharing the sign-in bucket
    /// answered it `429`. The identity provider does not retry a back-channel logout, so every
    /// refused call was a session that stayed alive. Over the limit is answered `503`.
    #[serde(default = "default_backchannel_rate")]
    pub backchannel_logout_per_minute: u32,
}

const fn default_login_rate() -> u32 {
    300
}

const fn default_backchannel_rate() -> u32 {
    6_000
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_per_address_per_minute: default_login_rate(),
            backchannel_logout_per_minute: default_backchannel_rate(),
        }
    }
}

/// Log the exception, count the norm.
///
/// A decision per HTTP request means a page load is a burst of a few hundred, and a log line per
/// decision turns the audit trail into an incident of its own — at which point somebody lowers
/// the level and there is no audit trail at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// One line when a session first reaches a host, rather than one per asset.
    #[serde(default = "yes")]
    pub first_allow_per_host: bool,
    /// 1-in-N per-request allow lines, for debugging only. `0` disables them, which is the
    /// default and the only value a production cluster should run.
    #[serde(default)]
    pub allow_sample: u32,
    /// Deny and challenge lines per minute for one host and one reason, as a token bucket of
    /// the same size. Every decision is still counted in `weebo_si_endpoint_auth_decisions_total`;
    /// what this bounds is the log itself, which a caller sending refused requests in a loop
    /// would otherwise turn into a line — and a stdout lock — per request. `0` logs every one.
    #[serde(default = "default_deny_per_minute")]
    pub deny_per_minute: u32,
}

const fn default_deny_per_minute() -> u32 {
    120
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            first_allow_per_host: true,
            allow_sample: 0,
            deny_per_minute: default_deny_per_minute(),
        }
    }
}

/// A session in use re-proves itself against the identity provider this often — lazily, and only
/// on use, which also renews its claims. RFC 0009's answer to "how long does a disabled account
/// keep working" where back-channel logout does not exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidationConfig {
    /// `Always` | `WhenNoBackchannel` | `Never`.
    #[serde(default)]
    pub mode: RevalidationMode,
    /// The interval, in seconds.
    #[serde(default = "default_revalidation")]
    pub interval_secs: u64,
}

const fn default_revalidation() -> u64 {
    3_600
}

impl Default for RevalidationConfig {
    fn default() -> Self {
        Self {
            mode: RevalidationMode::WhenNoBackchannel,
            interval_secs: default_revalidation(),
        }
    }
}

/// When a session re-proves itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevalidationMode {
    /// Every `interval_secs`, whatever the identity provider supports.
    Always,
    /// Only where the identity provider cannot tell us a session ended. Both mechanisms absent is
    /// a `Degraded` condition, not a default.
    #[default]
    WhenNoBackchannel,
    /// Never.
    Never,
}

/// The self-origin probe — RFC 0009's *Checking that assumption rather than configuring it*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    /// Turn it off where the gateway cannot reach its own public URL.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// How often it runs.
    #[serde(default = "default_probe_interval")]
    pub interval_seconds: u64,
    /// Where it sends its request. Defaults to the gateway's own external URL.
    #[serde(default)]
    pub url: String,
}

const fn default_probe_interval() -> u64 {
    900
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: default_probe_interval(),
            url: String::new(),
        }
    }
}

fn default_listen() -> String {
    "[::]:4180".to_owned()
}

fn default_secret_env() -> String {
    "ENDPOINT_GATEWAY_CLIENT_SECRET".to_owned()
}

const fn yes() -> bool {
    true
}

/// Which claims carry identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsConfig {
    /// Must be the claim Che derives its username from, or every owner check fails closed and
    /// every developer is locked out of their own endpoint. Checked at startup rather than
    /// trusted.
    pub username: String,
    /// The groups claim.
    #[serde(default = "default_groups_claim")]
    pub groups: String,
}

fn default_groups_claim() -> String {
    "groups".to_owned()
}

/// Which hosts this gateway governs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostsConfig {
    /// The governed suffix. Must start with a dot.
    pub suffix: String,
    /// Hosts the gate never answers for.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Cookie lifetimes, in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// The cookie on the gateway's own host.
    #[serde(default = "default_sso_ttl")]
    pub sso_ttl_secs: u64,
    /// The per-host cookie, bound to one endpoint host.
    #[serde(default = "default_host_ttl")]
    pub host_ttl_secs: u64,
    /// Re-minted in the background past half-life, so an endpoint in continuous use never
    /// expires under the person using it.
    #[serde(default = "yes")]
    pub host_sliding: bool,
    /// How long a one-time host grant is valid — one redirect.
    #[serde(default = "default_grant_ttl")]
    pub grant_ttl_secs: u64,
    /// The cap on sealed groups, per RFC 0009's *Group claims*: sealing every group is how a
    /// 4 KB cookie limit turns into a login loop nobody can diagnose.
    #[serde(default = "default_max_groups")]
    pub max_groups: usize,
}

const fn default_sso_ttl() -> u64 {
    12 * 3600
}
const fn default_host_ttl() -> u64 {
    3600
}
const fn default_grant_ttl() -> u64 {
    30
}
const fn default_max_groups() -> usize {
    64
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            sso_ttl_secs: default_sso_ttl(),
            host_ttl_secs: default_host_ttl(),
            host_sliding: true,
            grant_ttl_secs: default_grant_ttl(),
            max_groups: default_max_groups(),
        }
    }
}

/// What happens to a foreign `Authorization` header — and, first, what makes one *ours*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BearerConfig {
    /// A token from `issuer` is verified and authorised like a cookie.
    #[serde(default = "yes")]
    pub verify_own_issuer: bool,
    /// Which audience makes a token ours.
    ///
    /// **Required when `verify_own_issuer` is on**, and empty is a refusal to start rather than a
    /// default: on a realm with more than one client, "this issuer minted it" accepts every token
    /// that realm has ever minted, for every client — see RFC 0009's *Which tokens are ours*.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Accept on `azp` / `client_id` where the realm's client cannot be given an audience mapper.
    ///
    /// A named compatibility mode, one party at a time, and its cost is that the gate then
    /// accepts a credential minted for somebody else's audience. An admin who turns it on is told
    /// three times — a startup `WARN` naming the party, a `Degraded` condition on the feature, and
    /// its own metric label — because "we meant to add the mapper next sprint" is how a
    /// compatibility mode becomes the configuration.
    #[serde(default)]
    pub authorized_parties: Vec<String>,
    /// Asking the issuer about a token that carries no claims of its own — every Che on
    /// OpenShift, whose access tokens are opaque `sha256~…` strings.
    #[serde(default)]
    pub introspection: IntrospectionConfig,
    /// A Kubernetes service-account token is resolved with a `TokenReview`.
    #[serde(default = "yes")]
    pub service_account_token: bool,
    /// `Reject` | `Passthrough` — the cluster-wide default a path rule may override.
    #[serde(default)]
    pub foreign: Foreign,
}

impl Default for BearerConfig {
    fn default() -> Self {
        Self {
            verify_own_issuer: true,
            audiences: Vec::new(),
            authorized_parties: Vec::new(),
            introspection: IntrospectionConfig::default(),
            service_account_token: true,
            foreign: Foreign::Reject,
        }
    }
}

/// RFC 7662 token introspection, for issuers whose access tokens carry no claims.
///
/// Off by default, and the reason is stated rather than implied: introspection cannot have the
/// property the JWKS cache has. An opaque token carries no assertion, so there is nothing to check
/// while the identity provider is down — and pretending otherwise with a long cache would mean
/// honouring a token the issuer has already revoked. Where the issuer can be asked for JWT access
/// tokens (RFC 9068), that is the shape to ask for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntrospectionConfig {
    /// Whether an opaque bearer is resolved by asking the issuer.
    #[serde(default)]
    pub enabled: bool,
    /// Where to ask. Empty means the discovery document's `introspection_endpoint`, and a
    /// discovery document that advertises none while this is on is a refusal to start.
    #[serde(default)]
    pub endpoint: String,
    /// How long `inactive` is remembered, so a flood of invented tokens costs one call per token
    /// rather than one per request.
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl_secs: u64,
    /// Introspections per minute per forwarded address, with a burst of the same size. The
    /// limiter is in front of the round trip rather than behind it.
    #[serde(default = "default_introspection_rate")]
    pub per_address_per_minute: u32,
}

const fn default_negative_ttl() -> u64 {
    30
}

const fn default_introspection_rate() -> u32 {
    60
}

impl Default for IntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            negative_ttl_secs: default_negative_ttl(),
            per_address_per_minute: default_introspection_rate(),
        }
    }
}

/// The cluster-wide default for a token this issuer did not mint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Foreign {
    /// `401`. The default, and the reason a bearer header is not a one-header bypass.
    #[default]
    Reject,
    /// Handed to the application untouched.
    Passthrough,
}

impl From<Foreign> for BearerMode {
    fn from(foreign: Foreign) -> Self {
        match foreign {
            Foreign::Reject => Self::Reject,
            Foreign::Passthrough => Self::Passthrough,
        }
    }
}

/// Whether a workspace may reach its own endpoint without signing in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfOriginConfig {
    /// `Auto` | `On` | `Off`.
    #[serde(default)]
    pub pod_network: PodNetwork,
    /// The header the controller sets from the TCP peer, never the client.
    #[serde(default = "default_client_ip_header")]
    pub client_ip_header: String,
    /// Accept the workspace's own service-account token.
    #[serde(default = "yes")]
    pub service_account_token: bool,
    /// Which connections may set the client-address header.
    #[serde(default)]
    pub trusted_proxy: TrustedProxy,
}

/// Who is allowed to tell this gateway what a caller's address is.
///
/// The header and the connection are two different claims, and only the second one is hard to
/// forge: a pod that can reach the gateway's `Service` can send any header it likes. `Cidrs` is
/// the answer where the gateway is reachable from more than its own ingress controller; `Any` is
/// correct on a forward-auth deployment, where the only thing that calls `/auth` is the
/// controller itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedProxy {
    /// Believe the header on any connection.
    #[default]
    Any,
    /// Believe it only from these networks — real CIDRs (`10.128.0.0/14`, `fd00::/8`), a bare
    /// address, or the legacy dotted prefix (`"10.128."`, read as `10.128.0.0/16`). It used to be
    /// a string prefix, under which `"10.1"` also trusted `10.10.x.x` through `10.199.x.x`.
    Cidrs(Vec<Cidr>),
    /// Never believe it. Pod-address identity is then off, and the service-account token path is
    /// the only self-origin mechanism left.
    Off,
}

/// One network, parsed at load: an address and a prefix length, compared by mask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cidr {
    network: std::net::IpAddr,
    prefix: u8,
    /// What the admin wrote, so the value round-trips and error messages quote it.
    spelled: String,
}

impl Cidr {
    /// Parse `a.b.c.d/n`, `v6::/n`, a bare address, or a legacy dotted IPv4 prefix of whole
    /// octets ending in `.` (`"10."`, `"10.128."`, `"10.128.3."`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        use std::net::{IpAddr, Ipv4Addr};

        let spelled = raw.trim().to_owned();
        let (network, prefix) = if let Some((address, length)) = spelled.split_once('/') {
            let network: IpAddr = address
                .parse()
                .map_err(|_| format!("{spelled:?} is not a CIDR: {address:?} is not an address"))?;
            let prefix: u8 = length
                .parse()
                .map_err(|_| format!("{spelled:?} is not a CIDR: bad prefix length"))?;
            (network, prefix)
        } else if let Ok(address) = spelled.parse::<IpAddr>() {
            (address, if address.is_ipv4() { 32 } else { 128 })
        } else if let Some(head) = spelled.strip_suffix('.') {
            let octets = head
                .split('.')
                .map(str::parse::<u8>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| format!("{spelled:?} is neither a CIDR nor a dotted prefix"))?;
            if octets.is_empty() || octets.len() > 3 {
                return Err(format!("{spelled:?} is neither a CIDR nor a dotted prefix"));
            }
            let mut bytes = [0_u8; 4];
            for (slot, octet) in bytes.iter_mut().zip(&octets) {
                *slot = *octet;
            }
            let prefix = u8::try_from(octets.len() * 8).unwrap_or(32);
            (IpAddr::V4(Ipv4Addr::from(bytes)), prefix)
        } else {
            return Err(format!("{spelled:?} is not a CIDR"));
        };
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!(
                "{spelled:?}: prefix /{prefix} is longer than /{max}"
            ));
        }
        Ok(Self {
            network,
            prefix,
            spelled,
        })
    }

    /// Whether `address` is inside this network. An IPv4-mapped IPv6 peer (`::ffff:10.1.2.3`,
    /// which is how an IPv4 client appears on a `[::]` listener) is compared as the IPv4 address
    /// it is; otherwise the families must match.
    pub fn contains(&self, address: std::net::IpAddr) -> bool {
        use std::net::IpAddr;

        match (self.network, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

impl TryFrom<String> for Cidr {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl From<Cidr> for String {
    fn from(cidr: Cidr) -> Self {
        cidr.spelled
    }
}

fn default_client_ip_header() -> String {
    "X-Real-Ip".to_owned()
}

impl Default for SelfOriginConfig {
    fn default() -> Self {
        Self {
            pod_network: PodNetwork::Auto,
            client_ip_header: default_client_ip_header(),
            service_account_token: true,
            trusted_proxy: TrustedProxy::Any,
        }
    }
}

/// Three states for a mechanism whose safety the cluster's network decides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PodNetwork {
    /// Trust the address only while the probe says it can be trusted.
    #[default]
    Auto,
    /// Trust it.
    On,
    /// Do not.
    Off,
}

/// Path-rule limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    /// How many rules one endpoint may carry.
    #[serde(default = "default_max_rules")]
    pub max_per_endpoint: usize,
    /// A path that does not survive normalisation is denied. **Always**: the decision enforces
    /// it unconditionally, because turning it off is the path-confusion bypass RFC 0009 spends a
    /// section closing. The key is kept so existing files still load, and `false` is a refusal
    /// to start rather than a setting that is silently not honoured.
    #[serde(default = "yes")]
    pub reject_unnormalised_path: bool,
    /// What an `access` annotation naming an unknown key resolves to.
    #[serde(default)]
    pub on_unknown_key: OnUnknownKey,
}

const fn default_max_rules() -> usize {
    16
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            max_per_endpoint: default_max_rules(),
            reject_unnormalised_path: true,
            on_unknown_key: OnUnknownKey::Default,
        }
    }
}

/// RFC 0002's selection semantics for an unknown key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnUnknownKey {
    /// Fall to the team's default.
    #[default]
    Default,
    /// Refuse to compile the endpoint, which closes it.
    Deny,
}

/// The identity caches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Opened sessions and verified bearers, keyed by hash.
    #[serde(default = "default_identity_entries")]
    pub identity_max_entries: usize,
    /// How long a cached identity may outlive the moment it was proved.
    #[serde(default = "default_identity_ttl")]
    pub identity_ttl_secs: u64,
    /// `TokenReview` answers, bounded by the token's own `exp`.
    #[serde(default = "default_token_review_entries")]
    pub token_review_max_entries: usize,
}

const fn default_identity_entries() -> usize {
    20_000
}
const fn default_identity_ttl() -> u64 {
    300
}
const fn default_token_review_entries() -> usize {
    5_000
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            identity_max_entries: default_identity_entries(),
            identity_ttl_secs: default_identity_ttl(),
            token_review_max_entries: default_token_review_entries(),
        }
    }
}

/// Whether the gate's own verdict is answered or only counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Enforcement {
    /// Decide, log and count; answer `200` regardless. The rollout step that tells an admin which
    /// endpoint a probe has been hitting unauthenticated for a year, before the probe breaks.
    Observe,
    /// Answer what was decided.
    #[default]
    Enforce,
}

/// Where revoked sessions are recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackchannelConfig {
    /// Whether back-channel logout is served at all. Off, `/oidc/backchannel-logout` answers
    /// `404` and the chart does not route it; the revocation `ConfigMap` is still watched, so a
    /// revocation recorded before it was turned off keeps holding.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The `ConfigMap` holding revoked session ids, in the gateway's own namespace.
    #[serde(default = "default_revocations")]
    pub configmap: String,
    /// That namespace.
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

fn default_revocations() -> String {
    "endpoint-auth-revocations".to_owned()
}

fn default_namespace() -> String {
    "weebo-si-hardening".to_owned()
}

impl Default for BackchannelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            configmap: default_revocations(),
            namespace: default_namespace(),
        }
    }
}

/// Why a configuration was refused.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read.
    Unreadable(std::io::Error),
    /// The file is not the document this binary expects.
    Unparseable(String),
    /// A field is present and unusable.
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(err) => write!(f, "config unreadable: {err}"),
            Self::Unparseable(err) => write!(f, "config unparseable: {err}"),
            Self::Invalid(why) => write!(f, "config invalid: {why}"),
        }
    }
}

impl GatewayConfig {
    /// Read and validate a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(ConfigError::Unreadable)?;
        let config: Self = serde_yaml_bw::from_str(&raw)
            .map_err(|err| ConfigError::Unparseable(err.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Everything that must hold before this process serves one request.
    ///
    /// Refusing to start is the right failure for every one of these: a gateway that starts with
    /// a suffix it cannot govern or an issuer it cannot name is a gateway that denies every
    /// request in the cluster while looking healthy.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.scope()
            .map_err(|err| ConfigError::Invalid(format!("hosts: {err:?}")))?;
        if !self.issuer.starts_with("https://") {
            return Err(ConfigError::Invalid(format!(
                "issuer {:?} must be https",
                self.issuer
            )));
        }
        if !self.redirect_url.starts_with("https://") {
            return Err(ConfigError::Invalid(format!(
                "redirect_url {:?} must be https",
                self.redirect_url
            )));
        }
        if self.claims.username.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "claims.username is what every owner check compares; it may not be empty".into(),
            ));
        }
        if self.reverse_proxy
            && self.self_origin.trusted_proxy == TrustedProxy::Any
            && self.self_origin.pod_network != PodNetwork::Off
        {
            return Err(ConfigError::Invalid(
                "reverse_proxy with self_origin.trusted_proxy: any would let any pod that can \
                 reach this gateway claim any namespace's identity by setting one header — set \
                 trusted_proxy to the router's CIDRs, or pod_network: Off"
                    .into(),
            ));
        }
        if !self.rules.reject_unnormalised_path {
            return Err(ConfigError::Invalid(
                "rules.reject_unnormalised_path: false is not supported — a path that does not \
                 survive normalisation is always denied, because allowing it is the \
                 path-confusion bypass; remove the key or set it to true"
                    .into(),
            ));
        }
        if self.session.host_ttl_secs > self.session.sso_ttl_secs {
            return Err(ConfigError::Invalid(
                "session.host_ttl_secs outlives session.sso_ttl_secs, so a host cookie could \
                 survive the session it was minted from"
                    .into(),
            ));
        }
        // The one that cannot be a warning. A gateway that accepts every token in the realm while
        // looking healthy is worse than one that will not come up, so an empty audience list is
        // the same answer as a suffix this gateway cannot govern.
        self.bearer_rules()
            .map_err(|err| ConfigError::Invalid(err.to_string()))?;
        Ok(())
    }

    /// Why this configuration cannot limit `TokenReview`s per client, when it cannot.
    ///
    /// On forward-auth with `trusted_proxy: off` no caller has an address — `/auth` has no peer
    /// of its own and the controller's header is not believed — so every review is held to the
    /// global limit only, and one caller varying its token can spend it for everybody. Not a load
    /// error: sharing one small bucket instead would cut every workspace's capacity to one
    /// client's, which fails closed after a cold start with no attacker at all.
    pub fn token_review_limit_warning(&self) -> Option<&'static str> {
        (!self.reverse_proxy
            && self.self_origin.service_account_token
            && self.self_origin.trusted_proxy == TrustedProxy::Off)
            .then_some(
                "self_origin.trusted_proxy is off on a forward-auth deployment, so no caller has \
                 an address and TokenReviews are limited globally only: one caller sending fresh \
                 service-account-shaped tokens can use up the limit for every workspace. Set \
                 trusted_proxy to any (only the ingress controller calls /auth) or to its CIDRs.",
            )
    }

    /// What makes a bearer ours, or why nothing could.
    ///
    /// `None` where `verify_own_issuer` is off: the branch does not exist, so there is no list to
    /// require. Everything else is RFC 0009's *Which tokens are ours*.
    pub fn bearer_rules(&self) -> Result<Option<BearerRules>, RulesError> {
        if !self.bearer.verify_own_issuer {
            return Ok(None);
        }
        BearerRules::new(
            self.issuer.clone(),
            self.bearer.audiences.iter().cloned(),
            self.bearer.authorized_parties.iter().cloned(),
        )
        .map(Some)
    }

    /// Where a browser is sent — the gateway's own external origin, derived from the one
    /// registered redirect URI rather than configured twice, so the two can never disagree.
    pub fn redirect_base(&self) -> &str {
        self.redirect_url
            .strip_suffix("/oidc/callback")
            .unwrap_or(&self.redirect_url)
    }

    /// The host scope `/auth` reads.
    ///
    /// The gateway's own host — `redirect_url`'s — is excluded whether or not `hosts.exclude`
    /// names it. It is never an endpoint: on a `ReverseProxy` deployment a governed host is
    /// handed to the application whatever its path, and the gateway's own `/oidc/callback`
    /// would be handed with it.
    pub fn scope(&self) -> Result<HostScope, ScopeError> {
        let own = self.own_host();
        HostScope::new(
            &self.hosts.suffix,
            self.hosts
                .exclude
                .iter()
                .map(String::as_str)
                .chain(own.as_deref()),
        )
    }

    /// The host of `redirect_url`, lowercased and without a port.
    pub fn own_host(&self) -> Option<String> {
        let authority = self
            .redirect_url
            .strip_prefix("https://")?
            .split(['/', '?', '#'])
            .next()?;
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let host = host.split(':').next()?.trim().to_ascii_lowercase();
        (!host.is_empty()).then_some(host)
    }

    /// The compile-time settings every endpoint in this cluster is compiled with.
    pub fn compile_settings(&self) -> CompileSettings {
        CompileSettings {
            foreign_bearer: self.bearer.foreign.into(),
            max_rules: self.rules.max_per_endpoint,
            on_unknown_key: match self.rules.on_unknown_key {
                OnUnknownKey::Default => UnknownKey::Default,
                OnUnknownKey::Deny => UnknownKey::Deny,
            },
        }
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

    const MINIMAL: &str = r#"
issuer: "https://sso.weebo.si/realms/weebo"
client_id: "che-client"
redirect_url: "https://auth.weebo.si/oidc/callback"
claims:
  username: preferred_username
hosts:
  suffix: ".weebo.si"
  exclude: ["che.weebo.si"]
bearer:
  audiences: ["endpoint-gateway"]
"#;

    fn write(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn the_minimal_config_is_the_one_an_admin_actually_writes() {
        let file = write(MINIMAL);
        let config = GatewayConfig::load(file.path()).unwrap();
        assert_eq!(config.listen, "[::]:4180");
        assert_eq!(config.session.sso_ttl_secs, 12 * 3600);
        assert_eq!(config.bearer.foreign, Foreign::Reject);
        assert_eq!(config.cache.identity_max_entries, 20_000);
        assert_eq!(config.enforcement, Enforcement::Enforce);
        // Generous rather than tuned to one browser: where the controller states no client
        // address, every caller shares one bucket.
        assert_eq!(config.rate_limit.login_per_address_per_minute, 300);
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // A typo in a security control's configuration must not be a silently ignored line: an
        // admin who misspells `hosts` would otherwise get a gateway governing nothing.
        let file = write(&format!("{MINIMAL}\nhosts_typo: \".weebo.si\"\n"));
        assert!(matches!(
            GatewayConfig::load(file.path()),
            Err(ConfigError::Unparseable(_))
        ));
    }

    #[test]
    fn the_gateways_own_host_is_never_governed_even_when_exclude_forgets_it() {
        // MINIMAL's `exclude` names only Che's host; `redirect_url`'s is excluded regardless.
        use weebo_si_endpoint_auth::host::Host;

        let file = write(MINIMAL);
        let config = GatewayConfig::load(file.path()).unwrap();
        let scope = config.scope().unwrap();
        assert!(!scope.governs(&Host::parse("auth.weebo.si").unwrap()));
        assert!(scope.governs(&Host::parse("alice-ws-api.weebo.si").unwrap()));
        assert_eq!(config.own_host().as_deref(), Some("auth.weebo.si"));

        let mut ported = config.clone();
        ported.redirect_url = "https://Auth.Weebo.si:8443/oidc/callback".to_owned();
        assert_eq!(ported.own_host().as_deref(), Some("auth.weebo.si"));
    }

    #[test]
    fn a_suffix_that_governs_too_much_refuses_to_start() {
        let file = write(&MINIMAL.replace("\".weebo.si\"", "\".si\""));
        assert!(matches!(
            GatewayConfig::load(file.path()),
            Err(ConfigError::Invalid(_))
        ));
    }

    /// The refusal RFC 0009 asks for by name. `verify_own_issuer: true` with nothing naming an
    /// audience means *every token this realm has ever minted, for every client* — a gateway
    /// that accepts that while looking healthy is worse than one that will not come up.
    #[test]
    fn verifying_our_own_issuer_with_no_audience_at_all_refuses_to_start() {
        let file = write(&MINIMAL.replace("  audiences: [\"endpoint-gateway\"]\n", ""));
        let Err(ConfigError::Invalid(why)) = GatewayConfig::load(file.path()) else {
            panic!("a gateway with no audience must not start");
        };
        // And the message names the fix, not the field.
        assert!(why.contains("audience mapper"), "{why}");
    }

    #[test]
    fn the_compatibility_mode_is_an_audience_of_its_own_kind() {
        // An admin who cannot edit the realm's client names the party instead — allowed, and
        // warned about at startup and in its own metric label.
        let file = write(&MINIMAL.replace(
            "  audiences: [\"endpoint-gateway\"]",
            "  authorized_parties: [\"che-client\"]",
        ));
        let config = GatewayConfig::load(file.path()).unwrap();
        let rules = config.bearer_rules().unwrap().unwrap();
        assert!(rules.in_compatibility_mode());
        assert_eq!(rules.audiences().count(), 0);

        // With the branch off there is no list to require: every bearer is foreign, and only a
        // `bearer: Passthrough` rule reaches the application with one.
        let file = write(&format!(
            "{}\n  verify_own_issuer: false\n",
            MINIMAL.replace("  audiences: [\"endpoint-gateway\"]\n", "")
        ));
        let config = GatewayConfig::load(file.path()).unwrap();
        assert_eq!(config.bearer_rules().unwrap(), None);
    }

    #[test]
    fn introspection_is_off_by_default_and_remembers_a_refusal_for_half_a_minute() {
        let file = write(MINIMAL);
        let config = GatewayConfig::load(file.path()).unwrap();
        assert!(!config.bearer.introspection.enabled);
        assert_eq!(config.bearer.introspection.negative_ttl_secs, 30);
        assert!(config.bearer.introspection.endpoint.is_empty());
    }

    #[test]
    fn plain_http_endpoints_for_the_issuer_or_the_callback_refuse_to_start() {
        for replaced in [
            MINIMAL.replace("https://sso", "http://sso"),
            MINIMAL.replace("https://auth", "http://auth"),
        ] {
            let file = write(&replaced);
            assert!(matches!(
                GatewayConfig::load(file.path()),
                Err(ConfigError::Invalid(_))
            ));
        }
    }

    #[test]
    fn a_host_cookie_may_not_outlive_the_session_it_was_minted_from() {
        let file = write(&format!(
            "{MINIMAL}\nsession:\n  sso_ttl_secs: 600\n  host_ttl_secs: 3600\n"
        ));
        assert!(matches!(
            GatewayConfig::load(file.path()),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn carrying_traffic_while_believing_any_callers_address_header_refuses_to_start() {
        // On a forward-auth deployment the only thing that calls `/auth` is the controller; on a
        // reverse-proxy one *every* caller reaches this process directly, so "believe the header"
        // becomes "any pod may claim any namespace".
        let file = write(&format!("{MINIMAL}\nreverse_proxy: true\n"));
        assert!(matches!(
            GatewayConfig::load(file.path()),
            Err(ConfigError::Invalid(_))
        ));

        let scoped = write(&format!(
            "{MINIMAL}\nreverse_proxy: true\nself_origin:\n  trusted_proxy:\n    cidrs: [\"10.128.\"]\n"
        ));
        assert!(GatewayConfig::load(scoped.path()).is_ok());
    }

    #[test]
    fn forward_auth_without_a_trusted_proxy_is_warned_about_and_nothing_else_is() {
        let load = |extra: &str| {
            let file = write(&format!("{MINIMAL}\n{extra}"));
            GatewayConfig::load(file.path()).unwrap()
        };
        let off = load("self_origin:\n  trusted_proxy: off\n");
        assert!(off.token_review_limit_warning().is_some());
        for quiet in [
            "self_origin:\n  trusted_proxy: any\n",
            "self_origin:\n  trusted_proxy: off\n  service_account_token: false\n",
            "reverse_proxy: true\nself_origin:\n  pod_network: Off\n  trusted_proxy: off\n",
        ] {
            assert!(
                load(quiet).token_review_limit_warning().is_none(),
                "{quiet}"
            );
        }
    }

    #[test]
    fn the_trusted_proxy_forms_the_chart_renders_are_the_forms_that_parse() {
        // The chart writes `trusted_proxy: any` for the unit variant and a `cidrs:` mapping for
        // the list. A test rather than a review note: the two are different serde shapes, and a
        // gateway that refuses to start because its own chart wrote the other one is an outage
        // with a very confusing message.
        for (yaml, expected) in [
            ("trusted_proxy: any", TrustedProxy::Any),
            ("trusted_proxy: off", TrustedProxy::Off),
            (
                "trusted_proxy:\n    cidrs: [\"10.128.\", \"10.129.\"]",
                TrustedProxy::Cidrs(vec![
                    Cidr::parse("10.128.").unwrap(),
                    Cidr::parse("10.129.").unwrap(),
                ]),
            ),
        ] {
            let file = write(&format!(
                "{MINIMAL}\nself_origin:\n  pod_network: Off\n  {yaml}\n"
            ));
            let config = GatewayConfig::load(file.path()).unwrap();
            assert_eq!(config.self_origin.trusted_proxy, expected, "{yaml}");
        }
    }

    /// Second-pass finding 10: `reject_unnormalised_path` was parsed and never read, so `false`
    /// looked like a setting and changed nothing. It is now refused at load.
    #[test]
    fn turning_off_the_unnormalised_path_refusal_refuses_to_start() {
        let file = write(&format!(
            "{MINIMAL}\nrules:\n  reject_unnormalised_path: false\n"
        ));
        let Err(ConfigError::Invalid(why)) = GatewayConfig::load(file.path()) else {
            panic!("reject_unnormalised_path: false must not load");
        };
        assert!(why.contains("reject_unnormalised_path"), "{why}");
        let file = write(&format!(
            "{MINIMAL}\nrules:\n  reject_unnormalised_path: true\n"
        ));
        assert!(GatewayConfig::load(file.path()).is_ok());
    }

    #[test]
    fn the_back_channel_has_a_limit_of_its_own_and_generous_by_default() {
        let config = GatewayConfig::load(write(MINIMAL).path()).unwrap();
        assert!(
            config.rate_limit.backchannel_logout_per_minute
                > config.rate_limit.login_per_address_per_minute
        );
    }

    #[test]
    fn the_compile_settings_are_what_every_endpoint_is_compiled_with() {
        let file = write(MINIMAL);
        let settings = GatewayConfig::load(file.path()).unwrap().compile_settings();
        assert_eq!(settings.max_rules, 16);
        assert_eq!(settings.foreign_bearer, BearerMode::Reject);
    }

    /// M2: the trusted-proxy match used to be a string prefix, so `"10.1"` trusted every address
    /// from `10.1.x.x` to `10.199.x.x` — including `10.10.0.0/16`, somebody else's network.
    #[test]
    fn trusted_proxy_networks_are_matched_as_networks_and_not_as_strings() {
        use std::net::IpAddr;

        let ip = |raw: &str| raw.parse::<IpAddr>().unwrap();
        let cidr = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(cidr.contains(ip("10.1.200.3")));
        assert!(!cidr.contains(ip("10.10.0.1")), "the string-prefix bypass");
        assert!(!cidr.contains(ip("10.199.0.1")));
        // An IPv4 client on a `[::]` listener arrives IPv4-mapped.
        assert!(cidr.contains(ip("::ffff:10.1.0.9")));
        // Legacy dotted prefixes keep their meaning — whole octets.
        let legacy = Cidr::parse("10.128.").unwrap();
        assert!(legacy.contains(ip("10.128.4.4")));
        assert!(!legacy.contains(ip("10.12.8.4")));
        // IPv6, bare addresses, and the edges.
        assert!(Cidr::parse("fd00::/8").unwrap().contains(ip("fd12::1")));
        assert!(!Cidr::parse("fd00::/8").unwrap().contains(ip("10.0.0.1")));
        assert!(Cidr::parse("10.0.0.7").unwrap().contains(ip("10.0.0.7")));
        assert!(!Cidr::parse("10.0.0.7").unwrap().contains(ip("10.0.0.8")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("192.0.2.1")));
        // What is not a network refuses to load rather than trusting something unintended.
        for bad in ["10.1", "10.0.0.0/33", "banana", "10.300.", "/8", ""] {
            assert!(Cidr::parse(bad).is_err(), "{bad:?}");
        }
        let file = write(&format!(
            "{MINIMAL}\nself_origin:\n  pod_network: Off\n  trusted_proxy:\n    cidrs: [\"10.1\"]\n"
        ));
        assert!(GatewayConfig::load(file.path()).is_err());
    }
}
