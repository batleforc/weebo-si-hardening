//! The gateway's configuration file — RFC 0009's *What the admin installs*, rendered by the
//! chart from `WeeboSiConfig` so that one source of truth has two readers.
//!
//! Every field a decision reads is here or in an annotation; nothing in this file is consulted
//! per request beyond what the composition root turned into a value at boot. The one exception
//! that is not an exception: [`GatewayConfig::hosts`] becomes a [`HostScope`] once, and the
//! `HostScope` is what `/auth` reads.

use std::path::Path;

use serde::{Deserialize, Serialize};
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
    /// The identity provider's issuer URL — the same client Che already uses.
    pub issuer: String,
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
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            first_allow_per_host: true,
            allow_sample: 0,
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

/// What happens to a foreign `Authorization` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BearerConfig {
    /// A token from `issuer` is verified and authorised like a cookie.
    #[serde(default = "yes")]
    pub verify_own_issuer: bool,
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
            service_account_token: true,
            foreign: Foreign::Reject,
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
    /// Believe it only from these address prefixes — matched as a string prefix, which covers
    /// the pod and node CIDRs a cluster actually writes without pulling in an IP-arithmetic
    /// dependency for a comparison this coarse.
    Cidrs(Vec<String>),
    /// Never believe it. Pod-address identity is then off, and the service-account token path is
    /// the only self-origin mechanism left.
    Off,
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
    /// A path that does not survive normalisation is denied.
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
    /// Whether back-channel logout is served at all.
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
        if self.session.host_ttl_secs > self.session.sso_ttl_secs {
            return Err(ConfigError::Invalid(
                "session.host_ttl_secs outlives session.sso_ttl_secs, so a host cookie could \
                 survive the session it was minted from"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Where a browser is sent — the gateway's own external origin, derived from the one
    /// registered redirect URI rather than configured twice, so the two can never disagree.
    pub fn redirect_base(&self) -> &str {
        self.redirect_url
            .strip_suffix("/oidc/callback")
            .unwrap_or(&self.redirect_url)
    }

    /// The host scope `/auth` reads.
    pub fn scope(&self) -> Result<HostScope, ScopeError> {
        HostScope::new(
            &self.hosts.suffix,
            self.hosts.exclude.iter().map(String::as_str),
        )
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
    fn a_suffix_that_governs_too_much_refuses_to_start() {
        let file = write(&MINIMAL.replace("\".weebo.si\"", "\".si\""));
        assert!(matches!(
            GatewayConfig::load(file.path()),
            Err(ConfigError::Invalid(_))
        ));
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
                TrustedProxy::Cidrs(vec!["10.128.".into(), "10.129.".into()]),
            ),
        ] {
            let file = write(&format!(
                "{MINIMAL}\nself_origin:\n  pod_network: Off\n  {yaml}\n"
            ));
            let config = GatewayConfig::load(file.path()).unwrap();
            assert_eq!(config.self_origin.trusted_proxy, expected, "{yaml}");
        }
    }

    #[test]
    fn the_compile_settings_are_what_every_endpoint_is_compiled_with() {
        let file = write(MINIMAL);
        let settings = GatewayConfig::load(file.path()).unwrap().compile_settings();
        assert_eq!(settings.max_rules, 16);
        assert_eq!(settings.foreign_bearer, BearerMode::Reject);
    }
}
