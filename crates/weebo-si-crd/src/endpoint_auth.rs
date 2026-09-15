//! `spec.features.endpointAuth` — the catalogue of access profiles, the grants over it, the
//! hosts this feature governs, and how the gate is attached to a routing object. See RFC 0009's
//! *Design → Contract*.
//!
//! **Two things live here that a reader might expect elsewhere**, and both are here for the same
//! reason — they are pure projections of configuration that *two* callers need:
//!
//! - [`HostsConfig::owner_of`], the host-ownership patterns. The webhook refuses a host no
//!   pattern ties to the writing namespace, and the gateway's own configuration is rendered from
//!   the same field; a second implementation of the matcher is a second answer to "whose host is
//!   this", which is the question this feature's whole index rests on.
//! - [`Dialect`] and [`EndpointAuthConfig::attachment`], the annotations that attach the gate.
//!   The mutating webhook writes them and the controller's reconcile sweep re-writes them, so
//!   they cannot live in either one. They are I/O-free string rendering over configuration,
//!   which is what this crate already is.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::dwoc_pin::OnUnknownKey;
use crate::feature_mode::FeatureMode;
use crate::selector::Selector;
use crate::team::{Team, TeamName};

/// `hardening.weebo.io/access` — the catalogue key an endpoint resolves to.
pub const ACCESS_ANNOTATION: &str = "hardening.weebo.io/access";
/// `hardening.weebo.io/allow-users`.
pub const ALLOW_USERS_ANNOTATION: &str = "hardening.weebo.io/allow-users";
/// `hardening.weebo.io/allow-groups`.
pub const ALLOW_GROUPS_ANNOTATION: &str = "hardening.weebo.io/allow-groups";
/// `hardening.weebo.io/rules` — the ordered path-rule list.
pub const RULES_ANNOTATION: &str = "hardening.weebo.io/rules";
/// `hardening.weebo.io/endpoint-auth` — `managed` once the gate is attached, `bypass` for the
/// break-glass case.
pub const ENDPOINT_AUTH_ANNOTATION: &str = "hardening.weebo.io/endpoint-auth";
/// The value [`ENDPOINT_AUTH_ANNOTATION`] carries on an object the operator gated.
pub const ENDPOINT_AUTH_MANAGED: &str = "managed";
/// The value that drops the gate for one endpoint — writable only by the operator itself and by
/// an identity in `breakGlassIdentities`.
pub const ENDPOINT_AUTH_BYPASS: &str = "bypass";
/// `hardening.weebo.io/upstream` — where a `ReverseProxy` dialect records the backend it
/// repointed away from.
pub const UPSTREAM_ANNOTATION: &str = "hardening.weebo.io/upstream";

/// The annotations a developer may edit on a gated object, and the only ones the guard lets
/// through on a DWO-generated object. Everything else there is a projection of the devfile.
pub const DEVELOPER_ANNOTATIONS: [&str; 4] = [
    ACCESS_ANNOTATION,
    ALLOW_USERS_ANNOTATION,
    ALLOW_GROUPS_ANNOTATION,
    RULES_ANNOTATION,
];

/// A catalogue key — `private`, `team`, `shared`, `open`. A newtype for the same reason
/// [`crate::RegistryKey`] is one: it must never typecheck where another feature's key is
/// expected.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct AccessKey(String);

impl AccessKey {
    /// Wrap a catalogue key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who, besides the owner, a profile may let in. A list rather than a mode, per RFC 0009: `[]`
/// says "the owner and nobody else" where an unquoted `Off` is YAML 1.1's boolean `false`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum DelegationKind {
    /// Everyone in the owner's team, derived from namespace ownership.
    Team,
    /// Whoever the owner named in `allow-users` / `allow-groups`.
    UsersAndGroups,
}

/// One catalogue entry: what a key means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessEntry {
    /// The key a grant, an annotation or a path rule names.
    pub key: AccessKey,
    /// No authentication at all. `delegation` is rejected on an anonymous entry.
    #[serde(default)]
    pub anonymous: bool,
    /// Who else, besides the owner, this profile lets in.
    #[serde(default)]
    pub delegation: Vec<DelegationKind>,
}

/// What a team may reach, and what it gets by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessGrant {
    /// The keys this team's namespaces may name.
    pub allowed: Vec<AccessKey>,
    /// The key an endpoint resolves to when it names none. Singular: an endpoint resolves to
    /// exactly one profile.
    pub default: AccessKey,
}

/// Which users an override applies to — usernames (with a trailing-`*` prefix form) or a
/// namespace selector. Both, and neither, are legal: an override matching nothing is a
/// configuration violation rather than a silent no-op.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OverrideMatch {
    /// Usernames. `contractor-*` matches by prefix.
    #[serde(default)]
    pub users: Vec<String>,
    /// Namespaces, by label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
}

impl OverrideMatch {
    /// Whether `username` is named by this matcher's `users` list.
    pub fn matches_user(&self, username: &str) -> bool {
        self.users
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => username.starts_with(prefix),
                None => pattern == username,
            })
    }

    /// Whether this matcher names nobody at all.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty() && self.namespace_selector.is_none()
    }
}

/// An admin's per-user narrowing — per-user what a grant is per-team, and **only ever a
/// narrowing**: every field is intersected with the team's, never substituted for it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EndpointOverride {
    /// Who it applies to.
    #[serde(rename = "match")]
    pub matcher: OverrideMatch,
    /// Keys this user may reach, intersected with the team's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<AccessKey>>,
    /// A default of its own, which must survive the intersection like any other key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<AccessKey>,
    /// A delegation ceiling. `Some([])` is the hard form: this user may not share an endpoint at
    /// all, whichever catalogue key they reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Vec<DelegationKind>>,
}

/// How an endpoint names the catalogue key it wants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSelection {
    /// The annotation DevWorkspace Operator copies from the devfile endpoint onto the routing
    /// object.
    pub annotation: String,
    /// RFC 0002 semantics for a key the catalogue does not define.
    pub on_unknown_key: OnUnknownKey,
}

impl Default for EndpointSelection {
    fn default() -> Self {
        Self {
            annotation: ACCESS_ANNOTATION.to_owned(),
            on_unknown_key: OnUnknownKey::Default,
        }
    }
}

/// One host-ownership pattern: how a host names the user who owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostOwnership {
    /// A template over `{user}`, `{workspace}` and `{endpoint}`, matched against the host with
    /// the suffix removed. `{user}` is the capture that matters; the others are wildcards that
    /// may not contain a dot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// An anchored regex with a named `user` capture, for a naming scheme no template describes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
}

/// Which hosts this feature governs, and how one names its owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostsConfig {
    /// The only suffix this feature governs. Must start with a dot.
    pub suffix: String,
    /// How a host names the user who owns it — first match wins.
    #[serde(default)]
    pub ownership: Vec<HostOwnership>,
    /// Hosts the gate never attaches to: the Che gateway's own, and the gateway's own.
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl HostsConfig {
    /// Whether `host` is under the governed suffix and not excluded.
    pub fn governs(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        host.ends_with(&self.suffix.to_ascii_lowercase())
            && !self
                .exclude
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(&host))
    }

    /// The user `host` names, by the first pattern that matches it.
    ///
    /// `None` means "no pattern ties this host to a user", which at admission is a refusal
    /// naming the pattern list — never a silent allow, because a host nobody owns is a host
    /// whose policy nobody owns either.
    pub fn owner_of(&self, host: &str) -> Option<String> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let suffix = self.suffix.to_ascii_lowercase();
        let stem = host.strip_suffix(&suffix)?;
        self.ownership
            .iter()
            .find_map(|pattern| pattern.owner_of(stem))
    }
}

impl HostOwnership {
    /// The user this pattern reads out of `stem` — the host with its suffix removed.
    pub fn owner_of(&self, stem: &str) -> Option<String> {
        if let Some(template) = self.template.as_deref() {
            return match_template(template, stem);
        }
        if let Some(pattern) = self.regex.as_deref() {
            let anchored = anchor(pattern);
            let regex = regex::Regex::new(&anchored).ok()?;
            return regex
                .captures(stem)
                .and_then(|captures| captures.name("user"))
                .map(|user| user.as_str().to_owned());
        }
        None
    }
}

fn anchor(pattern: &str) -> String {
    let mut anchored = String::with_capacity(pattern.len() + 2);
    if !pattern.starts_with('^') {
        anchored.push('^');
    }
    anchored.push_str(pattern);
    if !pattern.ends_with('$') {
        anchored.push('$');
    }
    anchored
}

/// Match `stem` against a `{placeholder}` template and return what `{user}` captured.
///
/// Placeholders are non-greedy and may not contain a dot: `dev.{user}-{workspace}` must not read
/// `dev.a.b-c` as `user = "a.b"`, because a dot is a label boundary and a label boundary is where
/// one person's host stops being theirs.
fn match_template(template: &str, stem: &str) -> Option<String> {
    let mut user: Option<String> = None;
    let mut rest = stem;
    let mut remaining = template;

    while !remaining.is_empty() {
        let Some(open) = remaining.find('{') else {
            return (rest == remaining).then(|| user.clone()).flatten();
        };
        let literal = &remaining[..open];
        rest = rest.strip_prefix(literal)?;
        let close = remaining[open..].find('}')? + open;
        let name = &remaining[open + 1..close];
        remaining = &remaining[close + 1..];

        let next_literal_end = remaining.find('{').unwrap_or(remaining.len());
        let next_literal = &remaining[..next_literal_end];
        let value = if next_literal.is_empty() {
            let value = rest;
            rest = "";
            value
        } else {
            let at = rest.find(next_literal)?;
            let (value, tail) = rest.split_at(at);
            rest = tail;
            value
        };
        if value.is_empty() || value.contains('.') {
            return None;
        }
        if name == "user" {
            user = Some(value.to_owned());
        }
    }
    if rest.is_empty() { user } else { None }
}

/// Where the gateway is, and how the routing object is told to consult it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayRef {
    /// Where a browser is sent to sign in.
    pub external_url: String,
    /// The gateway's in-cluster `Service`.
    pub service: ServiceRef,
    /// Which router this cluster runs.
    pub dialect: Dialect,
    /// Whether the gate's own verdict is answered or only counted.
    #[serde(default = "default_enforcement")]
    pub enforcement: GateEnforcement,
    /// Traefik only: middleware names an `Ingress` may carry **after** ours.
    #[serde(default)]
    pub allowed_middlewares: Vec<String>,
    /// `Custom` only: the annotations this cluster's controller wants, and the keys the template
    /// declares it owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<CustomDialect>,
}

fn default_enforcement() -> GateEnforcement {
    GateEnforcement::Enforce
}

/// A `Service` reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRef {
    /// Its name.
    pub name: String,
    /// Its namespace.
    pub namespace: String,
    /// Its port.
    pub port: u16,
}

impl ServiceRef {
    /// `http://<name>.<namespace>.svc:<port>` — the in-cluster URL every forward-auth dialect
    /// points at.
    pub fn url(&self) -> String {
        format!("http://{}.{}.svc:{}", self.name, self.namespace, self.port)
    }
}

/// Whether the gate answers its verdict or only records it — RFC 0009's third rollout step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum GateEnforcement {
    /// Decide, log and count; answer `200` regardless.
    Observe,
    /// Answer what was decided.
    Enforce,
}

/// The `Custom` dialect's operator-written template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CustomDialect {
    /// The annotations to write. `${gateway_url}`, `${gateway_external_url}` and
    /// `${middleware}` are substituted.
    pub annotations: BTreeMap<String, String>,
    /// The annotation keys this template owns, declared rather than discovered: the guard pins
    /// them by value and cannot read them out of a rendered string. A key written but not
    /// declared is a configuration violation, not an unguarded annotation.
    #[serde(default)]
    pub managed_keys: Vec<String>,
}

/// How a dialect attaches the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AttachmentMode {
    /// The router asks the gateway per request; traffic never touches it.
    ForwardAuth,
    /// The router has no auth hook: the route is pointed at the gateway, which decides and then
    /// proxies to the workspace `Service`.
    ReverseProxy,
}

/// Which routing object a dialect attaches to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum RoutingKind {
    /// `networking.k8s.io/v1` `Ingress`.
    Ingress,
    /// `route.openshift.io/v1` `Route`.
    Route,
}

impl RoutingKind {
    /// The lowercase plural, as an admission request spells it.
    pub fn plural(self) -> &'static str {
        match self {
            Self::Ingress => "ingresses",
            Self::Route => "routes",
        }
    }

    /// The `kind`, as a metric label and a log field — never a branch, per RFC 0008's rule for
    /// `resource`.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Ingress => "Ingress",
            Self::Route => "Route",
        }
    }

    /// The plural, parsed back from an admission request.
    pub fn from_plural(plural: &str) -> Option<Self> {
        match plural {
            "ingresses" => Some(Self::Ingress),
            "routes" => Some(Self::Route),
            _ => None,
        }
    }
}

/// Which router this cluster runs. The binary speaks one vocabulary; the deployment names the
/// product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Dialect {
    /// Traefik, via one shared `forwardAuth` `Middleware`.
    Traefik,
    /// ingress-nginx, carrying the request in `auth-url` nginx variables.
    Nginx,
    /// The community `haproxy-ingress` controller.
    HaproxyIngress,
    /// OpenShift's router, which has no external-auth hook at all.
    OpenShiftRoute,
    /// An operator-written annotation template.
    Custom,
}

/// The name of the one shared Traefik `Middleware` the operator owns.
pub const MIDDLEWARE_NAME: &str = "weebo-si-endpoint-auth";

impl Dialect {
    /// Forward-auth, or carry the traffic.
    pub fn mode(self) -> AttachmentMode {
        match self {
            Self::OpenShiftRoute => AttachmentMode::ReverseProxy,
            _ => AttachmentMode::ForwardAuth,
        }
    }

    /// The routing object this dialect attaches to.
    pub fn target_kind(self) -> RoutingKind {
        match self {
            Self::OpenShiftRoute => RoutingKind::Route,
            _ => RoutingKind::Ingress,
        }
    }

    /// The annotations that attach the gate.
    pub fn annotations(self, gateway: &GatewayRef) -> BTreeMap<String, String> {
        let mut annotations = BTreeMap::new();
        let url = gateway.service.url();
        match self {
            Self::Traefik => {
                let mut chain = vec![format!(
                    "{}-{}@kubernetescrd",
                    gateway.service.namespace, MIDDLEWARE_NAME
                )];
                chain.extend(gateway.allowed_middlewares.iter().cloned());
                annotations.insert(
                    "traefik.ingress.kubernetes.io/router.middlewares".to_owned(),
                    chain.join(","),
                );
            }
            Self::Nginx => {
                // The request travels in the URL, not in a snippet: `allow-snippet-annotations`
                // has been false by default since ingress-nginx 1.9, and turning it back on
                // would trade one hardening control for another.
                annotations.insert(
                    "nginx.ingress.kubernetes.io/auth-url".to_owned(),
                    format!(
                        "{url}/auth?host=$host&uri=$request_uri&method=$request_method&proto=$scheme"
                    ),
                );
                annotations.insert(
                    "nginx.ingress.kubernetes.io/auth-response-headers".to_owned(),
                    "X-Auth-Request-User,X-Auth-Request-Groups,X-Auth-Request-Email".to_owned(),
                );
                annotations.insert(
                    "nginx.ingress.kubernetes.io/auth-signin".to_owned(),
                    format!(
                        "{}/oidc/start?rd=$scheme://$host$request_uri",
                        gateway.external_url
                    ),
                );
            }
            Self::HaproxyIngress => {
                annotations.insert(
                    "haproxy-ingress.github.io/auth-url".to_owned(),
                    format!("{url}/auth"),
                );
                annotations.insert(
                    "haproxy-ingress.github.io/auth-headers-succeed".to_owned(),
                    "x-auth-request-user,x-auth-request-groups,x-auth-request-email".to_owned(),
                );
                annotations.insert(
                    "haproxy-ingress.github.io/auth-signin".to_owned(),
                    format!("{}/oidc/start", gateway.external_url),
                );
            }
            Self::OpenShiftRoute => {
                // Nothing to ask the router: the attachment is the retarget, and the annotation
                // records where the traffic was going before.
            }
            Self::Custom => {
                if let Some(custom) = gateway.custom.as_ref() {
                    for (key, value) in &custom.annotations {
                        annotations.insert(key.clone(), render_custom(value, gateway));
                    }
                }
            }
        }
        annotations
    }

    /// The annotation keys this dialect owns — what the guard pins **by value**.
    ///
    /// Declared rather than derived from [`Self::annotations`] for the `Custom` dialect's sake:
    /// a template that writes a key it did not declare must be a configuration violation, and
    /// deriving the list would make it an unguarded annotation instead.
    pub fn managed_keys(self, gateway: &GatewayRef) -> BTreeSet<String> {
        let mut keys = BTreeSet::from([ENDPOINT_AUTH_ANNOTATION.to_owned()]);
        match self {
            Self::Custom => {
                if let Some(custom) = gateway.custom.as_ref() {
                    keys.extend(custom.managed_keys.iter().cloned());
                }
            }
            Self::OpenShiftRoute => {
                keys.insert(UPSTREAM_ANNOTATION.to_owned());
            }
            other => keys.extend(other.annotations(gateway).into_keys()),
        }
        keys
    }

    /// The kinds `policy-guard` must protect for this dialect, beyond the routing object itself.
    ///
    /// A dialect that puts the gate in a side object has moved the thing a developer can edit,
    /// and the guard has to follow it there.
    pub fn guarded_kinds(self) -> &'static [&'static str] {
        match self {
            Self::OpenShiftRoute => &["routes", "services", "endpointslices"],
            _ => &["ingresses"],
        }
    }
}

fn render_custom(template: &str, gateway: &GatewayRef) -> String {
    template
        .replace("${gateway_url}", &gateway.service.url())
        .replace("${gateway_external_url}", &gateway.external_url)
        .replace(
            "${middleware}",
            &format!(
                "{}-{}@kubernetescrd",
                gateway.service.namespace, MIDDLEWARE_NAME
            ),
        )
}

/// Where the `Route`'s backend is repointed, and where the original is recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retarget {
    /// The companion `Service` in the object's own namespace — a `Route`'s `spec.to` is a local
    /// reference with no cross-namespace form, which is the whole reason this dialect needs a
    /// companion at all.
    pub service: String,
    /// The port on it.
    pub port: u16,
    /// The backend the object pointed at before, as `<service>:<port>`, recorded in
    /// [`UPSTREAM_ANNOTATION`] so the gateway can reach it.
    pub upstream: String,
}

/// The name of the companion `Service` a `ReverseProxy` dialect needs in each workspace
/// namespace.
pub const COMPANION_SERVICE: &str = "weebo-si-endpoint-gateway";

/// What attaching the gate to one object comes to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attachment {
    /// Annotations to set, by key.
    pub annotations: BTreeMap<String, String>,
    /// Annotation keys to remove — what `mode: Off` strips, and what a dialect change leaves
    /// behind.
    pub removals: BTreeSet<String>,
    /// For a `ReverseProxy` dialect: how the backend is repointed.
    pub retarget: Option<Retarget>,
}

impl Attachment {
    /// Whether this attachment would change `current`.
    pub fn changes(&self, current: &BTreeMap<String, String>) -> bool {
        self.annotations
            .iter()
            .any(|(key, value)| current.get(key) != Some(value))
            || self.removals.iter().any(|key| current.contains_key(key))
            || self.retarget.is_some()
    }
}

/// `spec.features.endpointAuth` in full.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EndpointAuthConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the webhook's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Where the gateway is and which router attaches to it.
    pub gateway: GatewayRef,
    /// Identities that may set `hardening.weebo.io/endpoint-auth: bypass` on one object.
    #[serde(default)]
    pub break_glass_identities: Vec<String>,
    /// How a namespace names its owner, and which identity DevWorkspace Operator writes as.
    pub owner: OwnerConfig,
    /// Which hosts this feature governs.
    pub hosts: HostsConfig,
    /// The catalogue of access profiles.
    pub catalog: Vec<AccessEntry>,
    /// The key a namespace belonging to no team resolves to.
    pub default: AccessKey,
    /// Ordered, first match wins; may only narrow.
    #[serde(default)]
    pub overrides: Vec<EndpointOverride>,
    /// How an endpoint names its key.
    #[serde(default)]
    pub endpoint_selection: EndpointSelection,
    /// Whether, and how, a workspace may prove it is itself.
    #[serde(default)]
    pub self_origin: SelfOriginConfig,
    /// Per-team grants.
    #[serde(default)]
    pub grants: BTreeMap<TeamName, AccessGrant>,
}

/// How a namespace names its owner, and who DevWorkspace Operator writes as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OwnerConfig {
    /// The namespace annotation Che writes the username into.
    pub namespace_annotation: String,
    /// The full `system:serviceaccount:<ns>:<name>` DevWorkspace Operator creates these objects
    /// as. Row 2 of the guard table is inert if this is wrong, and every workspace endpoint stops
    /// being created.
    pub devworkspace_operator_identity: String,
}

/// Three-state switch for a mechanism whose safety the cluster's network decides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TriState {
    /// On only while the probe says the mechanism is sound.
    #[default]
    Auto,
    /// On, whatever the probe says — overruled by a probe that watched a forgery succeed.
    On,
    /// Off.
    Off,
}

/// Whether a workspace may reach its own endpoint without signing in, and how it proves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SelfOriginConfig {
    /// Trust the client address the controller reported.
    #[serde(default)]
    pub pod_network: TriState,
    /// Accept the workspace's own service-account token — the answer where the address does not
    /// survive the network path.
    #[serde(default = "yes")]
    pub service_account_token: bool,
}

fn yes() -> bool {
    true
}

impl Default for SelfOriginConfig {
    fn default() -> Self {
        Self {
            pod_network: TriState::Auto,
            service_account_token: true,
        }
    }
}

/// Everything wrong with an `endpointAuth` configuration, reported together rather than one at a
/// time — the same contract every other feature's `validate` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointAuthConfigViolation {
    /// Two catalogue entries share a key.
    DuplicateAccessKey(AccessKey),
    /// An entry is anonymous and delegates.
    AnonymousEntryDelegates(AccessKey),
    /// A grant, an override or `default` names a key the catalogue does not define.
    UnknownAccessKey(AccessKey),
    /// A grant's `default` is not in its own `allowed` list.
    DefaultNotAllowed {
        /// The team.
        team: TeamName,
        /// The key.
        key: AccessKey,
    },
    /// A grant names a team `spec.teams` does not define.
    UnknownTeam(TeamName),
    /// The suffix does not start with a dot, so `.weebo.si` was written `weebo.si` and
    /// `notweebo.si` would match it.
    SuffixNotDotted(String),
    /// No host-ownership pattern at all: every host would be refused at admission.
    NoHostOwnership,
    /// A pattern is neither a template nor a regex, or its regex does not compile or has no
    /// `user` capture.
    BadHostOwnership(String),
    /// An override that matches nobody.
    OverrideMatchesNothing,
    /// The `Custom` dialect is selected with no template.
    CustomDialectHasNoTemplate,
    /// A `Custom` template writes an annotation key it did not declare, which would be an
    /// unguarded annotation.
    UndeclaredManagedKey(String),
    /// The gateway's external URL is not https, so no `__Host-` cookie can be minted on it.
    GatewayUrlNotHttps(String),
}

impl fmt::Display for EndpointAuthConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAccessKey(key) => write!(f, "duplicate catalogue key {key}"),
            Self::AnonymousEntryDelegates(key) => {
                write!(f, "catalogue key {key} is anonymous and delegates")
            }
            Self::UnknownAccessKey(key) => write!(f, "no catalogue entry named {key}"),
            Self::DefaultNotAllowed { team, key } => {
                write!(f, "team {team}'s default {key} is not in its allowed list")
            }
            Self::UnknownTeam(team) => write!(f, "no team named {team} in spec.teams"),
            Self::SuffixNotDotted(suffix) => {
                write!(f, "hosts.suffix {suffix:?} must start with a dot")
            }
            Self::NoHostOwnership => f.write_str("hosts.ownership is empty: every host is refused"),
            Self::BadHostOwnership(pattern) => {
                write!(f, "host ownership pattern {pattern:?} is unusable")
            }
            Self::OverrideMatchesNothing => {
                f.write_str("an override matches neither users nor namespaces")
            }
            Self::CustomDialectHasNoTemplate => f.write_str("dialect Custom needs gateway.custom"),
            Self::UndeclaredManagedKey(key) => {
                write!(f, "custom template writes {key:?} without declaring it")
            }
            Self::GatewayUrlNotHttps(url) => write!(f, "gateway.externalUrl {url:?} must be https"),
        }
    }
}

impl EndpointAuthConfig {
    /// Every violation this configuration holds, in one pass.
    pub fn validate(&self, teams: &[Team]) -> Vec<EndpointAuthConfigViolation> {
        let mut violations = Vec::new();
        let mut keys: BTreeSet<&AccessKey> = BTreeSet::new();
        for entry in &self.catalog {
            if !keys.insert(&entry.key) {
                violations.push(EndpointAuthConfigViolation::DuplicateAccessKey(
                    entry.key.clone(),
                ));
            }
            if entry.anonymous && !entry.delegation.is_empty() {
                violations.push(EndpointAuthConfigViolation::AnonymousEntryDelegates(
                    entry.key.clone(),
                ));
            }
        }

        let known = |key: &AccessKey, violations: &mut Vec<EndpointAuthConfigViolation>| {
            if !keys.contains(key) {
                violations.push(EndpointAuthConfigViolation::UnknownAccessKey(key.clone()));
            }
        };
        known(&self.default, &mut violations);

        let team_names: BTreeSet<&TeamName> = teams.iter().map(|team| &team.name).collect();
        for (team, grant) in &self.grants {
            if !team_names.contains(team) {
                violations.push(EndpointAuthConfigViolation::UnknownTeam(team.clone()));
            }
            for key in &grant.allowed {
                known(key, &mut violations);
            }
            known(&grant.default, &mut violations);
            if !grant.allowed.contains(&grant.default) {
                violations.push(EndpointAuthConfigViolation::DefaultNotAllowed {
                    team: team.clone(),
                    key: grant.default.clone(),
                });
            }
        }

        for over in &self.overrides {
            if over.matcher.is_empty() {
                violations.push(EndpointAuthConfigViolation::OverrideMatchesNothing);
            }
            for key in over.allowed.iter().flatten() {
                known(key, &mut violations);
            }
            if let Some(default) = over.default.as_ref() {
                known(default, &mut violations);
            }
        }

        if !self.hosts.suffix.starts_with('.') {
            violations.push(EndpointAuthConfigViolation::SuffixNotDotted(
                self.hosts.suffix.clone(),
            ));
        }
        if self.hosts.ownership.is_empty() {
            violations.push(EndpointAuthConfigViolation::NoHostOwnership);
        }
        for pattern in &self.hosts.ownership {
            match (pattern.template.as_deref(), pattern.regex.as_deref()) {
                (Some(template), _) if template.contains("{user}") => {}
                (_, Some(regex)) => {
                    let compiled = regex::Regex::new(&anchor(regex));
                    let usable = compiled.as_ref().is_ok_and(|compiled| {
                        compiled.capture_names().flatten().any(|n| n == "user")
                    });
                    if !usable {
                        violations.push(EndpointAuthConfigViolation::BadHostOwnership(
                            regex.to_owned(),
                        ));
                    }
                }
                (template, _) => violations.push(EndpointAuthConfigViolation::BadHostOwnership(
                    template.unwrap_or_default().to_owned(),
                )),
            }
        }

        if !self.gateway.external_url.starts_with("https://") {
            violations.push(EndpointAuthConfigViolation::GatewayUrlNotHttps(
                self.gateway.external_url.clone(),
            ));
        }

        match (self.gateway.dialect, self.gateway.custom.as_ref()) {
            (Dialect::Custom, None) => {
                violations.push(EndpointAuthConfigViolation::CustomDialectHasNoTemplate);
            }
            (Dialect::Custom, Some(custom)) => {
                let declared: BTreeSet<&String> = custom.managed_keys.iter().collect();
                for key in custom.annotations.keys() {
                    if !declared.contains(key) {
                        violations.push(EndpointAuthConfigViolation::UndeclaredManagedKey(
                            key.clone(),
                        ));
                    }
                }
            }
            _ => {}
        }

        violations
    }

    /// What attaching the gate to one object comes to: the annotations to write, the keys to
    /// drop, and — on a `ReverseProxy` dialect — where the backend goes.
    ///
    /// `current` is the object's annotations as submitted; `backend` is its current backend, only
    /// read by a `ReverseProxy` dialect. An object carrying
    /// `hardening.weebo.io/endpoint-auth: bypass` gets **nothing**: the mutation honours the
    /// annotation by attaching nothing and the reconciler leaves it alone, so break-glass
    /// survives the next DWO pass instead of being quietly undone.
    pub fn attachment(
        &self,
        current: &BTreeMap<String, String>,
        backend: Option<(&str, u16)>,
    ) -> Attachment {
        if current.get(ENDPOINT_AUTH_ANNOTATION).map(String::as_str) == Some(ENDPOINT_AUTH_BYPASS) {
            return Attachment::default();
        }
        let mut annotations = self.gateway.dialect.annotations(&self.gateway);
        annotations.insert(
            ENDPOINT_AUTH_ANNOTATION.to_owned(),
            ENDPOINT_AUTH_MANAGED.to_owned(),
        );
        let retarget = match (self.gateway.dialect.mode(), backend) {
            (AttachmentMode::ReverseProxy, Some((service, port)))
                if service != COMPANION_SERVICE =>
            {
                let upstream = format!("{service}:{port}");
                annotations.insert(UPSTREAM_ANNOTATION.to_owned(), upstream.clone());
                Some(Retarget {
                    service: COMPANION_SERVICE.to_owned(),
                    port: self.gateway.service.port,
                    upstream,
                })
            }
            _ => None,
        };
        Attachment {
            annotations,
            removals: BTreeSet::new(),
            retarget,
        }
    }

    /// What `mode: Off` strips: every key this dialect owns, and the managed marker.
    pub fn detachment(&self) -> BTreeSet<String> {
        self.gateway.dialect.managed_keys(&self.gateway)
    }

    /// The catalogue entry a key names.
    pub fn entry(&self, key: &AccessKey) -> Option<&AccessEntry> {
        self.catalog.iter().find(|entry| &entry.key == key)
    }

    /// The grant that applies to a namespace in `team`, or the cluster default for a namespace in
    /// no team.
    pub fn grant_for(&self, team: Option<&TeamName>) -> AccessGrant {
        team.and_then(|team| self.grants.get(team))
            .cloned()
            .unwrap_or_else(|| AccessGrant {
                allowed: vec![self.default.clone()],
                default: self.default.clone(),
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

    fn hosts() -> HostsConfig {
        HostsConfig {
            suffix: ".weebo.si".to_owned(),
            ownership: vec![
                HostOwnership {
                    template: Some("{user}-{workspace}-{endpoint}".to_owned()),
                    regex: None,
                },
                HostOwnership {
                    template: Some("dev.{user}-{workspace}".to_owned()),
                    regex: None,
                },
            ],
            exclude: vec!["che.weebo.si".to_owned(), "auth.weebo.si".to_owned()],
        }
    }

    fn gateway(dialect: Dialect) -> GatewayRef {
        GatewayRef {
            external_url: "https://auth.weebo.si".to_owned(),
            service: ServiceRef {
                name: "endpoint-gateway".to_owned(),
                namespace: "weebo-si-hardening".to_owned(),
                port: 4180,
            },
            dialect,
            enforcement: GateEnforcement::Enforce,
            allowed_middlewares: Vec::new(),
            custom: None,
        }
    }

    fn config(dialect: Dialect) -> EndpointAuthConfig {
        EndpointAuthConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            gateway: gateway(dialect),
            break_glass_identities: Vec::new(),
            owner: OwnerConfig {
                namespace_annotation: "che.eclipse.org/username".to_owned(),
                devworkspace_operator_identity:
                    "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount"
                        .to_owned(),
            },
            hosts: hosts(),
            catalog: vec![
                AccessEntry {
                    key: AccessKey::new("private"),
                    anonymous: false,
                    delegation: Vec::new(),
                },
                AccessEntry {
                    key: AccessKey::new("team"),
                    anonymous: false,
                    delegation: vec![DelegationKind::Team],
                },
                AccessEntry {
                    key: AccessKey::new("open"),
                    anonymous: true,
                    delegation: Vec::new(),
                },
            ],
            default: AccessKey::new("private"),
            overrides: Vec::new(),
            endpoint_selection: EndpointSelection::default(),
            self_origin: SelfOriginConfig::default(),
            grants: BTreeMap::new(),
        }
    }

    #[test]
    fn a_host_names_its_owner_through_the_first_matching_pattern() {
        let hosts = hosts();
        assert_eq!(
            hosts.owner_of("alice-ws-api.weebo.si").as_deref(),
            Some("alice")
        );
        assert_eq!(
            hosts.owner_of("dev.bob-payments.weebo.si").as_deref(),
            Some("bob")
        );
        // A host under the suffix that no pattern describes belongs to nobody, which at
        // admission is a refusal naming the patterns rather than a silent allow.
        assert_eq!(hosts.owner_of("something.weebo.si"), None);
        assert_eq!(hosts.owner_of("alice-ws-api.example.com"), None);
    }

    #[test]
    fn a_placeholder_never_eats_a_label_boundary() {
        // `dev.a.b-c` must not read as user `a.b`: a dot is where one person's host stops being
        // theirs, and a greedy placeholder is how a second user's name ends up inside a first
        // user's capture.
        let hosts = hosts();
        assert_eq!(hosts.owner_of("dev.a.b-c.weebo.si"), None);
    }

    #[test]
    fn an_anchored_regex_with_a_user_capture_is_the_escape_hatch() {
        let hosts = HostsConfig {
            suffix: ".weebo.si".to_owned(),
            ownership: vec![HostOwnership {
                template: None,
                regex: Some(r"ws-(?<user>[a-z0-9]+)-[0-9]+".to_owned()),
            }],
            exclude: Vec::new(),
        };
        assert_eq!(
            hosts.owner_of("ws-carol-42.weebo.si").as_deref(),
            Some("carol")
        );
        // Anchored on both ends, so a prefix that merely contains the shape does not match.
        assert_eq!(hosts.owner_of("evil-ws-carol-42.weebo.si"), None);
    }

    #[test]
    fn the_governed_set_is_a_suffix_minus_the_exclusions() {
        let hosts = hosts();
        assert!(hosts.governs("alice-ws-api.weebo.si"));
        assert!(!hosts.governs("che.weebo.si"));
        assert!(!hosts.governs("notweebo.si"));
    }

    #[test]
    fn traefik_pins_a_chain_and_not_a_presence() {
        let mut gateway = gateway(Dialect::Traefik);
        gateway.allowed_middlewares = vec!["traefik-compress@kubernetescrd".to_owned()];
        let annotations = Dialect::Traefik.annotations(&gateway);
        assert_eq!(
            annotations["traefik.ingress.kubernetes.io/router.middlewares"],
            "weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd,traefik-compress@kubernetescrd"
        );
        // Ours is first, always: the chain runs before forwardAuth, so an entry in front of it
        // could rewrite the request the gate then decides on.
        assert!(
            annotations["traefik.ingress.kubernetes.io/router.middlewares"]
                .starts_with("weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd")
        );
    }

    #[test]
    fn nginx_carries_the_request_in_the_url_because_snippets_are_off_by_default() {
        let annotations = Dialect::Nginx.annotations(&gateway(Dialect::Nginx));
        let url = &annotations["nginx.ingress.kubernetes.io/auth-url"];
        for variable in ["$host", "$request_uri", "$request_method", "$scheme"] {
            assert!(url.contains(variable), "{url}");
        }
        assert!(annotations.contains_key("nginx.ingress.kubernetes.io/auth-response-headers"));
        assert!(annotations.contains_key("nginx.ingress.kubernetes.io/auth-signin"));
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_openshift_dialect_retargets_instead_of_annotating() {
        let config = config(Dialect::OpenShiftRoute);
        let attachment = config.attachment(&BTreeMap::new(), Some(("my-app", 8080)));
        let retarget = attachment.retarget.unwrap();
        assert_eq!(retarget.service, COMPANION_SERVICE);
        assert_eq!(retarget.upstream, "my-app:8080");
        assert_eq!(attachment.annotations[UPSTREAM_ANNOTATION], "my-app:8080");
        // Idempotent: an object already pointing at the companion is not retargeted again, or
        // the upstream annotation would record the gateway as its own backend.
        let second = config.attachment(&attachment.annotations, Some((COMPANION_SERVICE, 4180)));
        assert!(second.retarget.is_none());
    }

    #[test]
    fn break_glass_attaches_nothing_at_all() {
        let config = config(Dialect::Traefik);
        let current = BTreeMap::from([(
            ENDPOINT_AUTH_ANNOTATION.to_owned(),
            ENDPOINT_AUTH_BYPASS.to_owned(),
        )]);
        let attachment = config.attachment(&current, None);
        assert!(attachment.annotations.is_empty());
        assert!(!attachment.changes(&current));
    }

    #[test]
    fn the_managed_keys_are_what_off_strips_and_what_the_guard_pins() {
        let config = config(Dialect::Traefik);
        let keys = config.detachment();
        assert!(keys.contains("traefik.ingress.kubernetes.io/router.middlewares"));
        assert!(keys.contains(ENDPOINT_AUTH_ANNOTATION));
        // The developer's own annotations are never in that set: they are the one thing a
        // developer controls.
        for developer_key in DEVELOPER_ANNOTATIONS {
            assert!(!keys.contains(developer_key), "{developer_key}");
        }
    }

    #[test]
    fn a_custom_template_must_declare_every_key_it_writes() {
        let mut config = config(Dialect::Custom);
        config.gateway.custom = Some(CustomDialect {
            annotations: BTreeMap::from([
                ("x/auth-url".to_owned(), "${gateway_url}/auth".to_owned()),
                ("x/sign-in".to_owned(), "${gateway_external_url}".to_owned()),
            ]),
            managed_keys: vec!["x/auth-url".to_owned()],
        });
        let violations = config.validate(&[]);
        assert!(
            violations.contains(&EndpointAuthConfigViolation::UndeclaredManagedKey(
                "x/sign-in".to_owned()
            ))
        );

        let rendered = Dialect::Custom.annotations(&config.gateway);
        assert_eq!(
            rendered["x/auth-url"],
            "http://endpoint-gateway.weebo-si-hardening.svc:4180/auth"
        );
    }

    #[test]
    fn validation_reports_every_problem_in_one_pass() {
        let mut config = config(Dialect::Traefik);
        config.hosts.suffix = "weebo.si".to_owned();
        config.gateway.external_url = "http://auth.weebo.si".to_owned();
        config.default = AccessKey::new("nonexistent");
        config.grants.insert(
            TeamName::new("ghost"),
            AccessGrant {
                allowed: vec![AccessKey::new("private")],
                default: AccessKey::new("team"),
            },
        );
        let violations = config.validate(&[]);
        assert!(
            violations.contains(&EndpointAuthConfigViolation::SuffixNotDotted(
                "weebo.si".to_owned()
            ))
        );
        assert!(
            violations.contains(&EndpointAuthConfigViolation::GatewayUrlNotHttps(
                "http://auth.weebo.si".to_owned()
            ))
        );
        assert!(
            violations.contains(&EndpointAuthConfigViolation::UnknownAccessKey(
                AccessKey::new("nonexistent")
            ))
        );
        assert!(
            violations.contains(&EndpointAuthConfigViolation::UnknownTeam(TeamName::new(
                "ghost"
            )))
        );
        assert!(
            violations.contains(&EndpointAuthConfigViolation::DefaultNotAllowed {
                team: TeamName::new("ghost"),
                key: AccessKey::new("team"),
            })
        );
    }

    #[test]
    fn an_anonymous_entry_may_not_delegate() {
        let mut config = config(Dialect::Traefik);
        config.catalog.push(AccessEntry {
            key: AccessKey::new("open-ish"),
            anonymous: true,
            delegation: vec![DelegationKind::Team],
        });
        assert!(config.validate(&[]).contains(
            &EndpointAuthConfigViolation::AnonymousEntryDelegates(AccessKey::new("open-ish"))
        ));
    }

    #[test]
    fn a_namespace_in_no_team_gets_the_closed_cluster_default() {
        let config = config(Dialect::Traefik);
        let grant = config.grant_for(None);
        assert_eq!(grant.default, AccessKey::new("private"));
        assert_eq!(grant.allowed, vec![AccessKey::new("private")]);
    }

    #[test]
    fn the_dialect_decides_which_kinds_the_guard_must_cover() {
        // The three dialects this repo actually supports today. `guarded_kinds()` is the part
        // that is easy to forget and expensive to omit: a dialect that puts the gate in a side
        // object has moved the thing a developer can edit, and the guard has to follow it there.
        for dialect in [Dialect::Traefik, Dialect::Nginx, Dialect::HaproxyIngress] {
            assert_eq!(dialect.guarded_kinds(), &["ingresses"], "{dialect:?}");
            assert_eq!(dialect.target_kind(), RoutingKind::Ingress, "{dialect:?}");
            assert_eq!(dialect.mode(), AttachmentMode::ForwardAuth, "{dialect:?}");
        }
        assert_eq!(
            RoutingKind::from_plural("ingresses"),
            Some(RoutingKind::Ingress)
        );
        assert_eq!(RoutingKind::from_plural("pods"), None);
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_openshift_dialect_would_move_the_gate_into_two_more_kinds() {
        assert_eq!(
            Dialect::OpenShiftRoute.guarded_kinds(),
            &["routes", "services", "endpointslices"]
        );
        assert_eq!(Dialect::OpenShiftRoute.target_kind(), RoutingKind::Route);
        assert_eq!(Dialect::OpenShiftRoute.mode(), AttachmentMode::ReverseProxy);
        assert_eq!(RoutingKind::from_plural("routes"), Some(RoutingKind::Route));
    }
}
