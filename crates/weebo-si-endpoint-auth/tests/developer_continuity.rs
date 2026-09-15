//! *Developer continuity*, as an executable table — RFC 0009 says every row of that section is a
//! conformance test rather than an intention, and this file is that claim made good at the level
//! that needs no cluster.
//!
//! The rows about wire behaviour (a `Set-Cookie` surviving Traefik, a WebSocket upgrade actually
//! upgrading) belong to the dialect conformance suite and are named here as absences rather than
//! quietly dropped. Everything else — who gets in, who does not, and *how* each caller is told —
//! is decided by `decide()`, and is asserted below.
//!
//! These are the tests most likely to be the ones deleted when they get in the way, which is
//! exactly why they live in their own file with the RFC's own words as their names.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion, or a fixture that does not build, is the test failing"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use weebo_si_endpoint_auth::compile::{CompileSettings, compile};
use weebo_si_endpoint_auth::decide::{
    AuthRequest, Challenge, Decision, Reason, RequestShape, Scheme, Verdict, decide,
};
use weebo_si_endpoint_auth::host::{Host, HostScope};
use weebo_si_endpoint_auth::identity::{Claims, Credential, NamespaceName, TeamName, Username};
use weebo_si_endpoint_auth::index::CatalogLookup;
use weebo_si_endpoint_auth::policy::{EndpointPolicy, Method};
use weebo_si_endpoint_auth::testing::{catalogue, full_grant, raw_endpoint};

const HOST: &str = "alice-ws-api.weebo.si";

fn scope() -> HostScope {
    HostScope::new(".weebo.si", ["che.weebo.si", "auth.weebo.si"]).expect("fixture scope")
}

/// Alice's endpoint, shared with her team and with `bob`, with `/actuator/` kept private and
/// `/healthz` open — the shape RFC 0009's *What the developer writes* uses as its example.
fn endpoint() -> EndpointPolicy {
    let mut raw = raw_endpoint("user-alice", "alice");
    raw.access = Some("shared".into());
    raw.allow_users = Some("bob".into());
    raw.rules = Some(
        [
            "- { path: /healthz, match: exact, access: open }",
            "- { path: /actuator/, match: prefix, access: private }",
            "- { path: /, match: prefix, access: shared }",
        ]
        .join("\n"),
    );
    let mut policy = compile(
        &raw,
        &catalogue(),
        &full_grant(),
        &[],
        &CompileSettings::default(),
        1,
    )
    .expect("the fixture endpoint must compile");
    policy.team = Some(TeamName::new("team-1"));
    policy
}

fn lookup() -> CatalogLookup {
    CatalogLookup::Policy(Arc::new(endpoint()))
}

fn request(path: &str, shape: RequestShape) -> AuthRequest {
    AuthRequest {
        host: Host::parse(HOST).expect("fixture host"),
        raw_path: path.to_owned(),
        method: Method::Get,
        scheme: Scheme::Https,
        shape,
        preflight: false,
    }
}

fn verdict(request: &AuthRequest, credential: &Credential) -> Decision {
    decide(request, &scope(), &lookup(), credential)
}

fn alice() -> Credential {
    Credential::Session(Claims::in_team("alice", "team-1"))
}

#[test]
fn opening_their_endpoint_in_a_browser() {
    // "Three redirects, no login screen after the first sign-in of the day" — the part `decide()`
    // owns is that a browser with no session is *redirected* rather than refused.
    let decision = verdict(&request("/", RequestShape::Navigation), &Credential::None);
    assert_eq!(decision.verdict, Verdict::Challenge(Challenge::Redirect));
    // ...and that the same browser with a session simply passes.
    assert!(verdict(&request("/", RequestShape::Navigation), &alice()).is_allow());
}

#[test]
fn an_spa_on_one_endpoint_calling_their_api_on_another() {
    // Same registrable domain, so the host cookie rides on the `fetch`. What must not happen is a
    // redirect, which the browser turns into an opaque CORS failure attributed to their own code.
    let decision = verdict(
        &request("/api/items", RequestShape::Other),
        &Credential::None,
    );
    assert_eq!(
        decision.verdict,
        Verdict::Challenge(Challenge::Unauthorized)
    );
}

#[test]
fn hmr_and_websocket_reconnects_are_decided_from_the_same_cookie() {
    // The upgrade request is a request like any other: it carries the cookie, it is decided once,
    // and nothing about it is special to the gate.
    let upgrade = request("/_next/webpack-hmr", RequestShape::Other);
    assert!(verdict(&upgrade, &alice()).is_allow());
    assert!(!verdict(&upgrade, &Credential::None).is_allow());
}

#[test]
fn calling_the_endpoint_from_their_own_workspace() {
    // Nothing to do: the pod's own address is the owner.
    assert_eq!(
        verdict(
            &request("/api/items", RequestShape::Other),
            &Credential::PodOrigin(NamespaceName::new("user-alice")),
        ),
        Decision {
            verdict: Verdict::Allow,
            reason: Reason::SelfOrigin,
        }
    );
}

#[test]
fn the_same_on_a_cluster_that_snats_the_client_address() {
    // The workspace service-account token DevWorkspace Operator already mounts, in one header.
    assert_eq!(
        verdict(
            &request("/api/items", RequestShape::Other),
            &Credential::ServiceAccount(NamespaceName::new("user-alice")),
        )
        .reason,
        Reason::SelfOrigin
    );
}

#[test]
fn curl_postman_pytest_and_ci() {
    // A token this cluster's issuer minted, verified and then *authorised* — same owner check,
    // same delegation, same path rules as a cookie.
    assert!(
        verdict(
            &request("/api/items", RequestShape::Other),
            &Credential::Bearer(Claims::in_team("alice", "team-1")),
        )
        .is_allow()
    );
    assert!(
        !verdict(
            &request("/api/items", RequestShape::Other),
            &Credential::Bearer(Claims::user("mallory")),
        )
        .is_allow()
    );
}

#[test]
fn an_app_that_has_its_own_token_auth() {
    let mut raw = raw_endpoint("user-alice", "alice");
    raw.rules =
        Some("- { path: /api/, match: prefix, access: private, bearer: Passthrough }".into());
    let policy = compile(
        &raw,
        &catalogue(),
        &full_grant(),
        &[],
        &CompileSettings::default(),
        1,
    )
    .expect("fixture");
    let lookup = CatalogLookup::Policy(Arc::new(policy));
    let decision = decide(
        &request("/api/items", RequestShape::Other),
        &scope(),
        &lookup,
        &Credential::ForeignBearer,
    );
    assert_eq!(decision.reason, Reason::BearerPassthrough);
    // And only there: the same header anywhere else is a `401`.
    let elsewhere = decide(
        &request("/", RequestShape::Other),
        &scope(),
        &lookup,
        &Credential::ForeignBearer,
    );
    assert!(!elsewhere.is_allow());
}

#[test]
fn a_session_expiring_mid_task_is_a_401_and_never_a_redirect() {
    // "An XHR gets `401`, never a redirect" — losing a POST body to a redirect is the failure
    // people remember.
    let mut post = request("/api/items", RequestShape::Other);
    post.method = Method::Post;
    assert_eq!(
        verdict(&post, &Credential::None).verdict,
        Verdict::Challenge(Challenge::Unauthorized)
    );
}

#[test]
fn a_probe_an_uptime_check_or_a_third_party_webhook() {
    assert_eq!(
        verdict(&request("/healthz", RequestShape::Other), &Credential::None),
        Decision {
            verdict: Verdict::Allow,
            reason: Reason::Anonymous,
        }
    );
    // Scoped to that path: the open rule is not a hole in the endpoint.
    assert!(!verdict(&request("/", RequestShape::Other), &Credential::None).is_allow());
}

#[test]
fn opening_an_endpoint_in_the_ides_preview_iframe() {
    // A page with a sign-in link, never a redirect the identity provider will refuse to be framed
    // in — the difference between "the preview is broken" and one click.
    let decision = verdict(&request("/", RequestShape::Framed), &Credential::None);
    assert_eq!(decision.verdict, Verdict::Challenge(Challenge::FramedPage));
}

#[test]
fn an_endpoint_served_over_plain_http_is_refused_with_the_reason() {
    let mut insecure = request("/", RequestShape::Navigation);
    insecure.scheme = Scheme::Http;
    assert_eq!(verdict(&insecure, &alice()).reason, Reason::InsecureScheme);
}

#[test]
fn their_account_disabled_while_they_work() {
    // Cut off within informer lag, not at the end of a twelve-hour session — and *told* that it
    // was a logout rather than a missing sign-in.
    let decision = verdict(
        &request("/", RequestShape::Navigation),
        &Credential::RevokedSession,
    );
    assert_eq!(decision.reason, Reason::Revoked);
    assert!(matches!(decision.verdict, Verdict::Challenge(_)));
}

#[test]
fn a_colleague_reaches_it_and_a_stranger_does_not() {
    assert_eq!(
        verdict(
            &request("/", RequestShape::Navigation),
            &Credential::Session(Claims::in_team("carol", "team-1")),
        )
        .reason,
        Reason::Delegated
    );
    assert_eq!(
        verdict(
            &request("/", RequestShape::Navigation),
            &Credential::Session(Claims::user("mallory")),
        )
        .reason,
        Reason::NotOwner
    );
}

#[test]
fn narrowing_is_invisible_to_the_owner_and_the_whole_point_for_the_delegate() {
    let bob = Credential::Session(Claims::user("bob"));
    assert!(verdict(&request("/", RequestShape::Navigation), &bob).is_allow());
    assert!(!verdict(&request("/actuator/env", RequestShape::Navigation), &bob).is_allow());
    assert!(
        verdict(
            &request("/actuator/env", RequestShape::Navigation),
            &alice()
        )
        .is_allow()
    );
}

#[test]
fn the_rows_this_table_cannot_cover_are_named_rather_than_dropped() {
    // Left to the dialect conformance suite, because they are properties of a *controller*
    // rather than of a decision:
    //
    //   * "a `3xx` from `/auth`, `Set-Cookie` included, reaches the browser unaltered";
    //   * "the non-`2xx` body and status reach the client unchanged";
    //   * an `Upgrade` handshake actually completing through the middleware;
    //   * the sliding re-mint landing in the browser, which needs Traefik's
    //     `addAuthCookiesToResponse`.
    //
    // This test exists so that list is in the suite rather than only in an RFC, and so the next
    // person to write the conformance run finds it here.
    let outstanding: BTreeSet<&str> = BTreeSet::from([
        "set_cookie_on_3xx",
        "body_and_status_on_non_2xx",
        "websocket_upgrade",
        "sliding_remint_reaches_the_browser",
    ]);
    assert_eq!(outstanding.len(), 4);
    // The one thing this file *can* assert about them: the gate's own answer carries the pieces
    // those rows are about.
    let denial = verdict(
        &request("/actuator/env", RequestShape::Navigation),
        &Credential::Session(Claims::user("bob")),
    );
    assert_eq!(denial.verdict, Verdict::Deny);
    assert_eq!(denial.reason, Reason::NotOwner);
    assert_eq!(Username::new("alice").as_str(), "alice");
}
