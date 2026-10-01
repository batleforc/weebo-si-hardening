//! What one `/auth` request costs, step by step and per credential — measured in process.
//!
//! RFC 0009's *Request cost* claims single-digit microseconds of compute plus one round trip, and
//! `crates/weebo-si-endpoint-auth/benches/decide.rs` defends the decision half of that. This is
//! the rest of the handler: opening the cookie, verifying a bearer, the caches in front of both,
//! re-sealing a sliding cookie, and the side work every request pays whatever the verdict — the
//! metric, the identity headers, the log line. Each step is timed alone, so the table says which
//! one a regression landed in rather than only that the total moved.
//!
//! Not a gate: the numbers depend on the machine, so the only assertions are loose guards an
//! order of magnitude above what any of these should cost — and only in an optimised build,
//! because an unoptimised one is not the binary anybody deploys (ES256 alone is ~3 ms there).
//! Run on purpose, with `--release`:
//!
//! ```text
//! cargo test --release -p endpoint-gateway --bin endpoint-gateway cost -- --ignored --nocapture --test-threads=1
//! ```
//!
//! What it cannot see is I/O: a `TokenReview` for an uncached service-account token, an
//! introspection call for an opaque bearer, and the hop from the ingress controller. Those are
//! the conformance suite's latency step, against a real apiserver and a real Traefik.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    reason = "a measurement fixture that does not build is the measurement failing to start, and \
              nanosecond counts are printed as floats only for the table"
)]

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use axum::http::{HeaderMap, HeaderValue};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::jwk::JwkSet;
use weebo_si_endpoint_auth::bearer::BearerRules;
use weebo_si_endpoint_auth::cache::{CacheKind, Fingerprint, IdentityCache};
use weebo_si_endpoint_auth::compile::{CompileSettings, compile};
use weebo_si_endpoint_auth::decide::{AuthRequest, RequestShape, Scheme, decide};
use weebo_si_endpoint_auth::host::{Host, HostScope};
use weebo_si_endpoint_auth::identity::{Claims, Credential, GroupName, SessionId, TeamName};
use weebo_si_endpoint_auth::index::CatalogLookup;
use weebo_si_endpoint_auth::policy::{EndpointPolicy, Method};
use weebo_si_endpoint_auth::port::RevocationStore;
use weebo_si_endpoint_auth::testing::{catalogue, full_grant, raw_endpoint};
use weebo_si_endpoint_auth::time::Timestamp;

use crate::adapters::metrics::GatewayMetrics;
use crate::adapters::oidc::{JwksCache, JwksVerifier, VerifierPorts};
use crate::adapters::session::{Binding, SealedCodec, SealedPayload};

const HOST: &str = "alice-ws-api.weebo.si";
const ISSUER: &str = "https://sso.weebo.si/realms/weebo";
const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SAMPLES: usize = 10_000;

/// One row of the table.
struct Row {
    step: &'static str,
    case: &'static str,
    p50: f64,
    p99: f64,
}

/// Time `run` [`SAMPLES`] times after a warm-up, `batch` calls per sample so that a step much
/// cheaper than `Instant::now()` itself is not measured as the clock's own cost.
fn time(step: &'static str, case: &'static str, batch: u32, mut run: impl FnMut()) -> Row {
    for _ in 0..1_000 {
        run();
    }
    let mut samples: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let started = Instant::now();
            for _ in 0..batch {
                run();
            }
            started.elapsed().as_nanos() as f64 / f64::from(batch)
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    Row {
        step,
        case,
        p50: samples[SAMPLES / 2],
        p99: samples[SAMPLES * 99 / 100],
    }
}

fn now() -> Timestamp {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();
    Timestamp::from_secs(secs)
}

/// A session the size a real one is: a username, a handful of groups, a session id.
fn payload(expires_at: u64) -> SealedPayload {
    SealedPayload {
        username: "alice".into(),
        groups: (0..5).map(|i| format!("team-group-{i}")).collect(),
        session: Some("2f0c5a7e-1b9d-4f3e-9a51-6c0d8e7b4a21".into()),
        expires_at,
        generation: 1,
        grant_id: None,
        proved_at: 0,
        refresh: None,
        session_expires_at: Some(expires_at),
    }
}

struct NoRevocations;
impl RevocationStore for NoRevocations {
    fn is_revoked(&self, _session: &SessionId) -> bool {
        false
    }
}

/// An ES256 realm minted per run — the same shape as the verifier's own unit tests.
fn realm() -> (jsonwebtoken::EncodingKey, JwkSet) {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let point = pair.public_key().as_ref().to_vec();
    let keys = serde_json::from_value::<JwkSet>(serde_json::json!({
        "keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "cost",
            "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]),
        }]
    }))
    .unwrap();
    (jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref()), keys)
}

fn policy(edit: impl FnOnce(&mut weebo_si_endpoint_auth::compile::RawEndpoint)) -> CatalogLookup {
    let mut raw = raw_endpoint("user-alice", "alice");
    raw.team = Some(TeamName::new("team-1"));
    edit(&mut raw);
    let compiled: EndpointPolicy = compile(
        &raw,
        &catalogue(),
        &full_grant(),
        &[],
        &CompileSettings::default(),
        1,
    )
    .expect("the fixture must compile");
    CatalogLookup::Policy(Arc::new(compiled))
}

fn request(path: &str) -> AuthRequest {
    AuthRequest {
        host: Host::parse(HOST).unwrap(),
        raw_path: path.to_owned(),
        method: Method::Get,
        scheme: Scheme::Https,
        shape: RequestShape::Other,
        preflight: false,
    }
}

#[test]
#[ignore = "a measurement, not a check: run with --release --ignored --nocapture --test-threads=1"]
fn what_each_step_of_an_auth_request_costs() {
    let mut rows = Vec::new();
    let now = now();
    let later = now.plus_secs(3_600);
    let expires = later.as_secs();

    // --- the four inputs ---------------------------------------------------------------------
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("x-forwarded-host", HOST),
        ("x-forwarded-uri", "/static/app.4f2a1c.js?v=3"),
        ("x-forwarded-method", "GET"),
        ("x-forwarded-proto", "https"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    let query = HashMap::new();
    rows.push(time("parse", "forwarded headers + Host", 16, || {
        let parsed = crate::http::forwarded(black_box(&headers), &query);
        black_box(Host::parse(black_box(HOST)).ok());
        black_box(parsed.is_ok());
    }));

    // --- the host session cookie -------------------------------------------------------------
    let codec = SealedCodec::new(&[KEY.to_owned()]).unwrap();
    let sealed = codec
        .seal(&payload(expires), Binding::HostBound(HOST))
        .unwrap();
    rows.push(time(
        "session",
        "Fingerprint::scoped (cookie hash)",
        16,
        || {
            black_box(Fingerprint::scoped(HOST, black_box(&sealed)));
        },
    ));
    let sessions: IdentityCache<Claims> = IdentityCache::new(CacheKind::Session, 10_000, 600);
    let key = Fingerprint::scoped(HOST, &sealed);
    sessions.insert(key, payload(expires).claims(), later, now);
    rows.push(time("session", "cache hit (hash + get)", 16, || {
        let key = Fingerprint::scoped(HOST, black_box(&sealed));
        black_box(sessions.get(&key, now));
    }));
    rows.push(time("session", "cold: AES-GCM open + JSON", 4, || {
        black_box(codec.open(black_box(&sealed), Binding::HostBound(HOST), now));
    }));
    rows.push(time(
        "session",
        "slide re-mint: JSON + AES-GCM seal",
        4,
        || {
            black_box(codec.seal(black_box(&payload(expires)), Binding::HostBound(HOST)));
        },
    ));

    // --- an OIDC bearer ----------------------------------------------------------------------
    let (signing, keys) = realm();
    let cache = JwksCache::default();
    cache.store(keys);
    let verifier = JwksVerifier::new(VerifierPorts {
        cache,
        issuer: ISSUER.into(),
        client_id: "che-client".into(),
        rules: Some(BearerRules::new(ISSUER, ["endpoint-gateway"], Vec::<String>::new()).unwrap()),
        revocations: Arc::new(NoRevocations),
        metrics: None,
        username_claim: "preferred_username".into(),
        groups_claim: "groups".into(),
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("cost".into());
    let token = jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "iss": ISSUER, "aud": "endpoint-gateway", "exp": expires, "typ": "Bearer",
            "preferred_username": "alice", "groups": ["team-group-0", "team-group-1"],
        }),
        &signing,
    )
    .unwrap();
    assert!(
        verifier.examine(&token, now).identity.is_some(),
        "the fixture token must verify, or the row below measures a refusal"
    );
    rows.push(time("bearer", "cold: ES256 verify + claims", 1, || {
        black_box(verifier.examine(black_box(&token), now));
    }));
    let bearers: IdentityCache<Claims> = IdentityCache::new(CacheKind::Bearer, 10_000, 600);
    bearers.insert(Fingerprint::of(&token), Claims::user("alice"), later, now);
    rows.push(time("bearer", "cache hit (hash + get)", 16, || {
        black_box(bearers.get(&Fingerprint::of(black_box(&token)), now));
    }));

    // --- the decision, per kind of access ----------------------------------------------------
    let scope = HostScope::new(".weebo.si", ["che.weebo.si"]).unwrap();
    let private = policy(|_| {});
    let team = policy(|raw| raw.access = Some("team".into()));
    let shared = policy(|raw| {
        raw.access = Some("shared".into());
        raw.allow_users = Some("bob,carol,dave,erin,frank".into());
        raw.allow_groups = Some("qa,ops".into());
    });
    let open = policy(|raw| raw.access = Some("open".into()));
    let sixteen = policy(|raw| {
        raw.rules = Some(
            (0..15)
                .map(|i| format!("- {{ path: /p{i}/, match: prefix, access: private }}"))
                .chain(std::iter::once(
                    "- { path: /, match: prefix, access: shared }".to_owned(),
                ))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    });
    let asset = request("/static/app.4f2a1c.js");
    let deep = request("/p14/some/deep/path");
    let owner = Credential::Session(Claims::user("alice"));
    let mut mate = Claims::user("carol");
    mate.team = Some(TeamName::new("team-1"));
    let teammate = Credential::Session(mate);
    let mut listed_claims = Claims::user("frank");
    listed_claims.groups.insert(GroupName::new("ops"));
    let listed = Credential::Session(listed_claims);
    let stranger = Credential::Session(Claims::user("mallory"));
    for (case, lookup, req, credential) in [
        ("owner (private)", &private, &asset, &owner),
        ("teammate (team)", &team, &asset, &teammate),
        ("listed user/group (shared)", &shared, &asset, &listed),
        ("anonymous (open)", &open, &asset, &Credential::None),
        ("owner, 16 path rules", &sixteen, &deep, &owner),
        ("stranger (deny)", &private, &asset, &stranger),
        (
            "no credential (challenge)",
            &private,
            &asset,
            &Credential::None,
        ),
    ] {
        rows.push(time("decide", case, 16, || {
            black_box(decide(black_box(req), &scope, lookup, credential));
        }));
    }

    // --- the side work every request pays ----------------------------------------------------
    let registry = prometheus::Registry::new();
    let metrics = GatewayMetrics::register(&registry).unwrap();
    let decision = decide(&asset, &scope, &private, &owner);
    rows.push(time(
        "side",
        "metrics.decided (counter + histogram)",
        16,
        || {
            metrics.decided(black_box(decision), 0.000_05);
        },
    ));
    let mut claims = payload(expires).claims();
    claims.team = Some(TeamName::new("team-1"));
    rows.push(time("side", "set_identity_headers", 16, || {
        let mut out = HeaderMap::new();
        crate::http::set_identity_headers(&mut out, black_box(&claims));
        black_box(out);
    }));
    let logged: IdentityCache<()> = IdentityCache::new(CacheKind::Session, 10_000, 3_600);
    rows.push(time(
        "side",
        "allow log dedup: format + SHA-256 + get",
        16,
        || {
            let key = Fingerprint::of(&format!("{}@{HOST}", black_box(&sealed)));
            black_box(logged.get(&key, now));
        },
    ));
    let line = |out: &mut dyn std::io::Write| {
        let _ = writeln!(
            out,
            "endpoint-gateway: deny host={HOST} path=/static/app.4f2a1c.js reason=not_owner"
        );
    };
    rows.push(time(
        "side",
        "deny log line -> sink (formatting)",
        16,
        || {
            line(&mut std::io::sink());
        },
    ));
    // The real thing: `println!` locks stdout and writes a line. Under `--nocapture` that is a
    // write(2) to whatever this process's stdout is, which in a pod is the container runtime's
    // log pipe — so the number is the right order of magnitude, not the exact one.
    rows.push(time("side", "deny log line -> stdout (println)", 1, || {
        line(&mut std::io::stdout().lock());
    }));

    let mut table = String::from(
        "\n| step | credential / case | p50 ns/op | p99 ns/op |\n| --- | --- | ---: | ---: |\n",
    );
    for row in &rows {
        table.push_str(&format!(
            "| {} | {} | {:.0} | {:.0} |\n",
            row.step, row.case, row.p50, row.p99
        ));
    }
    eprintln!("{table}");
    if cfg!(debug_assertions) {
        eprintln!("unoptimised build: numbers printed, guards skipped — rerun with --release");
        return;
    }

    // Loose guards only: an order of magnitude above what each of these should cost, so a
    // noisy machine does not fail it and a step that started allocating per byte or waiting does.
    for row in &rows {
        let ceiling = match (row.step, row.case) {
            ("bearer", case) if case.starts_with("cold") => 2_000_000.0,
            ("side", case) if case.contains("stdout") => 5_000_000.0,
            ("session", case) if case.starts_with("cold") || case.starts_with("slide") => 500_000.0,
            _ => 50_000.0,
        };
        assert!(
            row.p50 < ceiling,
            "{} / {} took {:.0} ns at p50, over its {ceiling:.0} ns guard",
            row.step,
            row.case,
            row.p50
        );
    }
}
