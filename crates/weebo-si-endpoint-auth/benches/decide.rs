//! `decide()`, measured — RFC 0009's *Request cost* says a budget nobody measures is a wish.
//!
//! What this asserts is the shape of the claim, not a wall-clock number a CI runner could
//! promise: the decision is **single-digit microseconds and does no I/O**, so a page load of two
//! hundred assets costs two hundred map reads. The two benchmarks that matter are the
//! `asset_burst` one — the same host, the same cookie, two hundred times — and `sixteen_rules`,
//! which is the worst case a developer is allowed to configure.
//!
//! Run with `cargo bench -p weebo-si-endpoint-auth`. A regression here is a latency regression in
//! front of every workspace endpoint in the cluster.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a benchmark fixture that does not build is the benchmark failing to start, and the \
              message names which fixture"
)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use weebo_si_endpoint_auth::compile::{CompileSettings, compile};
use weebo_si_endpoint_auth::decide::{AuthRequest, RequestShape, Scheme, decide};
use weebo_si_endpoint_auth::host::{Host, HostScope};
use weebo_si_endpoint_auth::identity::{Claims, Credential};
use weebo_si_endpoint_auth::index::CatalogLookup;
use weebo_si_endpoint_auth::policy::{EndpointPolicy, Method};
use weebo_si_endpoint_auth::testing::{catalogue, full_grant, raw_endpoint};

const HOST: &str = "alice-ws-api.weebo.si";

fn policy(rules: Option<String>) -> EndpointPolicy {
    let mut raw = raw_endpoint("user-alice", "alice");
    raw.access = Some("shared".into());
    raw.allow_users = Some("bob,carol".into());
    raw.rules = rules;
    compile(
        &raw,
        &catalogue(),
        &full_grant(),
        &[],
        &CompileSettings::default(),
        1,
    )
    .expect("the benchmark fixture must compile")
}

fn request(path: &str) -> AuthRequest {
    AuthRequest {
        host: Host::parse(HOST).expect("fixture host"),
        raw_path: path.to_owned(),
        method: Method::Get,
        scheme: Scheme::Https,
        shape: RequestShape::Other,
        preflight: false,
    }
}

/// Time `iterations` decisions and report nanoseconds each.
fn measure(name: &str, iterations: u32, mut run: impl FnMut()) -> f64 {
    // Warm the branch predictor and the allocator the way a live process is warm.
    for _ in 0..1_000 {
        run();
    }
    let started = Instant::now();
    for _ in 0..iterations {
        run();
    }
    let each = started.elapsed().as_secs_f64() / f64::from(iterations) * 1e9;
    println!("{name:<24} {each:>9.0} ns/decision");
    each
}

fn main() {
    let scope = HostScope::new(".weebo.si", ["che.weebo.si"]).expect("fixture scope");
    let plain = CatalogLookup::Policy(Arc::new(policy(None)));
    let sixteen = CatalogLookup::Policy(Arc::new(policy(Some(
        (0..15)
            .map(|i| format!("- {{ path: /p{i}/, match: prefix, access: private }}"))
            .chain(std::iter::once(
                "- { path: /, match: prefix, access: shared }".to_owned(),
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    ))));

    let owner = Credential::Session(Claims::user("alice"));
    let delegated = Credential::Session(Claims::user("bob"));
    let stranger = Credential::Session(Claims::user("mallory"));

    let asset = request("/static/app.4f2a1c.js");
    let deep = request("/p14/some/deep/path");

    let mut results = Vec::new();
    results.push(measure("owner_allow", 200_000, || {
        black_box(decide(&asset, &scope, &plain, &owner));
    }));
    results.push(measure("delegated_allow", 200_000, || {
        black_box(decide(&asset, &scope, &plain, &delegated));
    }));
    results.push(measure("stranger_deny", 200_000, || {
        black_box(decide(&asset, &scope, &plain, &stranger));
    }));
    results.push(measure("sixteen_rules", 200_000, || {
        black_box(decide(&deep, &scope, &sixteen, &owner));
    }));
    let burst = measure("asset_burst_x200", 1_000, || {
        for index in 0..200 {
            let path = format!("/static/chunk-{index}.js");
            black_box(decide(&request(&path), &scope, &plain, &owner));
        }
    });
    println!("{:<24} {:>9.0} ns/decision", "  (per asset)", burst / 200.0);

    // The budget, asserted rather than printed: RFC 0009 promises single-digit microseconds of
    // decision, and anything above 50µs means something on this path started allocating, parsing
    // or waiting. Generous by an order of magnitude on purpose — this runs on CI hardware nobody
    // controls, and a benchmark that fails on a noisy runner is a benchmark that gets deleted.
    let worst = results.iter().copied().fold(0.0_f64, f64::max);
    assert!(
        worst < 50_000.0,
        "a decision took {worst:.0} ns; RFC 0009's *Request cost* budgets single-digit microseconds"
    );
}
