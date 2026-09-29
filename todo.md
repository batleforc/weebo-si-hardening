# Production-readiness TODO

Findings from the 2026-09-29 production-readiness review. Each item is ticked once it is fixed,
covered by a test where the code allows it, and the local gates (`task lint`, `task test`) pass.

Legend: `[ ]` open · `[x]` done · `[~]` deliberately deferred (reason inline)

## Blockers

- [x] **B1 — endpoint-gateway: state cookie opens as an SSO session.** `/oidc/start` seals the
  login state with `Binding::Sso` and the unvalidated `rd` as `username`; replayed as
  `__Host-weebo-sso` it mints a grant for any user. Give the state cookie its own binding, and
  validate `rd` at `/oidc/start` (`bins/endpoint-gateway/src/http.rs`).
  → State is its own `LoginState` type sealed under `Binding::LoginState` (cannot open as SSO or host cookie, and vice versa); `rd` validated at `/oidc/start`; state cookie cleared on every callback; `state` compared in constant time. Tests incl. `the_login_state_cookie_cannot_be_replayed_as_a_session`.
- [x] **B2 — endpoint-auth: session cache skips the host binding.** `resolve_session` keys the
  cache by cookie fingerprint only; a cache hit never checks the host. Key by host + cookie
  (`crates/weebo-si-endpoint-auth/src/application.rs`).
  → Cache keyed by `Fingerprint::scoped(host, cookie)`; test `a_cookie_cached_for_one_host_is_not_an_identity_on_another`.
- [x] **B3 — network-profiles / kubearmor-policy: reconciles delete each other's objects.** Both
  diff against every managed object in the namespace. Filter `existing` to the subject's own
  selector.
  → `weebo_si_chassis::managed::{OwnedScope, compute_owned_diff}`; `reconcile` requires `S: OwnedScope` so a subject cannot forget its scope; foreign-selector/name-collision desired objects refused; tests in both crates.
- [x] **B4 — policy-guard: namespace deletion hangs.** `DELETE` of a managed object by the
  namespace controller / garbage collector is denied. Exempt those system identities for
  `DELETE`. → Shared `weebo_si_chassis::teardown`, applied in policy-guard and registry guard; tests + RFC 0007/0008 changelog.
- [x] **B5 — operator: startup blocks on watches the chart does not grant.** Cilium watch and
  registry ConfigMap/Secret watches start regardless of RBAC flags; health server starts after
  the sync → crash loop. Gate the watches on the same flags, start health first.
  → `weebo_si_runtime::access::can_watch` (SelfSubjectAccessReview) gates the Cilium/KubeArmor capabilities, the registry-config loop and the endpoint-auth Ingress sweep (H14); `/healthz` now served before any watch syncs, `/readyz` flips last.
- [x] **B6 — `crates/weebo-si-operator/deploy/` manifests cannot start** (missing
  `--operator-identity`, `POD_NAMESPACE`, RBAC, validating webhooks, `:latest`). Remove them in
  favour of the chart, or regenerate from it.
  → Stale manifests deleted, `deploy/crd.yaml` kept (generated); docs point at the chart.

- [x] **B7 — every DevWorkspace reference used the wrong API group** (`controller.devfile.io/
  v1alpha1`, the DWOC's group). Found while fixing F6. On a real cluster no DevWorkspace webhook
  rule, watch or RBAC grant would have matched — dwoc-pin, image-policy's workspace layer and the
  network-profiles gate silently inert. Envtest passed because its fixture CRD had the same group.
  → Rules, RBAC, controller watch, fixture CRD, tests and RFC 0002/0005 examples now use
  `workspace.devfile.io/v1alpha2` (`matchPolicy: Equivalent` covers v1alpha1). **Should be
  confirmed once against a real DevWorkspace Operator install** (`task spike:*` rig).

## Release blockers

- [x] **R1 — no versioned release pipeline.** Tag-triggered workflow pushing semver images.
  → Tag-triggered `.github/workflows/release.yaml`: validates `v<semver>`, re-runs test/envtest/helm/brick scans, then publishes `{{version}}`, `{{major}}.{{minor}}`, sha tags; GitHub release notes from `cog changelog`; `cog` bump hook stamps Chart.yaml versions.
- [x] **R2 — charts cannot pull their own images.** Align `image.repository` with what CI pushes,
  allow digest pinning.
  → All charts on `ghcr.io/batleforc/<crate>`, optional `image.digest` (`repo@digest`), tag defaults to appVersion; first release is `v0.1.0`.
- [x] **R3 — no signing / SBOM / provenance on pushed images.**
  → `publish.yaml`: `sbom: true`, `provenance: mode=max`, keyless cosign signing by digest in a separate job (only job with `id-token: write`).
- [x] **R4 — no chart publishing.**
  → Charts packaged with tag version and pushed to `oci://ghcr.io/<owner>/charts` after images.

## High

- [x] **H1 — webhook never reloads its TLS certificate** (`webhook_cmd.rs`).
  → `reload_certificate` re-reads tls.crt/tls.key every 60 s and hot-swaps the rustls config on change.
- [x] **H2 — no graceful shutdown** (webhook, endpoint-gateway, preauth-proxy drain) — PID 1
  ignores SIGTERM.
  → webhook: SIGTERM → fail readiness, 5 s, then 20 s graceful drain. preauth-proxy: real drain
  bounded by `drain_timeout_secs`. Gateway: same shape as the webhook. All three done.
- [x] **H3 — endpoint-gateway permanently not-ready if the IdP is down at boot.** Retry discovery
  in the background.
  → Boot discovery retried in the background (2 s doubling to 5 min); JWKS refresh starts once it succeeds. Residual: introspection enabled with no configured endpoint still exits at boot.
- [x] **H4 — admission denies while the namespace cache lags**, even with every feature `Off`.
  → `admit` looks namespace facts up lazily, only once a feature is on; test `an_unobserved_namespace_admits_when_every_feature_is_off`. A namespace unobserved while a feature *is* on still denies (by design: no facts, no team).
- [x] **H5 — a missing template / cold cache deletes live policy** (network-profiles,
  kubearmor-policy). Fail closed: no diff when a template is unresolved.
  → Unresolved templates mark the object *held* (`DesiredState::held` / `ReconcileOutcome::held`): neither updated nor deleted; kubearmor still writes posture; tests.
- [x] **H6 — webhook PDB `maxUnavailable: 0` blocks node drains.**
  → Webhook PDB `maxUnavailable: 1` (rolling update keeps `maxUnavailable: 0`); optional `priorityClassName` for both roles.
- [x] **H7 — endpoint-gateway ingress exposes `/metrics`, `/selftest` publicly;** chart has no
  NetworkPolicy.
  → Public Ingress routes only `/oidc/start`, `/oidc/callback`, `/oidc/backchannel-logout`, `/host-session`, `/sign_out` (and `/selftest` only while the probe runs, token-gated). `/metrics` on its own port 9090 (`metrics_listen`). Optional NetworkPolicy (off by default).
- [x] **H8 — unauthenticated SA-shaped JWTs trigger unbounded TokenReviews.** Negative-cache
  failed reviews.
  → `TokenReviewer` negative-caches refusals 60 s / unreachable 5 s, bounded; 5 s call timeout; tests against a fake apiserver.
- [x] **H9 — preauth-proxy forwards upstream `Set-Cookie`** of the injected session to callers.
  → `Set-Cookie` naming the injected credential (or the passthrough marker) dropped on injected responses; 5 tests.
- [x] **H10 — preauth-proxy has no timeouts, unbounded concurrency on 4 MiB buffered bodies.**
  → New optional `limits:` block (connect/response/client-read timeouts, `max_in_flight` 256 → 503, shared 16 MiB body budget); hyper header-read timeout; tests.
- [x] **H11 — preauth-proxy chart ships no NetworkPolicy.**
  → Optional `networkPolicy` (off by default — the gateway selector is deployment-specific; enabling without a selector fails the render).
- [x] **H12 — CI: operator image path filter misses the feature crates it links;** push does not
  wait for tests.
  → Operator path filter lists all 14 linked crates (gateway gained `weebo-si-crd`); `main`/PR/schedule only build+scan, publishing only from the gated release workflow.
- [x] **H13 — no startupProbe on operator / gateway deployments.**
  → Operator: `startupProbe` on both roles, explicit probe timeouts, webhook `terminationGracePeriodSeconds: 30`. Gateway: same.
- [x] **H14 — ingress controller for endpoint-auth always starts, RBAC only behind a flag.**
  → Covered by B5: the Ingress sweep only starts when the ServiceAccount may watch ingresses.

## Medium

- [x] **M1 — sliding renewal lets a host cookie outlive its SSO session.** Cap at SSO expiry.
  → Grants and host cookies carry the SSO expiry (`se`); redeem and slide capped at it; cookies without it are not slid.
- [x] **M2 — login rate limiter can be reset by flooding keys;** CIDR trust match is a string
  prefix.
  → Full limiter evicts only refilled buckets, then refuses new keys; `Cidr` type matches by mask (IPv4-mapped IPv6 too). `"10.1"` now fails config load.
- [x] **M3 — JWKS not refreshed on unknown `kid`;** generation bumps even when keys unchanged.
  → Unknown `kid` triggers a refresh (≤ 1 per 30 s); unchanged key set no longer bumps the generation.
- [x] **M4 — leader-election renew has no timeout.**
  → Renew bounded by a 4 s timeout (demotes on timeout); lease stepped down on shutdown.
- [x] **M5 — webhook body limit (2 MB) below what an UPDATE review can carry.**
  → Webhook `DefaultBodyLimit` raised to 4 MiB.
- [x] **M6 — preauth-proxy does not URL-encode substituted secrets in form bodies.**
  → Substituted secrets percent-encoded when the configured Content-Type is form-urlencoded. Note: secrets stored pre-encoded must now be stored raw (RFC 0003 changelog).
- [x] **M7 — `ProfileKey` not validated as a DNS-1123 label.**
  → `ProfileKey`/`RuntimeProfileKey` must be DNS-1123 labels ≤ 63 (schema pattern + `validate()` → `InvalidProfileKey`); CRDs regenerated.
- [x] **M8 — namespace store: linear scan + full clone per admission.**
  → Keyed `Store::get` lookup; `managedFields`/`spec`/`status` stripped in the watch stream.
- [x] **M9 — `.trivyignore` line 1 truncated; `docs/ci.md` says images are never pushed.**
  → `.trivyignore` comment rewritten (it was committed truncated); `docs/ci.md` gained a Releases section.
- [x] **M10 — base images not pinned by digest; CI tooling floats on `latest`.**
  → Containerfiles on `rust:1.98.1-alpine3.24@sha256:…`; helm, markdownlint-cli2, cspell, semgrep, cargo-cyclonedx pinned.
- [x] **M11 — downloads in CI/tasks not checksum-verified.**
  → envtest (SHA-512) and Traefik (SHA-256) tarballs verified in CI; local task verifies too.
- [~] **M12 — readiness never un-marked** when a watch fails permanently.
  → Deferred: un-marking readiness needs per-reflector health plumbing through every store; a watch that loses its grant keeps retrying with backoff and logs every failure. Shutdown now un-marks readiness (webhook), which was the case that dropped traffic.

## Low

- [x] **L1 — `/sign_out` only clears the SSO cookie;** state cookie not cleared after callback.
  → `/sign_out` clears SSO and state cookies. No revocation recorded, deliberately: the IdP `sid` is reused on re-login (see RFC 0009 changelog).
- [x] **L2 — `/selftest` token compared in non-constant time.**
  → SHA-256 both sides + constant-time fold.
- [x] **L3 — `redeem` drops the user's own query string.**
  → Only `__weebo_grant` is removed from the query.
- [x] **L4 — passwd-append: login-name collision appends a duplicate name.**
  → Name taken by another UID → refuse with WARN (exit 0, exit 3 under `--strict`); passwd now scanned as bytes, so non-UTF-8 GECOS no longer exits 1.
- [~] **L5 — reconcile error policy retries at a flat 30 s.**
  → Deferred: flat 30 s per-object requeue is bounded load (kube-runtime de-duplicates the queue); exponential backoff is an improvement, not a production risk.
- [x] **L6 — `task ci:image` cannot build `crates/weebo-si-operator`; local tasks lack `--locked`.**
  → `task ci:image` finds `bins/` or `crates/`; `--locked` on local cargo tasks.
- [x] **L7 — `render.rs` treats a `null` parent as present** (unverified).
  → Confirmed: `null` parents are now treated as absent; test `a_null_parent_is_replaced_rather_than_written_under`.

## Follow-ups found while fixing

- [x] **F1 — preauth-proxy: JSON login bodies still take secrets raw** (a `"` in a password breaks the body).
  → `Encoding::JsonString` for `application/json` / `+json` bodies; test `json_encoding_keeps_a_secret_inside_its_string`; RFC 0003 changelog.
- [x] **F2 — preauth-proxy: no idle timeout once a response body streams; no preStop delay.**
  → Chart `preStopSleepSeconds: 5` (kubelet sleep action). Streaming idle timeout accepted, not
  added: a stalled body holds one bounded `max_in_flight` slot; documented.

- [ ] **F3 — first release: make the 4 GHCR images and 3 charts public by hand** (packages pushed
  with `GITHUB_TOKEN` start private). Manual, one-time.
- [x] **F4 — OCI charts are not signed; `cocogitto-action` fetches `cog` without a checksum.**
  → Charts signed by digest in a `sign-charts` job (keyless, `id-token` on that job only). The
  `cog` download remains unverified — it only renders release notes, accepted.
- [x] **F5 — `trivy config` flags KSV-0056 (NetworkPolicy write) on the operator RBAC** — check
  whether `task audit` fails on it.
  → It did (and did before: the old `.trivyignore` entry never matched). The write is the brick's
  purpose (RFC 0004); ignored with justification. `task audit` passes.

- [x] **F6 — profile objects carry no `ownerReference`** although RFC 0004/0006 say they do; with
  B3 fixed, a deleted workspace's objects are orphaned (harmless — they select no pods — but
  garbage).
  → Domain `Owner` on workspace objects; stores write `ownerReferences` (`controller: false`,
  `blockOwnerDeletion: false` — no extra RBAC); owner-less live objects are adopted via Update.
  Envtest asserts the reference; actual GC needs a real controller-manager (not in envtest).
- [x] **F7 — controller does not surface `ReconcileOutcome::held`.**
  → One `WARN … result=held` line per held object, both features, both passes. No metric (would
  change the RFC metrics contract).

- [x] **F8 — upgrade note: gateway `/metrics` moved to port 9090;** scrape configs must follow
  (no ServiceMonitor shipped). Documentation only — to go in the release notes.
  → In `docs/bricks/endpoint-gateway.md` and RFC 0009's changelog; the `cog changelog` release
  notes will carry the commit message.

## Second pass (2026-09-29, fresh review of the tree including the fixes above)

Findings are added below as the reviews land; `P2-*` ids.

### CI / release
- [x] **P2-C1 — `git push --follow-tags` never pushes `cog bump`'s lightweight tag** → docs push the tag by name.
- [x] **P2-C2 — cog stderr lands in release notes** → notes cut from the first `## ` heading.
- [x] **P2-C3 — release gates skip cargo-deny** → `dep-audit.yaml` is `workflow_call`ed; `images` needs it.
- [x] **P2-C4 — toolchain floats (`stable`), MSRV 1.90 untested** → `rust-toolchain.toml` 1.98.1, CI and mise pinned to it, `rust-version = "1.98"`.
- [x] **P2-C5 — cosign ref not lowercased** → one lowercased image name used for push and signature.
- [x] **P2-C6 — full re-run moves tags, `gh release create` not idempotent** → idempotent release step; docs say "re-run failed jobs".
- [x] **P2-C7 — CI helm check misses `identity.rbac.enabled`** → added.
- [x] **P2-C8 — mise helm/trivy float against CI pins** → `helm 4.3.0`, `trivy 0.74.0`.
- [x] **P2-C9 — `${{ inputs.* }}` interpolated in `run:`** → passed through `env:`.

### Operator / feature crates
- [x] **P2-O1 (High) — workspace id read from a label the DevWorkspace does not carry** (DWO keeps it
  in `status.devworkspaceId`) → every workspace pass would requeue forever on a real cluster.
  → `devworkspace_id()` reads `status.devworkspaceId`, label as fallback; both features; test.
- [x] **P2-O2 — `--cascade=orphan` DevWorkspace delete stuck:** GC's ownerReference-removing
  UPDATE on a managed object is refused by the guard.
  → `teardown_may(actor, deleting)`: garbage collector may also UPDATE; namespace controller DELETE only; tests.
- [x] **P2-O3 — one failed SelfSubjectAccessReview disables a feature for the pod's life; webhook
  and controller can disagree on Cilium → every DevWorkspace CREATE refused.** (agent)
  → `can_watch` → `Result`: only `allowed: false` means no; errors retried with backoff (≤ 60 s), then startup fails loudly (pod restarts) instead of silently disabling; 6 tests.
- [x] **P2-O4 — network-profiles / kubearmor `validate()` never called in production** (M7 key
  check, duplicate keys, missing baseline never surface as `Degraded`).
  → Both `validate()`s feed `WeeboSiConfig.status.features` (`Degraded` on violation).
- [x] **P2-O5 — namespace pass recreates the baseline in `Terminating` namespaces** (error every 30 s).
  → Namespace passes (network-profiles, kubearmor, registry-config) skip namespaces with `deletionTimestamp`.
- [x] **P2-O6 — non-leader replicas log ERROR on `step_down`.**
  → `step_down` only when this replica was leader.
- [x] **P2-O7 — `managed_in`/`has_baseline` scan every managed policy per call.** (agent)
  → `NsIndex` (namespace → keys, fed from the watch stream, relist-safe) for NetworkPolicy, Cilium and KubeArmor stores; 3 tests + envtest.
- [x] **P2-O8 — RFC 0004 RBAC table still says `controller.devfile.io/devworkspaces`.**
  → Fixed.
- [x] **P2-O9 — operator NOTES break-glass lists only the mutating webhook** (validating `Fail`
  webhooks omitted).
  → One command: delete mutating+validating configs by `app.kubernetes.io/instance` (verified all 8 carry it).
- [x] **P2-O10 — PDB `minAvailable` not checked against replicas** (gateway `minAvailable: 2` with
  1 replica, operator controller likewise) → drains blocked.
  → Operator (controller + webhook) and gateway PDB templates `fail` on combinations that can never allow an eviction.

### preauth-proxy / passwd-append / charts (agent)
- [x] **P2-P1 — `max_in_flight` permit released at response head; no idle timeout on streamed
  bodies** (F2's doc claim was wrong).
  → Response body wrapper holds the slot until end/error/drop; new `limits.response_idle_timeout_secs` (60) cuts a silent stream; 3 tests; doc corrected.
- [x] **P2-P2 — chart `containerPort` from `service.port` while the binary listens on `config.listen`.**
  → `containerPort` value; render fails if `config.listen` port differs.
- [x] **P2-P3 — no `startupProbe`; slow login origin → restart loop.**
  → TCP `startupProbe` (150 s), render fails if below connect+response timeout.
- [x] **P2-P4 — shutdown budget (`preStopSleepSeconds` + drain vs grace) unchecked.**
  → `terminationGracePeriodSeconds` exposed; render fails unless preStop + drain < grace.
- [x] **P2-P5 — non-`Cookie` injection relays every upstream `Set-Cookie`.**
  → Non-`Cookie` injection drops every `Set-Cookie` on injected responses (no opt-out); tests.
- [x] **P2-P6 — passwd name match with non-numeric UID skips the conflict check.**
  → Name match alone is a conflict (`NameOwner::Unparseable`); test.
- [x] **P2-P7 — leading whitespace on passwd lines not matched.**
  → Leading C-`isspace` skipped as glibc does; indented `#` still a comment; test.
- [x] **P2-P8 — no `values.schema.json`; typo'd `networkPolicy` key silently renders no policy.**
  → `charts/preauth-proxy/values.schema.json` (closed objects, required non-empty `existingSecret`); lint invocations pass the placeholder. Operator/gateway schemas: see P2-X1.
- [x] **P2-P9 — preauth-proxy NetworkPolicy selectors not full LabelSelectors (inconsistent with gateway).**
  → Full LabelSelectors (breaking for old values; RFC 0003 changelog).

- [x] **P2-X1 — `values.schema.json` for weebo-si-operator and endpoint-gateway charts.**
  → Closed `values.schema.json` for all three charts (gateway `config` closed too — it is copied key by key, so a typo was silently dropped); every `.Values` path the templates read is in the schema.

### endpoint-gateway (agent)
- [x] **P2-G1 (High) — TokenReview flood still possible** (negative cache per token; shape check is unsigned).
  → Pre-checks (unverified `iss` = cluster SA issuer, `exp` in future), single-flight per token, ≤ 16 concurrent reviews, 300/min global + 30/min per client buckets; over limit → not an identity. 5 tests.
- [x] **P2-G2 (High) — self-origin probe token per-process → probe lands on other replicas;
  `Auto` starts trusted** → forged client address trusted for hours.
  → Selftest token = HMAC-SHA256(session key, "weebo selftest") — any replica answers; `Auto` starts untrusted; a seen forgery is shared via the revocations ConfigMap annotation; unconfirmed trust lapses after 3 intervals. Also fixed: revocation writes (shared SSA field manager) overwrote each other → merge patch.
- [x] **P2-G3 — identity headers resolved differently from the decision** (grant accepted as
  cookie, revocation ignored, cookie preferred over bearer).
  → `authorize_resolved` returns the credential the decision used; identity headers come from it only (`identity_of` removed).
- [x] **P2-G4 — failed JWKS fetch not retried for 600 s.**
  → While no keys are loaded: retry 1 s doubling to 60 s.
- [x] **P2-G5 — back-channel logout shares the login rate limiter.**
  → Own limiter (`rate_limit.backchannel_logout_per_minute`, 6000); 503 + `Retry-After` over it.
- [x] **P2-G6 — full limiter scans under the mutex; client-IP header trusted from any peer for limiting.**
  → Limit key trusts the address header only from `trusted_proxy` peers; eviction samples ≤ 16 oldest buckets. Residual (accepted): with the chart default `trustedProxy: any` and no NetworkPolicy, an in-cluster caller can spoof the header on direct `/auth` calls — that yields only a decision oracle, not access (the ingress controller makes the real call); enabling `networkPolicy` closes it.
- [x] **P2-G7 — unknown-`kid` refresh fires for every SA / foreign-issuer JWT.**
  → Refresh/unverifiable only when unverified `iss` is ours.
- [x] **P2-G8 — `/sign_out` has no CSRF check.**
  → `Sec-Fetch-Site: same-origin|none` or matching `Origin` required; else 403.
- [x] **P2-G9 — callback `error=` branch does not clear the state cookie.**
  → Fixed.
- [x] **P2-G10 — `backchannel_logout.enabled` / `reject_unnormalised_path` parsed but unused; `rd`
  accepts `#`/any port; `redeem` Location not checked for leading `/`; revocations ConfigMap unbounded.**
  → Disabled back-channel → 404 and not routed; `reject_unnormalised_path: false` refuses to start/render; `rd` refuses `#` and non-443 ports; redeem requires a leading `/`; revocations pruned, capped at 10 000 (503 + metric beyond).

## Deferred with the OpenShift dialect (RFC 0010, Draft)

- [~] Reverse-proxy mode never redeems `__weebo_grant`, upgrade path suspect, proxy client has no
  timeouts — the dialect is `#[ignore]`d and not shippable until RFC 0010 is accepted.
