# Graph Report - wt-rfc-series  (2026-11-27)

## Corpus Check
- 612 files · ~861,587 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 26 file(s) not represented in the graph (top: (none) 14, .toml 6, .tpl 3)

## Summary
- 13173 nodes · 32505 edges · 561 communities (478 shown, 83 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 1983 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `60c239b3`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- scope.rs
- Host
- kube_workload.rs
- weebo-si-endpoint-auth/src/application.rs
- http.rs
- inbound_http.rs
- weebo-si-identity/src/application.rs
- src/validate.rs
- weebo-si-image-policy/src/rewrite.rs
- kube_catalog.rs
- config_store.rs
- variable.rs
- weebo-si-crd/src/endpoint_auth.rs
- oidc.rs
- pattern.rs
- TemplateRef
- kube_policy_store.rs
- Spec fields
- weebo-si-resource-quotas-adapters/src/controller.rs
- weebo-si-endpoint-auth-adapters/src/endpoint_auth.rs
- conformance.rs
- weebo-si-team-tools/src/validate.rs
- argo.rs
- weebo-si-crd/src/image_policy.rs
- merge_catalogs
- hashmap
- weebo-si-crd/src/identity.rs
- weebo-si-e2e/src/lib.rs
- passwd-append/tests/integration.rs
- PodSecurityLevel
- NamespaceName
- reference.rs
- exchange.rs
- ManagedObject
- openshift_envtest.rs
- domain/config.rs
- weebo-si-policy-guard-adapters/src/policy_guard.rs
- weebo-si-crd/src/lib.rs
- guard.rs
- weebo-si-endpoint-auth-adapters/src/controller.rs
- src/network_profiles.rs
- core.rs
- pod_security_metrics.rs
- arc
- endpoint-gateway/src/main.rs
- jwt_crypto.rs
- verdict.rs
- FeatureId
- session.rs
- admission_envtest.rs
- Credential
- weebo-si-operator/tests/envtest.rs
- objects.rs
- registry_object_store.rs
- weebo-si-network-profiles/src/application.rs
- router.rs
- kube_revocations.rs
- weebo-si-dwoc-pin/src/resolve.rs
- dwoc_pin.rs
- jobs
- weebo-si-kubearmor-policy/src/resolve.rs
- QuotaProfileKey
- webhook_cmd.rs
- kube_canary.rs
- weebo-si-pod-security/src/lib.rs
- includes
- feature.rs
- perf_envtest.rs
- endpoint_routing.rs
- quota_metrics.rs
- bricks/readme.md
- weebo-si/values/weebo-si-operator.yaml
- tests/endpoint_auth.rs
- weebo-si-identity-adapters/src/controller.rs
- images_cmd.rs
- env
- with
- nss.rs
- Team
- controller_envtest.rs
- deploy
- tasks
- preauth-proxy/tests/integration.rs
- versions
- src/kubearmor_policy.rs
- image_metrics.rs
- feature/kubearmor_policy.rs
- tasks
- entry.rs
- src/registry_config.rs
- team.rs
- registry_metrics.rs
- preauth-proxy/values.yaml
- ImagePolicyConfigViolation
- quotas_cmd.rs
- weebo-si-devfile-contract/src/feature.rs
- http_client.rs
- ns_index.rs
- weebo-si-team-tools/src/feature.rs
- Spec fields
- kubearmor_metrics.rs
- cost.rs
- registry_template_store.rs
- feature/network_profiles.rs
- mount.rs
- runtime-matrix.yaml
- deploy_weebo_si.rs
- access.rs
- Findings
- steps
- admit.rs
- hard
- hard
- config
- weebo-si-pod-security/src/application.rs
- e2e.sh
- tasks
- feature/workspace_gate.rs
- weebo-si-network-profiles-adapters/src/controller.rs
- domain/policy.rs
- versions
- versions
- weebo-si-registry-config/src/application.rs
- env
- passwd-append/src/main.rs
- properties
- feature/pod_security.rs
- Ecosystem
- feature/registry_config.rs
- team_tools_envtest.rs
- spike-0009.sh
- src/decide.rs
- teams_cmd.rs
- env
- steps
- tasks
- GatewayMetrics
- EnvTest
- weebo-si-team-tools-adapters/src/controller.rs
- kubearmor_envtest.rs
- e2e/values/endpoint-gateway.yaml
- analyze-rust
- config
- registry_envtest.rs
- write
- workspace_images.rs
- matchLabels
- RFC 0005 — image-policy
- RFC 0011 — teams and users as objects
- RFC 0013 — pod-security
- `spec.features`
- deny
- weebo-si-resource-quotas/src/application.rs
- openAPIV3Schema
- weebo-si-registry-config/src/resolve.rs
- weebo-si-kubearmor-policy-adapters/src/controller.rs
- Applied
- GatewayConfig
- weebo-si-network-profiles-adapters/tests/envtest.rs
- events.rs
- container
- package.json
- weebo-si-crd
- tasks
- src/config.rs
- endpoint-gateway/values.yaml
- openshift_pod_security_envtest.rs
- tests/workspace.rs
- versions
- versions
- versions
- weebo-si-resource-quotas/src/lib.rs
- matchDirectories
- RFC 0008 — policy-guard-coverage
- RFC 0014 — resource-quotas
- RFC 0016 — WeeboSiProject
- RFC 0017 — image-rewrite
- with
- preauth-proxy/src/main.rs
- weebo-si-team-tools/src/render.rs
- versions
- pod_security_envtest.rs
- RuntimeClass crun
- lint
- tests/pod_security.rs
- kube_provisioner.rs
- features
- The weebo-si standard
- RFC 0002 — weebo-si-operator
- RFC 0007 — registry-config
- brick
- brick
- brick
- brick
- Changelog
- properties
- weebo-si-network-profiles/src/resolve.rs
- weebo-si-registry-config-adapters/src/controller.rs
- spec
- feature/image_rewrite.rs
- RFC 0004 — network-profiles
- `spec.features`
- tasks
- feature_tests.rs
- Weebo Dev Env - Guideline for the Weebo Dev Env
- TargetState
- spec
- podSecurityContext
- podSecurityContext
- compilerOptions
- tasks
- violation.rs
- service
- networkPolicy
- weebo-si-pod-security-adapters/src/controller.rs
- resource_quotas_envtest.rs
- Contract
- weebo-si-operator/values.yaml
- weebo-si-team-tools-adapters/src/reconcile.rs
- weebo-si-crd/tests/envtest.rs
- RuntimeBackend
- network_metrics.rs
- node_enforcer.rs
- weebo-si-operator/src/main.rs
- plan.rs
- endpointAuth
- data
- RFC 0010 — endpoint-auth on OpenShift
- source.ts
- render.rs
- selector.rs
- properties
- kubearmor_metrics.rs
- kube_catalog.rs
- files
- spec
- RFC 0000 — Template
- RFC 0001 — passwd-append
- RFC 0003 — preauth-proxy
- RFC 0012 — operator kit migration
- RFC 0015 — platform API group for teams and users
- env
- probe.rs
- Failure
- key
- pods_cmd.rs
- weebo-armor-build.yaml
- weebo-net-anthropic.yaml
- weebo-net-dev-registries.yaml
- @weebo/operator-docs
- RFC 0006 — kubearmor-policy
- image
- properties
- properties
- Subject
- weebo-net-kube-api.yaml
- admission.rs
- append_locked
- WebhookMetrics
- found.rs
- weebo-si-registry-config/src/model/diff.rs
- features
- features
- metadata
- `endpoint-gateway`
- workspace-image
- with
- jobs
- check_file
- spike-0009-che.sh
- serve.py
- enabled
- properties
- webhook
- weebo-net-internet.yaml
- `WeeboSiTeam` and `WeeboSiUser`
- `WeeboSiUser` — the person reference
- with
- Production-readiness TODO
- probes
- Resolved
- managed/diff.rs
- value
- bricks
- check:envtest
- endpoint-gateway/Chart.yaml
- properties
- properties
- properties
- preauth-proxy/Chart.yaml
- weebo-si-operator/Chart.yaml
- enabled
- DomainError
- RFC 0020 — team tools
- weebo-si-kubearmor-policy/src/application.rs
- RFC 0019 — devfile contract
- resourceQuotas
- labels
- spec
- RFC 0009 — endpoint-auth
- Runtime matrix
- Seccomp profiles for workspace nodes
- nodes
- tests/team_tools.rs
- bearer
- networkPolicy
- gateway
- podSecurity
- spec
- che
- `image-policy`
- `registry-config`
- kind.yaml
- crate
- e2e
- crate
- contents
- dependencies
- kind-che.yaml
- RFC 0021 — namespace-only grants
- properties
- properties
- rules
- controller
- endpointAuth
- restricted.rs
- TemplateRef
- defaultPosture
- key
- dwocPin
- cheUser
- How `weebo-si-operator` works inside
- `preauth-proxy`
- `weebo-si-operator`
- binary
- steps
- images
- suite
- steps
- proxy.ts
- t6-probe.sh
- imagePolicy
- features
- catalog
- features
- key
- Hexagonal architecture
- weebo-si-hardening
- `kubearmor-policy`
- `pod-security`
- `resource-quotas`
- Cleanup
- workflows/e2e.yaml
- [[...slug]]/page.tsx
- seccomp-profiles.sh
- tasks
- tasks
- tasks
- Cidr
- errorPage
- ingress
- rateLimit
- claims
- revalidation
- rollingUpdate
- RFC 0018 — workspace pod identity
- registryConfig
- kubearmorPolicy
- matchLabels
- key
- `network-profiles` and `policy-guard`
- Request cost
- RFC process
- steps
- sign
- images
- with
- .markdownlint.yaml
- app/layout.tsx
- scripts
- weebo-si-pod-identity/src/lib.rs
- compute_diff
- secrets
- certificates
- serviceAccount
- requests
- set_features
- cspell.json
- networkProfiles
- features
- endpointAuth
- Guide-level explanation
- che-user/Chart.yaml
- push
- charts
- verify
- identity_violations
- session
- resources
- quantity.rs
- gateway
- templateRef
- devfile.yaml
- catalog
- che-user/values.yaml
- image
- permissions
- release
- runtime-matrix-k8s.sh
- weebosiuser.mdx
- lint
- lint
- image
- networkProfiles
- image
- teamTools
- dwocPin
- imagePolicy
- kubearmorPolicy
- identity
- syncPolicy
- catalog
- catalog
- tests/pod_identity.rs
- envtest
- sign-charts
- test
- spike-0009-rig.sh
- cache
- extraCa
- free_form.rs
- networkProfiles
- Design
- runtime-matrix.sh
- claims
- hosts
- features.rs
- Documentation
- Unresolved questions
- kind-runtimes.sh
- certificates
- weebosiconfig.mdx
- .claude/CLAUDE.md
- kind-userns.sh
- end-of-line.sh
- whitespace-fixer.sh
- crd-regen.sh
- AGENTS.md
- docs/index.mdx
- postcss.config.mjs
- site/README.md
- passwd-append
- preauth-proxy
- weebo-si-e2e
- weebo-si-envtest-support
- { generateStaticParams, generateMetadata }
- config
- streamext
- teardown.rs
- weebo-si-pod-identity/src/feature.rs
- kubearmor_policy_store.rs
- src/workspace_gate.rs
- ResourceQuotasFeature
- names
- weebo-si-team-tools/src/lib.rs
- team_tools_ca_envtest.rs
- webhook_cmd.rs
- weebo-si-network-profiles/src/model/diff.rs
- scale.rs
- status.rs
- Posture
- Foreign
- compile_annotations
- Verdict
- TrustedProxy
- WeeboSiTeam
- `team-tools`
- weebo-si-controller/src/reconcile.rs
- weebo-si-team-tools-adapters/src/metrics.rs
- Field
- `pod-identity`
- flag
- `image-rewrite`
- Restricted keys and namespace grants
- CI
- weebo-si-operator: the controller's resource budget
- PodSubject
- `passwd-append`
- Fake
- weebo-si-endpoint-auth-adapters/src/lib.rs
- Managed
- `devfile-contract`
- Mutation
- Value
- endpoint-auth: what the gate costs, and what to do about it
- Repository layout
- DesiredState
- ConfigError
- RevalidationMode
- OnUnknownKey
- RoutingKind

## God Nodes (most connected - your core abstractions)
1. `NamespaceName` - 322 edges
2. `DomainError` - 155 edges
3. `FeatureMode` - 141 edges
4. `TeamName` - 133 edges
5. `Team` - 115 edges
6. `Spec fields` - 96 edges
7. `Context` - 84 edges
8. `Timestamp` - 83 edges
9. `WeeboSiTeam` - 83 edges
10. `TemplateRef` - 80 edges

## Surprising Connections (you probably didn't know these)
- `pod_subject_from_request()` --references--> `context`  [INFERRED]
  crates/weebo-si-pod-identity-adapters/src/admission.rs → .github/workflows/e2e.yaml
- `a_component_rewritten_under_a_changed_or_removed_rule_is_a_stale_mirror()` --references--> `rules`  [INFERRED]
  crates/weebo-si-operator/src/images_cmd.rs → charts/endpoint-gateway/values.yaml
- `the_gate_costs_a_short_in_cluster_hop_on_connections_it_keeps()` --calls--> `timed()`  [INFERRED]
  crates/weebo-si-e2e/tests/endpoint_auth.rs → bins/endpoint-gateway/tests/conformance.rs
- `traefik_honours_every_promise_the_dialect_makes()` --calls--> `generate_webhook_tls()`  [INFERRED]
  bins/endpoint-gateway/tests/conformance.rs → crates/weebo-si-envtest-support/src/lib.rs
- `owners_of()` --calls--> `namespace_grant()`  [INFERRED]
  bins/endpoint-gateway/src/adapters/kube_catalog.rs → crates/weebo-si-endpoint-auth/src/compile.rs

## Import Cycles
- 1-file cycle: `crates/weebo-si-network-profiles/src/port.rs -> crates/weebo-si-network-profiles/src/port.rs`
- 1-file cycle: `crates/weebo-si-webhook/src/router.rs -> crates/weebo-si-webhook/src/router.rs`
- 1-file cycle: `crates/weebo-si-team-tools/src/fixtures.rs -> crates/weebo-si-team-tools/src/fixtures.rs`
- 1-file cycle: `crates/weebo-si-controller/src/events.rs -> crates/weebo-si-controller/src/events.rs`
- 1-file cycle: `bins/preauth-proxy/src/adapters/http_client.rs -> bins/preauth-proxy/src/adapters/http_client.rs`
- 1-file cycle: `crates/weebo-si-endpoint-auth/src/compile.rs -> crates/weebo-si-endpoint-auth/src/compile.rs`
- 2-file cycle: `crates/weebo-si-image-policy/src/platform.rs -> crates/weebo-si-image-policy/src/rewrite.rs -> crates/weebo-si-image-policy/src/platform.rs`
- 2-file cycle: `crates/weebo-si-endpoint-auth/src/index.rs -> crates/weebo-si-endpoint-auth/src/testing.rs -> crates/weebo-si-endpoint-auth/src/index.rs`
- 2-file cycle: `crates/weebo-si-endpoint-auth/src/compile.rs -> crates/weebo-si-endpoint-auth/src/testing.rs -> crates/weebo-si-endpoint-auth/src/compile.rs`
- 2-file cycle: `crates/weebo-si-team-tools/src/bind.rs -> crates/weebo-si-team-tools/src/fixtures.rs -> crates/weebo-si-team-tools/src/bind.rs`
- 2-file cycle: `crates/weebo-si-team-tools/src/fixtures.rs -> crates/weebo-si-team-tools/src/validate.rs -> crates/weebo-si-team-tools/src/fixtures.rs`
- 2-file cycle: `crates/weebo-si-crd/src/argo.rs -> crates/weebo-si-crd/src/identity.rs -> crates/weebo-si-crd/src/argo.rs`
- 2-file cycle: `crates/weebo-si-crd/src/identity.rs -> crates/weebo-si-crd/src/user.rs -> crates/weebo-si-crd/src/identity.rs`
- 2-file cycle: `crates/weebo-si-image-policy/src/port.rs -> crates/weebo-si-image-policy/src/variable.rs -> crates/weebo-si-image-policy/src/port.rs`
- 2-file cycle: `crates/weebo-si-crd/src/resource_quotas.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/resource_quotas.rs`
- 2-file cycle: `crates/weebo-si-crd/src/dwoc_pin.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/dwoc_pin.rs`
- 2-file cycle: `crates/weebo-si-crd/src/pod_security.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/pod_security.rs`
- 2-file cycle: `crates/weebo-si-crd/src/registry_config.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/registry_config.rs`
- 2-file cycle: `crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/team_tools.rs -> crates/weebo-si-crd/src/team.rs`
- 2-file cycle: `crates/weebo-si-crd/src/image_policy.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/image_policy.rs`

## Communities (561 total, 83 thin omitted)

### Community 0 - "scope.rs"
Cohesion: 0.29
Nodes (13): a_desired_object_colliding_with_another_scopes_live_object_is_refused(), a_desired_object_with_a_foreign_selector_is_refused(), a_held_object_is_neither_deleted_nor_updated(), a_stale_object_of_the_same_scope_is_still_deleted(), a_workspace_scope_never_deletes_the_baseline_or_a_sibling_workspace_object(), compute_owned_diff(), deleted(), Fake (+5 more)

### Community 1 - "Host"
Cohesion: 0.06
Nodes (30): an_excluded_host_is_not_governed_even_though_it_is_under_the_suffix(), Host, HostError, Empty, NotAHostname, TooLong, MAX_HOST_LEN, one_host_has_one_normal_form() (+22 more)

### Community 2 - "kube_workload.rs"
Cohesion: 0.05
Nodes (49): a_flood_of_distinct_tokens_is_held_to_the_limits_and_fails_closed(), a_forged_signature_under_a_proven_key_costs_no_token_review(), a_known_client_keeps_a_reserve_when_strangers_spend_the_global_budget(), a_new_key_set_has_to_prove_itself_again(), a_refused_token_review_is_remembered_rather_than_repeated(), a_reviewed_token_is_cached_no_longer_than_its_own_exp(), a_slow_apiserver_is_given_up_on_and_not_asked_again_at_once(), a_terminated_or_deleting_pod_does_not_own_its_address() (+41 more)

### Community 3 - "weebo-si-endpoint-auth/src/application.rs"
Cohesion: 0.05
Nodes (53): a_back_channel_logout_cuts_off_a_bearer_minted_from_that_session(), a_back_channel_logout_cuts_off_a_cached_session(), a_cookie_cached_for_one_host_is_not_an_identity_on_another(), a_foreign_bearer_is_not_an_identity_and_does_not_cost_a_token_review_twice(), a_name_the_owner_never_wrote_is_not_delegated_to(), a_page_load_of_two_hundred_assets_verifies_one_token(), a_policy_change_lands_on_the_next_request_with_the_same_credential(), an_expired_cookie_is_a_challenge_rather_than_an_error() (+45 more)

### Community 4 - "http.rs"
Cohesion: 0.04
Nodes (97): random_id(), a_caller_cannot_state_an_input_a_second_time_through_the_request_uri(), a_host_cookie_is_capped_at_its_sessions_expiry(), a_preflight_is_the_pair_of_headers_and_not_merely_an_options(), a_redemption_only_redirects_to_a_path_on_the_same_host(), a_return_url_must_be_an_endpoint_of_this_cluster(), a_return_url_with_a_fragment_or_another_port_is_refused(), an_input_the_controller_always_states_is_never_defaulted() (+89 more)

### Community 5 - "inbound_http.rs"
Cohesion: 0.05
Nodes (42): a_body_over_the_cap_is_413(), a_caller_that_never_finishes_its_headers_is_disconnected(), a_client_that_pauses_reading_does_not_get_the_upstream_cut(), a_dropped_body_releases_its_slot(), a_saturated_proxy_answers_503_at_once(), a_stalled_upload_holds_no_slot_and_is_408_after_the_read_timeout(), an_exhausted_body_budget_answers_503_and_bodyless_requests_still_pass(), an_idle_response_body_is_cut_after_the_idle_timeout() (+34 more)

### Community 6 - "weebo-si-identity/src/application.rs"
Cohesion: 0.07
Nodes (43): a_namespace_another_team_won_is_reported_and_not_counted(), a_report_counts_the_namespaces_it_owns_and_the_people_naming_it(), a_username_claim_ignores_case_and_breaks_ties_by_name(), Action, Absent, Adopt, Conflict, Create (+35 more)

### Community 7 - "src/validate.rs"
Cohesion: 0.23
Nodes (27): ResolvedImagePolicyConfig, a_declared_variable_is_not_reported_as_undeclared(), a_declared_variable_no_pattern_uses_is_reported(), a_default_entry_with_one_non_interpolating_pattern_is_fine(), a_rule_no_pattern_permits_and_an_empty_set_warn_and_off_warns_nothing(), a_team_name_illegal_only_by_case_or_space_is_still_reported(), a_top_level_default_entry_that_can_only_grant_nothing_is_reported(), an_illegal_team_name_is_reported_only_when_a_pattern_interpolates_it() (+19 more)

### Community 8 - "weebo-si-image-policy/src/rewrite.rs"
Cohesion: 0.06
Nodes (38): PlatformConfig, a_rule_derives_the_mirrored_form_of_the_four_platform_images_only(), an_unparseable_extra_is_an_error_not_a_silent_skip(), builtin_false_empties_the_compiled_in_half(), derived_platform_patterns(), DerivedPattern, extra_is_how_an_admin_names_their_mirror(), nothing_is_derived_without_builtin_or_without_a_matching_rule() (+30 more)

### Community 9 - "kube_catalog.rs"
Cohesion: 0.04
Nodes (119): policy(), HOST, main(), measure(), policy(), request(), a_closed_endpoint_names_the_requested_key_and_the_default(), a_compile_failure_still_leaves_the_owner_able_to_reach_their_own_endpoint() (+111 more)

### Community 10 - "config_store.rs"
Cohesion: 0.05
Nodes (45): DevfileContractConfig, ResolvedDwocPinConfig, IdentityConfig, Backend, Cilium, NetworkPolicy, EnforcementBackend, Auto (+37 more)

### Community 11 - "variable.rs"
Cohesion: 0.04
Nodes (29): ImageRecord, NotGrantedRecord, RecordingObserver, RewriteRecord, a_declared_variable_resolves_from_its_bound_annotation(), a_hostile_value_is_still_seen_by_the_detection_control(), a_missing_annotation_leaves_the_variable_undefined(), a_namespace_binds_because_dns_1123_is_a_subset_of_a_path_component() (+21 more)

### Community 12 - "weebo-si-crd/src/endpoint_auth.rs"
Cohesion: 0.03
Nodes (97): a_custom_template_must_declare_every_key_it_writes(), a_host_is_claimed_by_another_only_when_the_patterns_definitely_say_so(), a_host_names_its_owner_through_the_first_matching_pattern(), a_host_two_users_could_claim_is_owned_by_neither(), a_hyphenated_user_owns_their_host_while_no_other_reading_is_a_user(), a_hyphenated_workspace_or_endpoint_stays_its_owners(), a_namespace_in_no_team_gets_the_closed_cluster_default(), a_placeholder_never_eats_a_label_boundary() (+89 more)

### Community 13 - "oidc.rs"
Cohesion: 0.03
Nodes (77): an_introspection_response_is_read_with_the_same_claim_names_as_a_jwt(), Introspected, MAX_INFLIGHT, a_failed_first_jwks_fetch_is_retried_with_backoff_not_on_the_schedule(), a_jwks_generation_bump_is_what_invalidates_a_cached_identity(), a_logout_token_is_a_logout_token_and_not_any_signed_token_with_a_sid(), a_signed_token_is_only_an_identity_when_it_is_also_for_us(), a_verifier_with_no_keys_refuses_rather_than_trusting_the_header() (+69 more)

### Community 14 - "pattern.rs"
Cohesion: 0.06
Nodes (64): a_declared_variable_interpolates_in_a_path_segment(), a_digest_only_reference_does_not_satisfy_a_tag_constraint_by_default(), a_digested_reference_matches_only_tag_agnostic_patterns(), a_double_star_matches_one_or_more_segments_never_zero(), a_literal_pattern_matches_only_itself(), a_pattern_never_matches_a_reference_whose_normalized_host_differs(), a_pattern_with_a_tag_constraint_matches_only_a_matching_tag(), a_pattern_with_no_tag_constraint_matches_any_tag_or_a_digest() (+56 more)

### Community 15 - "TemplateRef"
Cohesion: 0.14
Nodes (29): limit_items_are_read_from_the_spec(), LimitItem, LimitRangeTemplate, QuotaTemplate, string_map(), a_compute_quota_without_a_container_default_is_an_outage_and_refused(), a_compute_quota_without_any_limit_range_is_refused(), a_missing_template_is_reported_by_kind() (+21 more)

### Community 16 - "kube_policy_store.rs"
Cohesion: 0.09
Nodes (20): a_delete_of_an_object_already_gone_is_not_a_failure(), a_failed_uid_precondition_is_benign_not_a_reconcile_error(), a_listed_object_carries_its_uid_into_the_delete_precondition(), a_profile_object_round_trips_its_owner_through_what_this_adapter_writes(), a_team_tools_policy_is_invisible_to_network_profiles(), an_unowned_object_is_written_without_owner_references_and_reads_back_unowned(), any_other_delete_failure_is_a_port_failure(), api_error() (+12 more)

### Community 17 - "Spec fields"
Cohesion: 0.02
Nodes (96): `spec.features.devfileContract.deniedParents[]` [#spec.features.devfileContract.deniedParents], `spec.features.devfileContract.namespaceSelector.matchExpressions[]` [#spec.features.devfileContract.namespaceSelector.matchExpressions], `spec.features.devfileContract.namespaceSelector` [#spec.features.devfileContract.namespaceSelector], `spec.features.devfileContract` [#spec.features.devfileContract], `spec.features.dwocPin.catalog[]` [#spec.features.dwocPin.catalog], `spec.features.dwocPin.namespaceSelection` [#spec.features.dwocPin.namespaceSelection], `spec.features.dwocPin.namespaceSelector.matchExpressions[]` [#spec.features.dwocPin.namespaceSelector.matchExpressions], `spec.features.dwocPin.namespaceSelector` [#spec.features.dwocPin.namespaceSelector] (+88 more)

### Community 18 - "weebo-si-resource-quotas-adapters/src/controller.rs"
Cohesion: 0.12
Nodes (14): configured_off(), Ctx, Error, error_policy(), FEATURE, Fingerprint, fingerprint_changes(), log() (+6 more)

### Community 19 - "weebo-si-endpoint-auth-adapters/src/endpoint_auth.rs"
Cohesion: 0.12
Nodes (32): a_host_another_namespace_owns_is_refused_and_a_hostless_object_is_not_judged(), a_hyphenated_owner_is_admitted_their_host_unless_another_reading_is_a_user(), a_tls_host_counts_and_a_certificate_name_annotation_is_reported(), an_annotation_dwo_dropped_is_put_back_on_an_update(), an_ingress_naming_a_team_ca_issuer_is_refused(), an_update_that_tampers_with_the_chain_is_left_for_the_guard_to_refuse(), annotations_of(), backend_of() (+24 more)

### Community 20 - "conformance.rs"
Cohesion: 0.06
Nodes (50): ALICE_HOST, ALICE_POD_IP, Answer, BOB_HOST, BOB_POD_IP, BURST, CAROL_HOST, CAROL_POD_IP (+42 more)

### Community 21 - "weebo-si-team-tools/src/validate.rs"
Cohesion: 0.05
Nodes (89): ToolTemplateRef, Lookup, EntryInvalid, NotGranted, TeamInvalid, Valid, buildkit_entry(), store() (+81 more)

### Community 22 - "argo.rs"
Cohesion: 0.07
Nodes (51): a_clean_template_has_no_violation(), a_namespace_naming_itself_is_refused(), a_namespace_override_wins_and_rebinds_the_variable(), a_person_overrides_one_value_and_keeps_its_siblings(), a_source_naming_both_chart_and_path_is_refused(), an_unknown_variable_inside_values_is_found(), ApplicationDestination, ApplicationSource (+43 more)

### Community 23 - "weebo-si-crd/src/image_policy.rs"
Cohesion: 0.11
Nodes (28): a_declared_variable_outside_the_name_charset_is_reported(), a_declared_variable_rebinding_a_reserved_name_is_reported(), a_declared_variable_with_an_empty_binding_is_reported(), a_grant_allowed_naming_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_top_level_default_naming_an_uncatalogued_key_is_reported(), a_well_formed_configuration_produces_no_violations() (+20 more)

### Community 24 - "merge_catalogs"
Cohesion: 0.37
Nodes (10): a_redefinition_is_reported_and_the_first_definition_wins(), a_team_cannot_shadow_a_cluster_entry(), a_team_cannot_unrestrict_a_cluster_entry(), CatalogConflict, Entry, entry(), merge_catalogs(), team() (+2 more)

### Community 25 - "hashmap"
Cohesion: 0.08
Nodes (22): Introspector, a_fingerprint_never_renders_the_credential(), a_flood_of_distinct_credentials_evicts_rather_than_grows(), a_hit_is_the_second_request_of_a_page_load(), an_already_expired_credential_is_not_cached_at_all(), an_entry_never_outlives_the_credential_it_answers_for(), at(), CacheKind (+14 more)

### Community 26 - "weebo-si-crd/src/identity.rs"
Cohesion: 0.09
Nodes (44): a_group_outside_the_allow_list_refuses_the_whole_object(), a_person_naming_a_team_that_does_not_exist_is_reported(), a_person_with_no_team_cannot_have_a_workspace(), a_plan_merges_the_teams_groups_with_the_persons(), a_repository_outside_the_allow_list_is_refused(), a_team_switching_its_workspace_off_is_reported_not_skipped(), a_username_cannot_render_the_repository_out_of_its_allowed_prefix(), a_workspace_plan_renders_the_teams_template() (+36 more)

### Community 27 - "weebo-si-e2e/src/lib.rs"
Cohesion: 0.07
Nodes (31): a_dashboard_shaped_workspace_carries_the_dashboards_config_attribute(), a_sample_is_found_by_name_and_a_subset_of_its_labels(), AllToLoopback, apply_args(), ca_file(), config_status(), DOMAIN, Endpoint (+23 more)

### Community 28 - "passwd-append/tests/integration.rs"
Cohesion: 0.10
Nodes (46): a_command_after_the_separator_is_exec_ed(), a_database_without_a_trailing_newline_is_repaired_not_corrupted(), a_fresh_run_appends_both_entries(), a_hostile_home_exits_two_without_touching_the_files(), a_login_name_taken_by_another_uid_is_not_duplicated(), a_missing_target_is_reported(), a_non_utf8_passwd_database_still_gets_its_entry(), a_re_run_with_different_fields_still_writes_nothing() (+38 more)

### Community 29 - "PodSecurityLevel"
Cohesion: 0.12
Nodes (22): default_ceiling(), PodSecurityLevel, .ALL, Baseline, Privileged, Restricted, TeamPodSecurity, a_namespace_of_no_team_gets_the_default_and_no_team() (+14 more)

### Community 30 - "NamespaceName"
Cohesion: 0.04
Nodes (39): NamespaceName, RoutingObjectWrite, FakeBaselineView, FakeBaselineView, teardown(), a_template_keeps_its_body_and_drops_its_status(), KubeToolTemplateStore, spawn_reflector() (+31 more)

### Community 31 - "reference.rs"
Cohesion: 0.06
Nodes (40): a_digest_drops_the_tag_because_the_tag_is_not_evidence(), a_first_component_with_no_dot_and_no_port_is_a_path_not_a_host(), a_port_is_a_host_and_a_tag_is_a_tag_even_together(), a_rule_host_is_normalised_like_a_reference_host(), a_rule_target_is_a_host_and_a_path_with_no_glob_or_variable(), DEFAULT_TAG, DIGEST, fields_are_split_not_globbed() (+32 more)

### Community 32 - "exchange.rs"
Cohesion: 0.11
Nodes (39): Config, a_cookie_merely_ending_in_the_marker_name_is_not_the_marker(), a_credential_whose_cookie_name_is_unclear_drops_every_set_cookie(), a_failed_acquisition_is_an_error_not_an_unauthenticated_forward(), a_non_cookie_injection_drops_every_set_cookie(), a_non_cookie_injection_still_relays_set_cookie_on_passthrough(), a_passed_through_request_is_not_renewed_on_a_401(), a_passed_through_response_keeps_its_set_cookie() (+31 more)

### Community 33 - "ManagedObject"
Cohesion: 0.06
Nodes (29): a_target_unreachable_before_any_policy_is_unknown_never_enforcing(), an_inconclusive_leg_is_never_folded_into_a_definite_verdict(), CanaryVerdict, Enforcing, NotEnforcing, Unknown, Reachability, Blocked (+21 more)

### Community 34 - "openshift_envtest.rs"
Cohesion: 0.05
Nodes (41): COMPANION_SERVICE, UPSTREAM_ANNOTATION, ALICE, BREAK_GLASS, CHAIN, config_yaml(), create_namespace(), DEVWORKSPACE_OPERATOR_CONFIG_CRD (+33 more)

### Community 35 - "domain/config.rs"
Cohesion: 0.04
Nodes (65): a_form_body_encodes_secrets_and_other_bodies_do_not(), a_missing_required_key_is_refused(), an_unknown_key_is_refused(), an_unset_env_reference_fails_the_load(), creds(), DEFAULT_MAX_REPLAYS, env(), every_field_level_rule_is_enforced() (+57 more)

### Community 36 - "weebo-si-policy-guard-adapters/src/policy_guard.rs"
Cohesion: 0.06
Nodes (24): Context<'a>, context_exposes_teams_namespace_and_catalog_and_nothing_else(), NamespaceFacts, DwocCatalog, FakeNamespaceView, NamespaceView, admission_routes(), guarded_write_from_request() (+16 more)

### Community 37 - "weebo-si-crd/src/lib.rs"
Cohesion: 0.04
Nodes (74): DEVFILE_CONTRACT_ANNOTATION, DEVFILE_CONTRACT_REASON_ANNOTATION, DEVFILE_PARENT_ATTRIBUTE, GENERATOR_ATTRIBUTE, MAX_CONTRACT, MAX_DENIED_ENTRIES, MAX_DENIED_VERSIONS, OnDenied (+66 more)

### Community 38 - "guard.rs"
Cohesion: 0.11
Nodes (25): a_create_of_an_unmanaged_object_by_a_non_allowed_identity_is_denied(), a_create_of_an_unmanaged_object_by_an_allowed_identity_is_allowed(), a_non_operator_touching_a_managed_object_is_denied_on_every_operation(), an_update_of_an_unmanaged_object_by_anyone_is_allowed(), any_write_from_the_operator_is_allowed(), ctx(), guard(), GuardedWrite (+17 more)

### Community 39 - "weebo-si-endpoint-auth-adapters/src/controller.rs"
Cohesion: 0.11
Nodes (38): ResolvedEndpointAuthConfig, annotation_patch(), CHAIN, CLOSED, companion_service(), companion_slice(), Ctx, EndpointAuthDeps (+30 more)

### Community 40 - "src/network_profiles.rs"
Cohesion: 0.06
Nodes (43): a_baseline_absent_from_the_catalog_is_reported(), a_grant_allowed_naming_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_profile_with_no_variants_is_reported(), a_profile_with_two_variants_for_the_same_backend_is_reported(), a_restricted_default_is_a_violation(), a_well_formed_configuration_produces_no_violations() (+35 more)

### Community 41 - "core.rs"
Cohesion: 0.05
Nodes (46): Decision<S>, TeamName, owner_of(), a_declared_variable_the_adapter_could_not_resolve_is_reported_undefined(), a_declared_variable_the_adapter_resolved_is_not_reported_undefined(), a_dropped_not_granted_key_is_counted_once_per_decision(), a_platform_only_image_is_flagged_as_such_for_its_own_counter(), an_attacker_controlled_reference_is_escaped_before_it_reaches_the_api_error() (+38 more)

### Community 42 - "pod_security_metrics.rs"
Cohesion: 0.07
Nodes (29): a_pass_that_writes_nothing_keeps_the_last_writes_violations(), every_series_starts_at_zero(), gauge(), outcome(), PodSecurityMetrics, results_and_drift_are_counted_and_teardown_forgets(), the_gauges_follow_the_namespaces_and_forget_drops_one(), the_summary_warning_is_not_a_pod() (+21 more)

### Community 43 - "arc"
Cohesion: 0.08
Nodes (54): a_container_with_no_image_is_skipped_not_denied(), a_created_pod_offers_every_image_location_to_the_rewrite(), a_plugin_component_is_not_read_because_dwo_resolves_it_after_admission(), a_pod_with_only_containers_still_works(), a_workspace_offers_its_component_images_and_its_existing_record(), a_workspace_update_matches_components_by_name_not_position(), a_workspace_with_no_components_yields_no_images_rather_than_failing(), all_three_pod_container_lists_are_read() (+46 more)

### Community 44 - "endpoint-gateway/src/main.rs"
Cohesion: 0.04
Nodes (53): IntrospectorPorts, installed(), discover(), Discovery, OidcClient, TokenResponse, metrics_router(), router() (+45 more)

### Community 45 - "jwt_crypto.rs"
Cohesion: 0.06
Nodes (19): a_key_of_the_wrong_family_is_refused_before_any_signature_is_tried(), an_algorithm_ring_does_not_take_over_still_goes_to_rust_crypto(), compute_digest(), es256_pair(), es256_verifies_its_own_signature_and_nothing_else(), extract_ec_public_key_coordinates(), install(), new_signer() (+11 more)

### Community 46 - "verdict.rs"
Cohesion: 0.33
Nodes (6): a_reference_at_the_bound_is_not_marked_truncated(), a_reference_is_quoted_and_escaped_before_it_reaches_a_log(), a_terminal_escape_sequence_cannot_reach_a_log_reader_unescaped(), an_over_long_reference_is_bounded_and_says_so(), escape_reference(), MAX_ECHOED_REFERENCE

### Community 47 - "FeatureId"
Cohesion: 0.06
Nodes (16): FeatureId, FeatureOutcome, FakeFeatureGate, FeatureGate, Observer, RecordingObserver, Quiet, devfile_contract_decisions_are_counted_by_result_and_mode() (+8 more)

### Community 48 - "session.rs"
Cohesion: 0.06
Nodes (38): a_grant_is_not_a_session(), a_key_is_accepted_in_whichever_base64_the_admin_generated_it(), a_login_state_cookie_is_not_an_sso_cookie_and_an_sso_cookie_is_not_a_login_state(), a_sealed_cookie_opens_on_the_host_it_was_sealed_for_and_on_no_other(), a_tampered_cookie_does_not_open(), an_expired_cookie_does_not_open(), Binding, HostBound (+30 more)

### Community 49 - "admission_envtest.rs"
Cohesion: 0.07
Nodes (89): a_devworkspace_is_pinned_by_a_real_running_webhook(), a_devworkspace_is_refused_until_its_namespace_has_a_baseline_live(), a_devworkspace_naming_a_granted_image_is_admitted(), a_devworkspace_naming_an_ungranted_image_is_refused_with_a_readable_message(), a_dwoc_pin_block_added_after_boot_is_observed_without_a_restart(), a_kubearmor_policy_is_guarded_exactly_as_a_network_policy_is(), a_namespace_annotation_inside_the_allowed_set_is_honoured_live(), a_namespace_without_the_workspace_label_is_out_of_the_pod_rules_scope() (+81 more)

### Community 50 - "Credential"
Cohesion: 0.08
Nodes (17): a_failed_acquisition_caches_nothing(), AlwaysFails, Cache, concurrent_misses_produce_exactly_one_login(), CountingSource, invalidating_a_credential_that_is_no_longer_held_is_a_no_op(), invalidating_the_held_credential_empties_the_cache(), the_first_call_acquires_and_the_second_reuses() (+9 more)

### Community 51 - "weebo-si-operator/tests/envtest.rs"
Cohesion: 0.07
Nodes (43): apply_document(), assert_forbidden(), bind_cluster_role(), CERTIFICATES, controller_role_matches_the_documented_grants(), CONTROLLER_TOKEN, create_namespace(), create_release_namespace() (+35 more)

### Community 52 - "objects.rs"
Cohesion: 0.09
Nodes (31): Owner, BACKEND_LABEL, CANARY_LABEL, DEVWORKSPACE_ID_LABEL, KUBEARMOR_ENFORCER_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, PROFILE_LABEL (+23 more)

### Community 53 - "registry_object_store.rs"
Cohesion: 0.08
Nodes (20): a_malformed_body_is_a_port_failure_rather_than_a_half_written_object(), a_secret_copy_names_the_secret_kind_and_carries_its_type(), API_VERSION, apply_document(), delete(), FIELD_MANAGER, KubeRegistryObjectStore, object() (+12 more)

### Community 54 - "weebo-si-network-profiles/src/application.rs"
Cohesion: 0.15
Nodes (35): a_canary_that_reaches_in_both_legs_reports_not_enforcing(), a_canary_that_reaches_then_is_blocked_reports_enforcing(), a_canary_whose_first_leg_fails_skips_the_second_and_reports_unknown(), a_live_profile_object_without_an_owner_is_updated_to_carry_its_workspace(), a_second_enforce_pass_with_nothing_changed_reports_unchanged_and_leaves_the_store_alone(), a_stale_object_of_the_same_workspace_is_still_deleted(), a_workspace_reconcile_never_deletes_the_baseline_or_a_sibling_workspace_object(), all_templates() (+27 more)

### Community 55 - "router.rs"
Cohesion: 0.10
Nodes (28): Registry, log_calls(), names_a_whole_object(), no_log_macro_names_the_admitted_object(), SOURCES, the_scan_catches_an_object_in_a_log_macro(), a_denial_is_logged_with_its_reasons(), a_devfile_contract_denial_stops_before_dwoc_pin_and_the_gate_denial_wins() (+20 more)

### Community 56 - "kube_revocations.rs"
Cohesion: 0.09
Nodes (8): a_revocation_prunes_the_expired_and_refuses_to_overflow(), ADDRESS_FORGERY_ANNOTATION, KubeRevocations, MAX_REVOCATIONS, plan_revocation(), RevokeError, Full, Kube

### Community 57 - "weebo-si-dwoc-pin/src/resolve.rs"
Cohesion: 0.17
Nodes (28): Grant, OnUnknownKey, Default, Deny, a_disallowed_workspace_attribute_is_ignored_and_falls_through(), a_team_with_no_grant_falls_back_to_the_synthetic_default_grant(), an_uncatalogued_workspace_attribute_is_ignored_and_falls_through(), an_unknown_annotation_key_under_default_falls_through_to_the_grant_default_and_is_flagged() (+20 more)

### Community 58 - "dwoc_pin.rs"
Cohesion: 0.13
Nodes (24): a_default_absent_from_the_catalog_is_reported(), a_grant_allowed_naming_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_grant_with_an_empty_allowed_set_is_reported(), a_well_formed_configuration_produces_no_violations(), Catalog, catalog_entry_wire_shape_is_flat() (+16 more)

### Community 59 - "jobs"
Cohesion: 0.06
Nodes (46): name, runs-on, steps, timeout-minutes, run, name, runs-on, steps (+38 more)

### Community 60 - "weebo-si-kubearmor-policy/src/resolve.rs"
Cohesion: 0.22
Nodes (29): RuntimeProfileGrant, RuntimeProfileKey, a_partially_granted_request_under_deny_names_only_the_ungranted_keys(), a_team_with_no_grant_falls_back_to_the_synthetic_empty_grant(), an_empty_workspace_attribute_means_explicitly_nothing_and_does_not_fall_through(), an_ungranted_request_under_default_falls_back_to_the_grant_default_and_is_flagged(), an_ungranted_request_under_deny_is_refused(), config() (+21 more)

### Community 61 - "QuotaProfileKey"
Cohesion: 0.22
Nodes (21): QuotaCatalog, QuotaGrant, QuotaProfile, QuotaProfileKey, a_namespace_of_no_team_can_only_name_the_cluster_default(), a_namespace_of_no_team_gets_the_cluster_default(), a_team_namespace_gets_the_team_default(), an_empty_annotation_is_no_request() (+13 more)

### Community 62 - "webhook_cmd.rs"
Cohesion: 0.10
Nodes (5): KubeTemplateStore, devworkspace_operator_config_resource(), KubeDwocStore, KubeNsStore, AdmissionShared

### Community 63 - "kube_canary.rs"
Cohesion: 0.08
Nodes (30): build(), canary_deny_policy_spec(), canary_pod_spec(), client_args(), CLIENT_POD, CLIENT_TERMINAL_TIMEOUT, CONNECT_TIMEOUT, DEFAULT_CANARY_IMAGE (+22 more)

### Community 64 - "weebo-si-pod-security/src/lib.rs"
Cohesion: 0.05
Nodes (40): PodSecurityVersion, apply_body(), KubeNamespaceLabelStore, release_body(), restore_body(), the_apply_body_carries_the_six_labels_and_the_annotation_only(), the_restore_body_sets_back_removes_the_rest_and_drops_the_annotation(), warnings() (+32 more)

### Community 65 - "includes"
Cohesion: 0.05
Nodes (45): cmds, desc, cmds, desc, task, includes, ci, crd (+37 more)

### Community 66 - "feature.rs"
Cohesion: 0.14
Nodes (31): FakeDwocCatalog, DwocRef, CatalogKey, add_when_no_current_reference(), allowed_override_when_current_is_inside_the_grants_allowed_set(), already_pinned_when_current_equals_resolved(), an_annotation_value_is_escaped_and_bounded_before_it_reaches_a_message(), an_invalid_config_where_the_resolved_key_is_not_in_the_catalog_is_a_domain_error() (+23 more)

### Community 67 - "perf_envtest.rs"
Cohesion: 0.11
Nodes (18): clock_ticks(), configure(), Controller, cpu_seconds(), devfile_contract_adds_under_a_millisecond_to_a_devworkspace_admission(), env_or(), FIXTURES, http_get() (+10 more)

### Community 68 - "endpoint_routing.rs"
Cohesion: 0.09
Nodes (35): DEVELOPER_ANNOTATIONS, ENDPOINT_AUTH_ANNOTATION, ENDPOINT_AUTH_BYPASS, a_certificate_name_annotation_is_refused_even_through_dwo(), a_developer_may_not_create_or_update_an_endpoint_into_bypass(), a_host_this_namespace_does_not_own_is_refused_whoever_wrote_it(), ALLOWED_CERTIFICATE_ANNOTATIONS, an_issuer_off_the_allow_list_is_refused_even_through_dwo() (+27 more)

### Community 69 - "quota_metrics.rs"
Cohesion: 0.09
Nodes (22): a_namespace_moving_profile_leaves_the_old_series(), namespaces_and_saturation_follow_the_picture(), NO_PROFILE, only_a_change_of_the_annotation_counts(), outcome(), Picture, profiles_are_set_not_added(), ResourceQuotasMetrics (+14 more)

### Community 70 - "bricks/readme.md"
Cohesion: 0.17
Nodes (3): `deploy/weebo-si/`, Architecture, Bricks

### Community 71 - "weebo-si/values/weebo-si-operator.yaml"
Cohesion: 0.05
Nodes (44): certificates, provider, enabled, controller, leaderElection, replicaCount, endpointAuth, dialect (+36 more)

### Community 72 - "tests/endpoint_auth.rs"
Cohesion: 0.12
Nodes (34): gateway_metric_sum(), Ingress, a_caller_stated_identity_never_reaches_the_workspace(), a_developer_cannot_take_the_gate_off_their_own_endpoint(), a_host_cookie_minted_for_one_endpoint_is_refused_on_another(), a_second_namespace_claiming_a_host_the_patterns_give_to_another_is_refused(), a_team_endpoint_opens_to_a_teammate_and_stays_shut_to_a_stranger(), a_teammate_is_shut_out_once_an_override_narrows_the_owner() (+26 more)

### Community 73 - "weebo-si-identity-adapters/src/controller.rs"
Cohesion: 0.08
Nodes (34): TargetStatus, WeeboSiUser, WeeboSiUserStatus, a_stale_team_status_write_is_a_lost_race_not_an_error(), a_team_change_requeues_its_members_and_nobody_else(), an_unchanged_team_condition_keeps_its_time_and_skips_the_write(), claimant(), condition() (+26 more)

### Community 74 - "images_cmd.rs"
Cohesion: 0.09
Nodes (15): a_component_rewritten_under_a_changed_or_removed_rule_is_a_stale_mirror(), a_listed_namespace_view_answers_labels_and_annotations(), audit(), check_reference(), ListedNamespaces, load_config(), load_namespaces(), load_teams() (+7 more)

### Community 75 - "env"
Cohesion: 0.05
Nodes (43): concurrency, cancel-in-progress, group, ENVTEST_K8S_VERSION, ENVTEST_SHA512, KUBEBUILDER_ASSETS, PERF_CONTROLLER_LOG, PERF_IDLE_SECONDS (+35 more)

### Community 76 - "with"
Cohesion: 0.05
Nodes (43): concurrency, cancel-in-progress, group, CODE, jobs, rust, name, on (+35 more)

### Community 77 - "nss.rs"
Cohesion: 0.09
Nodes (32): a_group_name_held_by_another_gid_is_a_conflict_like_a_passwd_name(), a_login_name_taken_by_another_uid_is_a_conflict_not_an_append(), a_malformed_line_is_skipped_rather_than_panicking(), a_name_match_with_an_unparseable_uid_is_still_a_conflict(), a_non_utf8_gecos_does_not_stop_the_scan(), a_non_utf8_name_is_reported_lossily_rather_than_failing(), append_locked_handles_a_non_utf8_database_and_writes_nothing_on_conflict(), crlf_line_endings_are_tolerated() (+24 more)

### Community 78 - "Team"
Cohesion: 0.11
Nodes (58): EntryKey, ImageGrant, Team, a_catalogued_image_is_attributed_to_its_entry(), a_namespace_with_no_team_reaches_no_team_registry_image_at_all(), a_platform_image_is_attributed_to_the_platform_set(), a_team_with_no_grant_is_the_same_case_as_no_team(), allowed_set() (+50 more)

### Community 79 - "controller_envtest.rs"
Cohesion: 0.12
Nodes (34): a_config_under_the_wrong_name_is_reported_degraded(), a_dry_run_reports_what_it_would_create_and_creates_nothing(), a_kind_this_cluster_does_not_serve_is_absent_not_missing(), a_person_gets_an_authentik_user_owned_by_their_own_object(), a_persons_workspace_application_is_rendered_from_their_teams_template(), a_second_person_claiming_a_taken_username_writes_nothing(), a_team_redefining_a_catalogue_key_is_reported_degraded(), a_team_reports_its_namespaces_its_members_and_what_it_lost() (+26 more)

### Community 80 - "deploy"
Cohesion: 0.05
Nodes (41): defaults, name, runs-on, steps, timeout-minutes, concurrency, cancel-in-progress, group (+33 more)

### Community 81 - "tasks"
Cohesion: 0.05
Nodes (41): cmds, desc, status, cmds, desc, status, cmds, desc (+33 more)

### Community 82 - "preauth-proxy/tests/integration.rs"
Cohesion: 0.12
Nodes (25): a_401_renews_and_replays_once(), a_caller_cookie_without_the_marker_is_joined_not_replaced(), a_first_request_acquires_and_injects(), a_refusing_origin_stops_the_rollout_with_exit_three(), a_request_carrying_the_marker_is_passed_through_untouched(), an_origin_that_mints_nothing_also_exits_three(), an_unreachable_upstream_is_a_502_never_an_open_door(), an_unset_secret_is_exit_two_and_never_an_empty_password() (+17 more)

### Community 83 - "versions"
Cohesion: 0.06
Nodes (40): jsonPath, name, type, apiVersion, kind, metadata, spec, apiVersion (+32 more)

### Community 84 - "src/kubearmor_policy.rs"
Cohesion: 0.08
Nodes (32): a_baseline_absent_from_the_catalog_is_reported(), a_default_outside_its_own_allowed_set_is_reported(), a_grant_allowing_an_uncatalogued_key_is_reported(), a_grant_naming_an_undeclared_team_is_reported(), a_well_formed_configuration_produces_no_violations(), an_empty_grant_is_not_a_violation(), an_invalid_runtime_profile_key_is_reported(), clean_catalog() (+24 more)

### Community 85 - "image_metrics.rs"
Cohesion: 0.19
Nodes (16): a_changed_bound_annotation_is_counted(), a_namespace_with_no_team_gets_a_named_label_not_an_empty_one(), a_platform_only_image_ticks_its_own_counter_as_well_as_the_main_one(), a_variable_resolution_is_counted_by_name_and_result(), a_verdict_is_counted_by_result_resource_and_team(), an_ungranted_request_is_one_tick_per_decision_not_per_key(), counter(), ImageMetrics (+8 more)

### Community 86 - "feature/kubearmor_policy.rs"
Cohesion: 0.17
Nodes (30): ResolvedKubeArmorPolicyConfig, a_baseline_key_absent_from_the_catalog_is_a_domain_error(), a_granted_key_whose_template_has_not_landed_writes_nothing_for_that_key_alone(), a_missing_baseline_template_still_carries_the_posture(), a_workspace_asking_for_nothing_beyond_the_default_gets_the_grant_default(), a_workspace_with_two_granted_profiles_gets_two_objects_keyed_by_workspace_id(), an_ungranted_request_under_deny_writes_nothing_beyond_the_baseline(), BASELINE_NAME (+22 more)

### Community 87 - "tasks"
Cohesion: 0.05
Nodes (39): cmds, desc, silent, cmds, deps, desc, env, silent (+31 more)

### Community 88 - "entry.rs"
Cohesion: 0.08
Nodes (24): Case, empty_shell_is_allowed_and_renders_as_an_empty_field(), group_line_matches_upstream_byte_for_byte(), GroupEntry, InvalidField, MAX_NAME_LEN, passwd_line_matches_upstream_byte_for_byte(), PasswdEntry (+16 more)

### Community 89 - "src/registry_config.rs"
Cohesion: 0.17
Nodes (23): a_configmap_and_a_secret_of_the_same_name_are_two_different_sources(), a_grant_allowing_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_well_formed_configuration_produces_no_violations(), an_empty_grant_is_not_a_violation(), an_entry_with_no_sources_is_reported(), clean_catalog() (+15 more)

### Community 90 - "team.rs"
Cohesion: 0.13
Nodes (23): a_redefined_key_is_a_conflict_and_the_first_definition_stands(), a_team_default_it_cannot_reach_is_reported(), a_team_reaches_its_own_profiles_and_the_cluster_default(), an_empty_catalogue_is_reported(), config(), default_quota_annotation(), profile(), QuotaNamespaceSelection (+15 more)

### Community 91 - "registry_metrics.rs"
Cohesion: 0.14
Nodes (21): a_create_is_not_drift(), a_dry_run_pass_never_lands_on_a_write_result(), a_forgotten_namespace_stops_being_counted_at_all(), a_namespace_that_recovers_moves_between_states_rather_than_being_counted_twice(), a_refused_template_is_counted_by_key_and_reason(), an_enforce_pass_counts_what_was_applied(), an_object_whose_key_left_the_catalogue_is_still_counted(), an_update_in_enforce_is_counted_as_restored_drift() (+13 more)

### Community 92 - "preauth-proxy/values.yaml"
Cohesion: 0.05
Nodes (37): affinity, config, containerPort, credentials, existingSecret, secretKey, userKey, namespaceSelector (+29 more)

### Community 93 - "ImagePolicyConfigViolation"
Cohesion: 0.13
Nodes (17): ImagePolicyConfigViolation, CatalogKeyConflict, DefaultEntryInterpolatesTeamName, DefaultUnknownKey, DuplicateEntryKey, EmptyCatalog, EmptyVariableBinding, EntryHasNoPatterns (+9 more)

### Community 94 - "quotas_cmd.rs"
Cohesion: 0.12
Nodes (19): has_flag(), audit(), count(), load(), render(), resources(), run(), usage() (+11 more)

### Community 95 - "weebo-si-devfile-contract/src/feature.rs"
Cohesion: 0.07
Nodes (56): DeniedParent, check_contract(), check_parent(), check_schema(), decide(), Denied, Contract, denied_match() (+48 more)

### Community 96 - "http_client.rs"
Cohesion: 0.16
Nodes (21): a_cookie_that_deletes_is_not_a_credential(), a_header_value_that_cannot_be_a_header_never_echoes_the_value(), a_silent_origin_is_an_acquisition_failure_after_the_response_timeout(), a_silent_upstream_is_a_gateway_error_after_the_response_timeout(), acquisition(), client(), HttpClient, HttpCredentialSource (+13 more)

### Community 97 - "ns_index.rs"
Cohesion: 0.16
Nodes (10): a_relist_replaces_the_index_at_init_done_like_the_store(), dynamic_object_keys_look_up_in_a_store_built_with_the_same_resource(), feed(), Inner, it_answers_per_namespace_and_follows_applies_and_deletes(), names(), np(), NsIndex (+2 more)

### Community 98 - "weebo-si-team-tools/src/feature.rs"
Cohesion: 0.10
Nodes (42): Subject, OwnedScope, TeamToolState, Grace, Held, Idle, Invalid, Running (+34 more)

### Community 99 - "Spec fields"
Cohesion: 0.05
Nodes (38): Build a manifest, Example, `spec.features.dwocPin.catalog[]` [#spec.features.dwocPin.catalog], `spec.features.dwocPin` [#spec.features.dwocPin], `spec.features.endpointAuth.catalog[]` [#spec.features.endpointAuth.catalog], `spec.features.endpointAuth` [#spec.features.endpointAuth], `spec.features.imagePolicy.catalog[]` [#spec.features.imagePolicy.catalog], `spec.features.imagePolicy` [#spec.features.imagePolicy] (+30 more)

### Community 100 - "kubearmor_metrics.rs"
Cohesion: 0.15
Nodes (19): a_create_is_not_drift(), a_dry_run_pass_never_lands_on_a_write_result(), an_enforce_pass_counts_what_was_applied(), an_update_in_enforce_is_counted_as_restored_drift(), kind_label(), KubeArmorMetrics, managed_objects_are_counted_by_kind_and_scope(), no_metric_carries_a_namespace_or_a_workspace_label() (+11 more)

### Community 101 - "cost.rs"
Cohesion: 0.14
Nodes (12): HOST, ISSUER, KEY, NoRevocations, now(), payload(), realm(), request() (+4 more)

### Community 102 - "registry_template_store.rs"
Cohesion: 0.09
Nodes (22): a_config_map_with_no_data_at_all_still_has_a_body(), a_config_maps_body_carries_data_and_binary_data_and_nothing_else(), a_secrets_body_carries_data_and_type_but_never_string_data(), an_object_with_no_metadata_maps_at_all_projects_to_empty_maps(), body_from(), config_map_body(), copied_metadata(), find() (+14 more)

### Community 103 - "feature/network_profiles.rs"
Cohesion: 0.14
Nodes (26): ResolvedNetworkProfilesConfig, a_workspace_asking_for_nothing_beyond_the_default_gets_the_grant_default(), a_workspace_with_two_granted_profiles_gets_two_objects_keyed_by_workspace_id(), an_ungranted_request_under_deny_writes_nothing_beyond_the_baseline(), BASELINE_NAME, config(), ctx(), evaluate_with_no_config_at_all_is_a_domain_error() (+18 more)

### Community 104 - "mount.rs"
Cohesion: 0.09
Nodes (28): a_template_with_no_mount_path_at_all_is_admitted(), a_template_without_the_automount_label_is_refused(), admit(), an_absent_mount_as_over_a_home_is_refused_too(), an_env_mount_over_a_home_path_is_admitted(), an_ordinary_directory_below_a_home_does_not_shadow(), automountable(), dot_segments_are_resolved_before_the_path_is_judged() (+20 more)

### Community 105 - "runtime-matrix.yaml"
Cohesion: 0.06
Nodes (35): concurrency, cancel-in-progress, group, env, KIND_SHA256, KIND_VERSION, OUT, RUNC_BIN (+27 more)

### Community 106 - "deploy_weebo_si.rs"
Cohesion: 0.13
Nodes (25): api(), dry_apply(), every_feature_is_present_from_stage_zero_and_enforced_by_the_last(), every_policy_template_selects_no_pod_where_it_lives(), every_reference_names_a_template_in_this_directory(), every_stage_resolves_with_no_violation(), every_team_reaches_the_access_keys_the_guide_offers(), install() (+17 more)

### Community 107 - "access.rs"
Cohesion: 0.09
Nodes (19): a_denial_after_a_retry_is_still_a_denial(), a_transient_error_is_retried_not_read_as_a_denial(), an_apiserver_that_never_answers_is_an_error_once_the_budget_is_spent(), an_explicit_denial_is_not_allowed_and_stops_asking(), both_verbs_allowed_is_allowed(), can(), can_patch(), can_watch() (+11 more)

### Community 108 - "Findings"
Cohesion: 0.08
Nodes (24): C1 — Immutable tags, a pinned base, signatures, C2 — A size budget in CI, `che-min-mise` review, Effect on the weebo-si standard, Findings, H1 — Remove the setuid bits nothing needs, H2 — Stop writing `/etc/passwd`: ship `libnss-wrapper` in the base, H3 — Make `/globals` and `/home/tooling` read-only for the user (+16 more)

### Community 109 - "steps"
Cohesion: 0.07
Nodes (34): name, runs-on, steps, timeout-minutes, jobs, build, lint, test (+26 more)

### Community 110 - "admit.rs"
Cohesion: 0.13
Nodes (36): a_blank_warning_takes_no_slot(), a_control_character_never_reaches_a_warning(), a_denial_in_dry_run_mode_is_recorded_but_never_blocks_admission(), a_denial_in_enforce_mode_short_circuits_admission_and_applies_no_mutation(), admit(), admit_does_not_bound_the_warnings(), admit_with(), AdmitOutcome (+28 more)

### Community 111 - "hard"
Cohesion: 0.06
Nodes (33): cpu, memory, cpu, memory, ResourceQuota quota-build, LimitRange limits-build, limits.cpu, limits.memory (+25 more)

### Community 112 - "hard"
Cohesion: 0.06
Nodes (33): cpu, memory, cpu, memory, ResourceQuota quota-standard, LimitRange limits-standard, limits.cpu, limits.memory (+25 more)

### Community 113 - "config"
Cohesion: 0.06
Nodes (33): cert-manager.io/cluster-issuer, audiences, serviceAccountToken, groups, username, config, bearer, claims (+25 more)

### Community 114 - "weebo-si-pod-security/src/application.rs"
Cohesion: 0.23
Nodes (23): a_clamped_level_counts_as_clamped_and_applied(), a_second_pass_over_what_it_wrote_is_unchanged_and_writes_nothing(), a_stricter_level_set_by_hand_is_reported_and_left_alone(), config(), dry_run_says_what_it_would_write_and_writes_nothing(), enforce_then_teardown_gives_the_namespace_back_exactly_as_found(), enforce_writes_exactly_the_six_labels_and_the_previous_annotation(), facts() (+15 more)

### Community 115 - "e2e.sh"
Cohesion: 0.14
Nodes (33): addon_argocd(), addon_authentik(), addon_kubearmor(), addon_team_tools(), addons(), build(), cluster_dns(), deploy() (+25 more)

### Community 116 - "tasks"
Cohesion: 0.06
Nodes (32): cmds, desc, task, vars, cmds, desc, cmds, desc (+24 more)

### Community 117 - "feature/workspace_gate.rs"
Cohesion: 0.12
Nodes (36): a_create_in_a_namespace_that_already_has_its_baseline_is_allowed(), a_create_in_a_namespace_with_no_baseline_is_denied(), a_create_under_default_naming_an_ungranted_restricted_key_is_allowed_with_a_warning(), a_granted_key_under_deny_is_allowed(), a_granted_restricted_key_under_deny_is_allowed_without_a_warning(), a_mixed_refusal_names_the_restricted_key_only_in_the_restricted_clause(), a_restricted_key_under_deny_is_refused_as_restricted(), a_restricted_key_warning_fits_the_chassis_bound() (+28 more)

### Community 118 - "weebo-si-network-profiles-adapters/src/controller.rs"
Cohesion: 0.07
Nodes (41): a_change_yields_and_a_rewrite_of_the_same_value_does_not(), a_namespace_the_index_has_not_seen_is_retried_in_seconds(), a_namespace_the_index_has_seen_keeps_the_slow_recheck(), config_changes(), CONFIG_POLL, devworkspace_id(), devworkspace_owner(), devworkspace_resource() (+33 more)

### Community 119 - "domain/policy.rs"
Cohesion: 0.12
Nodes (24): Renew, a_larger_budget_allows_more_replays(), a_marker_carrying_request_is_never_injected_into(), a_passed_through_request_is_never_renewed_on_behalf_of_its_caller(), a_renewal_status_spends_one_replay(), a_status_outside_the_list_is_relayed(), a_zero_replay_budget_never_replays(), Action (+16 more)

### Community 120 - "versions"
Cohesion: 0.06
Nodes (31): jsonPath, name, type, apiVersion, kind, metadata, name, kind (+23 more)

### Community 121 - "versions"
Cohesion: 0.06
Nodes (31): jsonPath, name, type, apiVersion, kind, metadata, name, kind (+23 more)

### Community 122 - "weebo-si-registry-config/src/application.rs"
Cohesion: 0.26
Nodes (23): a_cold_template_cache_does_not_delete_the_live_copy(), a_dry_runs_rendered_output_never_carries_the_payload(), a_key_that_stops_being_granted_has_its_copy_deleted(), a_namespace_whose_template_has_not_landed_reports_not_ready(), a_refused_template_does_not_delete_or_rewrite_the_live_copy(), a_second_enforce_pass_with_nothing_changed_reports_unchanged(), config(), drift_is_corrected_on_the_next_enforce_pass() (+15 more)

### Community 123 - "env"
Cohesion: 0.06
Nodes (31): ENVTEST_K8S_VERSION, ENVTEST_SHA512, KUBEBUILDER_ASSETS, REQUIRE_ENVTEST, TRAEFIK_SHA256, TRAEFIK_VERSION, env, name (+23 more)

### Community 124 - "passwd-append/src/main.rs"
Cohesion: 0.17
Nodes (27): a_double_dash_with_no_command_is_a_usage_error(), a_flag_missing_its_value_is_a_usage_error(), a_hostile_home_is_rejected_before_any_file_is_touched(), a_non_numeric_gid_is_a_usage_error(), a_root_effective_uid_is_refused(), a_second_double_dash_belongs_to_the_command(), AllShells, an_image_without_a_shell_gets_an_empty_shell_field() (+19 more)

### Community 125 - "properties"
Cohesion: 0.07
Nodes (30): additionalProperties, type, type, type, type, type, properties, create (+22 more)

### Community 126 - "feature/pod_security.rs"
Cohesion: 0.16
Nodes (20): PodSecurityBackend, Auto, Labels, ObserveSynced, a_build_team_gets_baseline_enforced_and_restricted_warned(), auto_on_openshift_observes_instead_of_writing(), config(), facts() (+12 more)

### Community 127 - "Ecosystem"
Cohesion: 0.14
Nodes (13): Ecosystem, .ALL, Cargo, Composer, Conda, Go, Maven, Npm (+5 more)

### Community 128 - "feature/registry_config.rs"
Cohesion: 0.29
Nodes (23): ResolvedRegistryConfig, a_granted_key_with_two_sources_produces_two_objects(), a_resolved_key_absent_from_the_catalog_is_a_domain_error(), a_template_shadowing_a_home_directory_is_refused_and_never_copied(), a_template_that_has_not_landed_is_reported_as_not_found_and_not_ready(), a_template_without_the_automount_label_is_refused(), an_ungranted_request_under_deny_writes_nothing_at_all(), an_ungranted_team_gets_nothing_and_is_still_ready() (+15 more)

### Community 129 - "team_tools_envtest.rs"
Cohesion: 0.14
Nodes (25): a_cluster_ip_service_template_applies_into_the_tools_namespace(), a_phase_zero_object_is_adopted_in_place(), a_stale_team_tools_status_write_is_a_lost_race_not_an_error(), a_template_update_never_resets_replicas(), a_workspace_object_without_managed_by_is_never_adopted_nor_deleted(), an_invalid_entry_keeps_what_is_rendered_and_off_deletes_only_ours(), cilium_crd(), feature() (+17 more)

### Community 130 - "spike-0009.sh"
Cohesion: 0.24
Nodes (29): che_namespaces(), controller_service(), fetch(), haproxy_ingresses(), has_header(), has_kind(), have_cluster(), heading() (+21 more)

### Community 131 - "src/decide.rs"
Cohesion: 0.04
Nodes (105): Caches, Authorized, Gateway<'a>, Outcome, a_contested_host_denies_rather_than_picking_a_winner(), a_foreign_bearer_is_refused_unless_the_path_asked_for_it(), a_genuine_preflight_is_allowed_and_the_request_after_it_is_not(), a_host_nothing_answers_for_denies_even_for_the_owner() (+97 more)

### Community 132 - "teams_cmd.rs"
Cohesion: 0.15
Nodes (28): a_configuration_with_no_team_exports_nothing_and_does_not_fail(), a_grant_becomes_the_teams_own_catalogue_minus_the_cluster_floor(), a_grant_naming_a_team_nobody_declared_is_reported_not_silently_dropped(), a_grant_that_only_named_the_cluster_floor_is_not_carried_over(), a_granted_key_the_catalogue_never_declared_is_reported(), a_team_with_no_grant_carries_no_block_for_that_feature(), check(), check_is_clean_when_every_team_is_applied_as_declared() (+20 more)

### Community 133 - "env"
Cohesion: 0.07
Nodes (29): concurrency, cancel-in-progress, group, ENVTEST_K8S_VERSION, ENVTEST_SHA512, KUBEBUILDER_ASSETS, REQUIRE_ENVTEST, TRAEFIK_SHA256 (+21 more)

### Community 134 - "steps"
Cohesion: 0.07
Nodes (29): jobs, semgrep, name, on, pull_request, push, schedule, workflow_dispatch (+21 more)

### Community 135 - "tasks"
Cohesion: 0.07
Nodes (29): cmds, desc, cmds, desc, cmds, desc, cmds, desc (+21 more)

### Community 137 - "EnvTest"
Cohesion: 0.12
Nodes (7): assets_dir(), EnvTest, free_port(), generate_service_account_keys(), install_crypto_provider(), STARTUP_TIMEOUT, TEST_TOKEN

### Community 138 - "weebo-si-team-tools-adapters/src/controller.rs"
Cohesion: 0.10
Nodes (30): Regarding, ResolvedTeamToolsConfig, a_grant_naming_a_workspace_or_unlabelled_namespace_is_not_bound(), a_namespace_matching_two_tool_teams_is_reported_once(), a_restart_follows_the_client_objects_creation_in_running_workspaces_only(), attribute_of(), config(), converged() (+22 more)

### Community 139 - "kubearmor_envtest.rs"
Cohesion: 0.21
Nodes (26): kubearmor_policy_resource(), a_cluster_without_the_crd_offers_no_engine(), a_relabelled_node_is_picked_up_after_invalidate(), a_workspace_object_selects_only_that_workspaces_pods(), a_written_object_reads_back_as_the_same_managed_object(), bootstrap(), config(), create_namespace() (+18 more)

### Community 140 - "e2e/values/endpoint-gateway.yaml"
Cohesion: 0.07
Nodes (28): cert-manager.io/cluster-issuer, groups, username, config, claims, clientId, hosts, issuer (+20 more)

### Community 141 - "analyze-rust"
Cohesion: 0.07
Nodes (28): name, permissions, runs-on, steps, timeout-minutes, jobs, analyze-rust, name (+20 more)

### Community 142 - "config"
Cohesion: 0.07
Nodes (28): configmap, enabled, config, backchannelLogout, clientId, enforcement, issuer, probe (+20 more)

### Community 143 - "registry_envtest.rs"
Cohesion: 0.22
Nodes (28): a_granted_namespace_converges_to_a_configmap_and_a_secret(), a_key_that_stops_being_granted_has_its_copies_deleted(), a_second_enforce_pass_reports_unchanged(), a_shadowing_template_is_refused_and_never_copied(), a_written_copy_carries_the_label_the_guard_denies_writes_to(), an_edited_copy_is_restored_on_the_next_pass(), an_ordinary_configmap_in_the_same_namespace_is_allowed(), an_ungranted_key_writes_nothing() (+20 more)

### Community 144 - "write"
Cohesion: 0.14
Nodes (16): a_host_cookie_may_not_outlive_the_session_it_was_minted_from(), a_suffix_that_governs_too_much_refuses_to_start(), an_unknown_field_is_refused_rather_than_ignored(), carrying_traffic_while_believing_any_callers_address_header_refuses_to_start(), forward_auth_without_a_trusted_proxy_is_warned_about_and_nothing_else_is(), introspection_is_off_by_default_and_remembers_a_refusal_for_half_a_minute(), plain_http_endpoints_for_the_issuer_or_the_callback_refuse_to_start(), the_back_channel_has_a_limit_of_its_own_and_generous_by_default() (+8 more)

### Community 145 - "workspace_images.rs"
Cohesion: 0.22
Nodes (21): a_namespace_with_no_team_gets_the_top_level_default(), a_platform_image_is_permitted_whatever_the_grant_says(), a_workspace_running_only_granted_images_is_allowed(), a_workspace_with_no_images_is_allowed_and_says_so(), an_absent_configuration_is_an_error_not_a_silent_allow(), catalog(), config(), evaluate() (+13 more)

### Community 146 - "matchLabels"
Cohesion: 0.08
Nodes (27): apiVersion, toEndpoints, toEntities, toPorts, matchLabels, matchLabels, fromEndpoints, kind (+19 more)

### Community 147 - "RFC 0005 — image-policy"
Cohesion: 0.07
Nodes (28): A pattern set is a union, Alternatives considered, Architecture, Changelog, CLI, Contract, Data and state, Design (+20 more)

### Community 148 - "RFC 0011 — teams and users as objects"
Cohesion: 0.07
Nodes (28): A person, A team, Alternatives considered, Architecture, Changelog, Contract, Data and state, Design (+20 more)

### Community 149 - "RFC 0013 — pod-security"
Cohesion: 0.07
Nodes (28): A build workspace: user namespace, then a filter, Alternatives considered, Architecture, Changelog, CLI, Contract, Data and state, Design (+20 more)

### Community 150 - "`spec.features`"
Cohesion: 0.06
Nodes (32): Catalogue and grants, `features.devfileContract`, `features.dwocPin`, `features.endpointAuth`, `features.identity`, `features.imagePolicy`, `features.imageRewrite`, `features.kubearmorPolicy` (+24 more)

### Community 151 - "deny"
Cohesion: 0.07
Nodes (27): name, permissions, runs-on, steps, timeout-minutes, jobs, deny, name (+19 more)

### Community 152 - "weebo-si-resource-quotas/src/application.rs"
Cohesion: 0.20
Nodes (23): a_second_pass_is_unchanged_and_writes_nothing(), an_invalid_profile_keeps_the_existing_ceiling(), an_invalid_profile_on_a_bare_namespace_writes_nothing(), check_catalog_names_the_invalid_profile(), config(), dry_run_writes_nothing(), enforce_writes_exactly_the_two_fixed_names(), feature() (+15 more)

### Community 153 - "openAPIV3Schema"
Cohesion: 0.07
Nodes (26): apiVersion, kind, metadata, name, kind, plural, singular, description (+18 more)

### Community 154 - "weebo-si-registry-config/src/resolve.rs"
Cohesion: 0.24
Nodes (25): RegistryGrant, RegistryKey, a_namespace_annotation_is_a_request_never_a_grant(), a_partially_granted_request_under_deny_names_only_the_ungranted_keys(), a_team_with_no_grant_gets_nothing_rather_than_a_baseline(), an_empty_annotation_means_explicitly_nothing_and_does_not_fall_through(), an_ungranted_request_under_default_falls_back_and_is_flagged(), an_ungranted_request_under_deny_is_refused() (+17 more)

### Community 155 - "weebo-si-kubearmor-policy-adapters/src/controller.rs"
Cohesion: 0.10
Nodes (27): DefaultPosture, configured_off(), Ctx, enforcement_loop(), ENFORCEMENT_TICK, Error, error_policy(), every_annotation_key_is_kubearmors_own() (+19 more)

### Community 156 - "Applied"
Cohesion: 0.07
Nodes (19): apply_document(), delete(), KubeManagedQuotaStore, KubeQuotaTemplateStore, managed_label(), managed_object(), only_the_management_label_makes_an_object_ours(), spawn_reflector() (+11 more)

### Community 157 - "GatewayConfig"
Cohesion: 0.11
Nodes (11): ClaimsConfig, default_deny_per_minute(), default_probe_interval(), Enforcement, Enforce, Observe, GatewayConfig, HostsConfig (+3 more)

### Community 158 - "weebo-si-network-profiles-adapters/tests/envtest.rs"
Cohesion: 0.15
Nodes (24): a_leftover_server_pod_from_an_interrupted_run_is_reused(), a_server_pod_that_terminated_is_inconclusive_never_blocked(), a_workspace_with_two_granted_profiles_gets_two_real_objects(), canary_fixture(), CANARY_NAMESPACE, cleanup_is_a_no_op_when_the_probe_never_ran(), cleanup_removes_every_object_the_probe_created(), config() (+16 more)

### Community 159 - "events.rs"
Cohesion: 0.11
Nodes (13): a_devworkspace_reference_carries_its_kind(), DynamicObject, every_reason_is_a_valid_event_reason(), regarding_typed!, publish(), ReasonCode, .SUCCESS, reconciled() (+5 more)

### Community 160 - "container"
Cohesion: 0.07
Nodes (26): hardening.weebo.io/access, attributes, hardening.weebo.io/image-policy, hardening.weebo.io/network-profiles, components, container, name, cpuLimit (+18 more)

### Community 161 - "package.json"
Cohesion: 0.11
Nodes (25): eslint, eslint-config-next, postcss, tailwindcss, @tailwindcss/postcss, @types/mdx, @types/node, @types/react (+17 more)

### Community 162 - "weebo-si-crd"
Cohesion: 0.28
Nodes (31): endpoint-gateway, weebo-si-chassis, weebo-si-controller, weebo-si-crd, weebo-si-devfile-contract, weebo-si-dwoc-pin, weebo-si-endpoint-auth, weebo-si-endpoint-auth-adapters (+23 more)

### Community 163 - "tasks"
Cohesion: 0.08
Nodes (25): cmds, desc, dir, cmds, desc, dir, task, cmds (+17 more)

### Community 164 - "src/config.rs"
Cohesion: 0.12
Nodes (16): BackchannelConfig, CacheConfig, default_backchannel_rate(), default_grant_ttl(), default_host_ttl(), default_identity_entries(), default_identity_ttl(), default_login_rate() (+8 more)

### Community 165 - "endpoint-gateway/values.yaml"
Cohesion: 0.08
Nodes (24): autoscaling, enabled, maxReplicas, minReplicas, targetCPUUtilizationPercentage, imagePullSecrets, metrics, enabled (+16 more)

### Community 166 - "openshift_pod_security_envtest.rs"
Cohesion: 0.12
Nodes (7): auto_observes_on_openshift_and_reports_a_looser_synced_level_without_writing(), feature(), install_scc(), envtest_or_skip!, pass(), scc_crd(), synced_namespace()

### Community 167 - "tests/workspace.rs"
Cohesion: 0.08
Nodes (51): metric_sum(), a_catalogue_entry_pointing_at_nothing_is_refused_under_on_missing_target_deny(), a_current_devfile_is_silent_and_a_later_denial_only_refuses_the_next_start(), a_devworkspacetemplate_parent_warns_and_still_starts(), a_dry_run_restricted_refusal_is_still_counted(), a_dry_run_rewrite_counts_the_rewrite_and_changes_nothing(), a_granted_workspace_starts_with_every_pod_devworkspace_operator_builds_admitted(), a_hostile_generator_attribute_is_bounded_everywhere() (+43 more)

### Community 168 - "versions"
Cohesion: 0.08
Nodes (24): apiVersion, kind, metadata, name, kind, listKind, plural, singular (+16 more)

### Community 169 - "versions"
Cohesion: 0.08
Nodes (24): apiVersion, kind, metadata, name, kind, listKind, plural, singular (+16 more)

### Community 170 - "versions"
Cohesion: 0.08
Nodes (24): apiVersion, kind, metadata, name, kind, listKind, plural, singular (+16 more)

### Community 171 - "weebo-si-resource-quotas/src/lib.rs"
Cohesion: 0.11
Nodes (18): reconcile(), ReconcileOutcome, teardown(), DesiredState, a_zero_limit_is_a_ban_that_counts_only_once_used(), FIELD_MANAGER, LIMITS_NAME, no_status_yet_is_no_band() (+10 more)

### Community 172 - "matchDirectories"
Cohesion: 0.09
Nodes (24): apiVersion, matchDirectories, matchPaths, kind, hardening.weebo.io/template, action, dir, readOnly (+16 more)

### Community 173 - "RFC 0008 — policy-guard-coverage"
Cohesion: 0.08
Nodes (25): A second webhook path, not a second rule on the first, Alternatives considered, Architecture, Changelog, Contract, Data and state, Design, Drawbacks and risks (+17 more)

### Community 174 - "RFC 0014 — resource-quotas"
Cohesion: 0.08
Nodes (25): Alternatives considered, Architecture, Changelog, CLI, Contract, Data and state, Design, Drawbacks and risks (+17 more)

### Community 175 - "RFC 0016 — WeeboSiProject"
Cohesion: 0.08
Nodes (24): A project, A team that declares projects, Alternatives considered, angos, Architecture, Changelog, Contract, Data and state (+16 more)

### Community 176 - "RFC 0017 — image-rewrite"
Cohesion: 0.08
Nodes (25): Alternatives considered, Architecture, Before / after, Changelog, Contract, Data and privacy, Data and state, Design (+17 more)

### Community 177 - "with"
Cohesion: 0.08
Nodes (25): with, cache-from, cache-to, category, context, exit-code, file, format (+17 more)

### Community 178 - "preauth-proxy/src/main.rs"
Cohesion: 0.17
Nodes (17): a_flag_missing_its_value_is_refused(), an_unknown_flag_is_refused(), Args, argv(), check_is_a_boolean(), CONFIG, DEFAULT_CONFIG, INTERNAL (+9 more)

### Community 179 - "weebo-si-team-tools/src/render.rs"
Cohesion: 0.09
Nodes (46): ToolIssuerRef, ToolKey, is_tools_side(), owner(), valid_entry(), a_rendered_service_drops_the_template_allocations(), a_rendered_workload_never_carries_replicas_nor_template_metadata(), a_requester_template_keeps_its_dwo_mount_keys() (+38 more)

### Community 180 - "versions"
Cohesion: 0.08
Nodes (23): apiVersion, kind, metadata, name, kind, plural, singular, properties (+15 more)

### Community 181 - "pod_security_envtest.rs"
Cohesion: 0.22
Nodes (17): a_label_somebody_else_changes_is_drift_and_is_put_back(), a_restore_with_nothing_before_removes_every_key(), a_stricter_level_an_admin_set_is_left_alone(), annotations(), create_namespace(), create_violating_pod(), dry_run_writes_nothing(), enforce_writes_the_six_labels_and_restore_gives_the_namespace_back() (+9 more)

### Community 182 - "RuntimeClass crun"
Cohesion: 0.11
Nodes (23): RuntimeClass crun, RuntimeClass youki, RuntimeClass gvisor, RuntimeClass kata, weebo.io/runtime, labels, name, apiVersion (+15 more)

### Community 183 - "lint"
Cohesion: 0.08
Nodes (23): jobs, lint, name, runs-on, steps, timeout-minutes, name, on (+15 more)

### Community 184 - "tests/pod_security.rs"
Cohesion: 0.07
Nodes (27): kubearmor_policy(), a_build_team_gets_baseline_and_a_che_workspace_starts_there(), a_build_workspace_builds_an_image_under_its_profile_and_not_under_runtime_default(), build(), build_dwoc(), build_workspace(), BUILDAH, BUSYBOX (+19 more)

### Community 185 - "kube_provisioner.rs"
Cohesion: 0.14
Nodes (7): ARGO_GROUP, AUTHENTIK_GROUP, FIELD_MANAGER, KubeProvisioner, OWNER_API_VERSION, owner_uid(), controller_deps()

### Community 186 - "features"
Cohesion: 0.08
Nodes (24): mode, mode, dwocPin, endpointAuth, identity, imagePolicy, imageRewrite, kubearmorPolicy (+16 more)

### Community 187 - "The weebo-si standard"
Cohesion: 0.09
Nodes (23): Asked of weebo-si, Asked of WeeboDevImage, che-min-mise's start-up and the network, Keeping `deploy/weebo-si/` honest, Mirrors: what changes for che-min-mise, Pod Security, Quotas, Rolling back (+15 more)

### Community 188 - "RFC 0002 — weebo-si-operator"
Cohesion: 0.09
Nodes (23): Alternatives considered, Architecture, Changelog, CLI, Contract, Data and state, Design, Drawbacks and risks (+15 more)

### Community 189 - "RFC 0007 — registry-config"
Cohesion: 0.09
Nodes (23): Alternatives considered, Architecture, Changelog, CLI, Contract, Data and state, Design, Drawbacks and risks (+15 more)

### Community 190 - "brick"
Cohesion: 0.09
Nodes (22): name, permissions, uses, with, jobs, brick, name, on (+14 more)

### Community 191 - "brick"
Cohesion: 0.09
Nodes (22): name, permissions, uses, with, jobs, brick, name, on (+14 more)

### Community 192 - "brick"
Cohesion: 0.09
Nodes (22): name, permissions, uses, with, jobs, brick, name, on (+14 more)

### Community 193 - "brick"
Cohesion: 0.09
Nodes (22): name, permissions, uses, with, jobs, brick, name, on (+14 more)

### Community 194 - "Changelog"
Cohesion: 0.07
Nodes (27): Bug Fixes, Bug Fixes, Bug Fixes, Bug Fixes, Bug Fixes, Bug Fixes, Build system, Changelog (+19 more)

### Community 195 - "properties"
Cohesion: 0.12
Nodes (22): type, additionalProperties, properties, type, type, additionalProperties, properties, type (+14 more)

### Community 196 - "weebo-si-network-profiles/src/resolve.rs"
Cohesion: 0.16
Nodes (40): ProfileGrant, a_grant_never_selects(), a_partially_granted_request_under_deny_names_only_the_ungranted_keys(), a_restricted_default_is_a_violation_and_is_filtered(), a_restricted_key_named_by_the_grant_annotation_is_honoured(), a_restricted_key_requested_by_the_attribute_without_the_namespace_grant_is_not_granted(), a_team_with_no_grant_falls_back_to_the_synthetic_empty_grant(), an_annotation_naming_a_key_the_team_lacks_unlocks_nothing() (+32 more)

### Community 197 - "weebo-si-registry-config-adapters/src/controller.rs"
Cohesion: 0.15
Nodes (15): CatalogSnapshot, configured_off(), Ctx, Error, error_policy(), FEATURE, managed_objects_loop(), MANAGED_OBJECTS_TICK (+7 more)

### Community 198 - "spec"
Cohesion: 0.09
Nodes (21): apiVersion, kind, metadata, name, kind, plural, singular, properties (+13 more)

### Community 199 - "feature/image_rewrite.rs"
Cohesion: 0.16
Nodes (21): FEATURE_ID, a_hostile_name_cannot_break_out_of_the_annotation_json(), a_matching_image_is_set_in_place_and_its_original_recorded(), a_write_that_cannot_carry_an_annotation_gets_only_the_image(), an_invalid_rule_set_rewrites_nothing(), evaluate(), every_image_is_counted_once_with_its_result(), feature() (+13 more)

### Community 200 - "RFC 0004 — network-profiles"
Cohesion: 0.09
Nodes (22): Alternatives considered, Architecture, Changelog, CLI, Contract, Data and state, Design, Drawbacks and risks (+14 more)

### Community 201 - "`spec.features`"
Cohesion: 0.09
Nodes (23): `features.dwocPin`, `features.endpointAuth`, `features.imagePolicy`, `features.kubearmorPolicy`, `features.networkProfiles`, `features.podSecurity`, `features.registryConfig`, `features.resourceQuotas` (+15 more)

### Community 202 - "tasks"
Cohesion: 0.09
Nodes (21): cmds, desc, cmds, desc, cmds, desc, dir, cmds (+13 more)

### Community 203 - "feature_tests.rs"
Cohesion: 0.13
Nodes (34): a_block_removed_mid_request_admits_untouched(), a_control_character_never_reaches_a_warning(), a_denial_never_quotes_credentials_from_the_admin_prefix(), a_denied_contract_refuses_a_devfile_without_the_attribute(), a_denied_parent_on_a_non_start_update_is_a_warning(), a_denied_parent_on_a_start_is_refused_quoting_the_admin_entry(), a_denied_prefix_is_not_bypassed_by_another_spelling(), a_denied_prefix_matches_despite_query_and_userinfo() (+26 more)

### Community 204 - "Weebo Dev Env - Guideline for the Weebo Dev Env"
Cohesion: 0.10
Nodes (20): Backend, Code, Command, Command output, CRD validation: CEL or `validate()`, Devfile, Doc / Gen / Guideline, Dockerfile / Containerfile (+12 more)

### Community 205 - "TargetState"
Cohesion: 0.09
Nodes (11): TargetState, Absent, Adopted, Conflict, Created, Off, every_state_has_a_lowercase_label(), IdentityMetrics (+3 more)

### Community 206 - "spec"
Cohesion: 0.10
Nodes (20): apiVersion, kind, metadata, name, kind, listKind, plural, singular (+12 more)

### Community 207 - "podSecurityContext"
Cohesion: 0.10
Nodes (20): apiVersion, config, routing, workspace, procMount, kind, metadata, name (+12 more)

### Community 208 - "podSecurityContext"
Cohesion: 0.10
Nodes (20): apiVersion, drop, config, routing, workspace, allowPrivilegeEscalation, capabilities, kind (+12 more)

### Community 209 - "compilerOptions"
Cohesion: 0.10
Nodes (20): compilerOptions, allowJs, esModuleInterop, forceConsistentCasingInFileNames, incremental, isolatedModules, jsx, lib (+12 more)

### Community 210 - "tasks"
Cohesion: 0.10
Nodes (20): cmds, desc, cmds, desc, cmds, desc, silent, cmds (+12 more)

### Community 211 - "violation.rs"
Cohesion: 0.13
Nodes (41): an_ephemeral_update_is_never_rewritten(), config(), fixed_pod(), fs_group_change_policy_set_on_rewrite(), granted_group_zero_keeps_fs_group_zero(), host_users_set_false_on_rewrite(), identity_rewrite(), no_written_path_is_the_parent_of_another() (+33 more)

### Community 212 - "service"
Cohesion: 0.10
Nodes (20): additionalProperties, properties, type, additionalProperties, properties, type, type, type (+12 more)

### Community 213 - "networkPolicy"
Cohesion: 0.11
Nodes (20): enabled, namespaceSelector, podSelector, cidrs, namespaceSelector, podSelector, ports, k8s-app (+12 more)

### Community 214 - "weebo-si-pod-security-adapters/src/controller.rs"
Cohesion: 0.12
Nodes (18): a_namespace_the_selector_excludes_is_left_once_the_index_knows_it(), an_unloaded_configuration_never_restores_anything(), config(), Ctx, Error, error_policy(), FEATURE, leaving() (+10 more)

### Community 215 - "resource_quotas_envtest.rs"
Cohesion: 0.27
Nodes (16): a_foreign_quota_is_counted_and_survives_teardown(), an_invalid_profile_keeps_the_ceiling_the_namespace_already_has(), config(), create(), create_namespace(), enforce_writes_the_two_objects_and_a_second_pass_is_unchanged(), key(), envtest_or_skip! (+8 more)

### Community 216 - "Contract"
Cohesion: 0.10
Nodes (20): Attaching the gate: one contract, several dialects, Checking that assumption rather than configuring it, Contract, Group claims, and why the cookie only carries some of them, How a host session is minted, HTTP surface, Nothing here is restart-time configuration, Operator-side: mutate, reconcile, guard (+12 more)

### Community 217 - "weebo-si-operator/values.yaml"
Cohesion: 0.10
Nodes (20): imagePolicy, podWebhook, imagePullSecrets, imageRewrite, webhooks, namespace, create, extraLabels (+12 more)

### Community 218 - "weebo-si-team-tools-adapters/src/reconcile.rs"
Cohesion: 0.08
Nodes (40): Applied, Diff, Delete, ObjectKey, failure(), SystemClock, Adoption, Adopt (+32 more)

### Community 219 - "weebo-si-crd/tests/envtest.rs"
Cohesion: 0.20
Nodes (25): a_team_tools_issuer_must_be_a_cluster_issuer(), a_well_formed_dwoc_pin_block_is_accepted(), admission_rejects_a_dwoc_pin_block_missing_mode(), an_empty_features_block_is_accepted(), apply_crd(), config(), configs(), devfile_contract_cel_rules_accept_the_example_and_refuse_each_mistake() (+17 more)

### Community 220 - "RuntimeBackend"
Cohesion: 0.06
Nodes (23): RuntimeBackend, KubeArmor, RuntimeEnforcementBackend, Auto, KubeArmor, KubeArmorPolicyDeps, a_cluster_with_the_crd_offers_kubearmor(), a_cluster_without_the_crd_offers_nothing() (+15 more)

### Community 221 - "network_metrics.rs"
Cohesion: 0.17
Nodes (16): a_reconcile_with_no_team_is_still_counted_under_a_real_label_value(), a_shrinking_population_shrinks_the_gauge(), an_error_is_its_own_result_not_a_missing_increment(), an_ungranted_key_is_counted_per_team_and_profile(), an_update_is_drift_restored_and_a_create_is_not(), dry_run_never_lands_on_a_write_result(), enforce_counts_what_was_applied_under_the_matched_team(), kind_label() (+8 more)

### Community 222 - "node_enforcer.rs"
Cohesion: 0.10
Nodes (14): a_node_naming_its_lsm_is_enforced_and_the_gauge_reads_one(), a_node_with_no_enforcer_label_is_not_enforced_rather_than_unknown(), an_empty_enforcer_label_is_treated_as_no_enforcer(), an_unscheduled_pod_projects_with_no_node_name(), enforcement_from_label(), KubeNodeEnforcerView, PodFacts, project_node() (+6 more)

### Community 223 - "weebo-si-operator/src/main.rs"
Cohesion: 0.19
Nodes (13): CACHES_NEVER_SYNCED, every_rendered_crd_has_no_unquoted_yaml11_boolean(), INTERNAL, main(), OK, print_crd(), print_features(), quote_yaml11_booleans() (+5 more)

### Community 224 - "plan.rs"
Cohesion: 0.25
Nodes (25): a_bare_namespace_gets_the_six_labels_and_an_empty_previous(), a_foreign_owner_before_the_first_write_is_not_drift(), a_label_changed_by_somebody_else_after_the_first_write_is_drift(), a_looser_existing_level_is_taken_over_and_remembered(), a_stricter_level_somebody_else_set_is_left_alone(), a_stricter_level_this_feature_wrote_is_lowered_when_the_resolution_loosens(), an_equal_level_somebody_else_set_is_taken_over(), an_unreadable_previous_is_kept_as_is_and_reported() (+17 more)

### Community 225 - "endpointAuth"
Cohesion: 0.12
Nodes (17): breakGlassIdentities, default, endpointSelection, hosts, mode, overrides, owner, selfOrigin (+9 more)

### Community 226 - "data"
Cohesion: 0.11
Nodes (18): controller.devfile.io/mount-as, apiVersion, data, GOPROXY, NPM_CONFIG_REGISTRY, PIP_INDEX_URL, RUSTUP_DIST_SERVER, RUSTUP_UPDATE_ROOT (+10 more)

### Community 227 - "RFC 0010 — endpoint-auth on OpenShift"
Cohesion: 0.11
Nodes (19): Alternatives considered, Architecture, Blocking, Changelog, Contract, Data and state, Design, Drawbacks and risks (+11 more)

### Community 228 - "source.ts"
Cohesion: 0.13
Nodes (13): GET, revalidate, dynamic, GET, revalidate, dynamic, generateStaticParams, GET (+5 more)

### Community 229 - "render.rs"
Cohesion: 0.12
Nodes (25): CONFIG_REF_ATTRIBUTE, a_null_parent_is_replaced_rather_than_written_under(), a_scalar_and_an_annotation_under_one_missing_map_both_survive(), a_scalar_under_an_existing_parent_adds_only_the_field(), add(), an_empty_path_writes_nothing(), annotate_adds_the_whole_annotations_map_when_absent(), ANNOTATIONS (+17 more)

### Community 230 - "selector.rs"
Cohesion: 0.17
Nodes (15): a_missing_match_labels_key_fails_the_match(), does_not_exist_operator_matches_when_the_key_is_absent(), empty_selector_matches_everything(), exists_operator_ignores_values_and_checks_key_presence(), in_operator_matches_when_the_label_value_is_in_the_list(), in_operator_with_empty_values_matches_nothing(), labels(), match_labels_and_match_expressions_are_anded_together() (+7 more)

### Community 231 - "properties"
Cohesion: 0.11
Nodes (18): type, additionalProperties, properties, type, enum, type, type, clientId (+10 more)

### Community 232 - "kubearmor_metrics.rs"
Cohesion: 0.09
Nodes (17): Diff, ManagedObject, an_enforced_node_gauges_one_and_names_its_enforcer(), delete(), Enforcement, Enforced, NotEnforced, Unknown (+9 more)

### Community 233 - "kube_catalog.rs"
Cohesion: 0.09
Nodes (16): a_user_in_two_teams_gets_the_same_one_whatever_the_order(), an_anonymous_and_delegating_entry_is_dropped_alone(), catalogue_from(), fnv(), grant_for(), hosts_of(), KubeCatalog, Owner (+8 more)

### Community 234 - "files"
Cohesion: 0.11
Nodes (17): apiVersion, ignition, storage, source, contents, mode, overwrite, path (+9 more)

### Community 235 - "spec"
Cohesion: 0.11
Nodes (17): extraAddons, level, apiVersion, mode, values, access, kind, metadata (+9 more)

### Community 236 - "RFC 0000 — Template"
Cohesion: 0.11
Nodes (17): Alternatives considered, Architecture, Changelog, Contract, Data and state, Design, Drawbacks and risks, Future work (+9 more)

### Community 237 - "RFC 0001 — passwd-append"
Cohesion: 0.11
Nodes (18): Alternatives considered, Architecture, Changelog, Contract, Data and state, Design, Drawbacks and risks, Future work (+10 more)

### Community 238 - "RFC 0003 — preauth-proxy"
Cohesion: 0.11
Nodes (18): Alternatives considered, Architecture, Changelog, Contract, Data and state, Design, Drawbacks and risks, Future work (+10 more)

### Community 239 - "RFC 0012 — operator kit migration"
Cohesion: 0.11
Nodes (18): Alternatives considered, Architecture, Changelog, Contract, Data and state, Design, Documentation site, Drawbacks and risks (+10 more)

### Community 240 - "RFC 0015 — platform API group for teams and users"
Cohesion: 0.11
Nodes (17): Alternatives considered, Architecture, Changelog, Contract, Data and state, Design, Drawbacks and risks, Future work (+9 more)

### Community 241 - "env"
Cohesion: 0.18
Nodes (18): steps, ACTOR, GH_TOKEN, HELM_REGISTRY_TOKEN, NOTES, OWNER, PRERELEASE, REFS (+10 more)

### Community 242 - "probe.rs"
Cohesion: 0.10
Nodes (15): apply(), classify(), FORGED_ADDRESS, only_an_answered_selftest_is_conclusive(), probe_once(), ProbeResult, Clean, Forged (+7 more)

### Community 243 - "Failure"
Cohesion: 0.18
Nodes (12): apply(), Args, config_command(), env_flag(), Failure, Field, Internal, Usage (+4 more)

### Community 244 - "key"
Cohesion: 0.13
Nodes (17): additionalProperties, properties, type, type, minLength, type, clientSecret, existingSecret (+9 more)

### Community 245 - "pods_cmd.rs"
Cohesion: 0.22
Nodes (14): ResolvedPodSecurityConfig, an_unknown_level_is_a_usage_error(), audit(), config(), each_namespace_gets_the_level_the_controller_would_resolve(), in_scope(), level_flag(), level_overrides_the_configuration_and_works_without_one() (+6 more)

### Community 246 - "weebo-armor-build.yaml"
Cohesion: 0.12
Nodes (16): apiVersion, kind, hardening.weebo.io/template, hardening.weebo.io/template, action, path, metadata, labels (+8 more)

### Community 247 - "weebo-net-anthropic.yaml"
Cohesion: 0.12
Nodes (16): apiVersion, toFQDNs, toPorts, matchLabels, kind, hardening.weebo.io/template, hardening.weebo.io/template, metadata (+8 more)

### Community 248 - "weebo-net-dev-registries.yaml"
Cohesion: 0.12
Nodes (16): apiVersion, toFQDNs, toPorts, matchLabels, kind, hardening.weebo.io/template, hardening.weebo.io/template, metadata (+8 more)

### Community 249 - "@weebo/operator-docs"
Cohesion: 0.18
Nodes (7): RFC-0012, fumadocs-ui, @weebo/operator-docs, generateStaticParams, GET, revalidate, site

### Community 250 - "RFC 0006 — kubearmor-policy"
Cohesion: 0.12
Nodes (17): Alternatives considered, Architecture, Changelog, Contract, Data and state, Design, Drawbacks and risks, Future work (+9 more)

### Community 251 - "image"
Cohesion: 0.12
Nodes (16): sh, cmds, desc, requires, vars, cmds, desc, cmds (+8 more)

### Community 252 - "properties"
Cohesion: 0.12
Nodes (16): type, type, additionalProperties, properties, type, type, additionalProperties, properties (+8 more)

### Community 253 - "properties"
Cohesion: 0.14
Nodes (16): type, additionalProperties, properties, type, additionalProperties, properties, type, additionalProperties (+8 more)

### Community 254 - "Subject"
Cohesion: 0.13
Nodes (25): DevfileWorkspace, is_start(), only_a_create_a_start_or_a_running_template_change_is_a_start(), absent_attribute_is_none(), an_empty_attribute_key_disables_the_channel_entirely(), CHE_DEVFILE_ANNOTATION, devfile_workspace_from_object(), devworkspace() (+17 more)

### Community 255 - "weebo-net-kube-api.yaml"
Cohesion: 0.12
Nodes (15): apiVersion, toEntities, toPorts, matchLabels, kind, hardening.weebo.io/template, hardening.weebo.io/template, metadata (+7 more)

### Community 256 - "admission.rs"
Cohesion: 0.15
Nodes (29): a_create_reads_init_then_regular_containers_and_the_generate_name(), a_plain_pod_update_or_delete_is_not_judged(), admit(), an_ephemeral_update_reads_only_the_new_ephemeral_containers(), an_ephemeral_update_without_old_object_is_refused_as_on_host_userns(), an_unobserved_namespace_is_refused_by_validation_and_left_to_it_by_the_mutation(), container(), dry_run_patches_nothing_and_refuses_nothing() (+21 more)

### Community 257 - "append_locked"
Cohesion: 0.16
Nodes (12): append_locked(), AppendError, Prepare, Write, NameOwner, Uid, Unparseable, Outcome (+4 more)

### Community 258 - "WebhookMetrics"
Cohesion: 0.32
Nodes (4): no_series_exists_until_a_request_is_actually_skipped(), the_two_guard_routes_are_distinguishable_under_one_feature_label(), unguarded_series(), WebhookMetrics

### Community 259 - "found.rs"
Cohesion: 0.33
Nodes (10): a_bare_namespace_is_neither_owned_nor_foreign(), a_foreign_entry_for_a_label_no_longer_present_does_not_count(), a_key_kubectl_set_is_foreign(), an_update_under_this_managers_name_is_not_an_apply(), entry(), found(), keys_applied_by_this_field_manager_are_owned(), namespace() (+2 more)

### Community 260 - "weebo-si-registry-config/src/model/diff.rs"
Cohesion: 0.18
Nodes (10): a_changed_mount_path_alone_is_an_update(), a_config_map_and_a_secret_of_one_name_are_two_objects(), a_held_object_is_neither_deleted_nor_updated(), a_lost_automount_label_is_an_update(), a_renamed_catalogue_key_alone_does_not_rewrite_the_copy(), compute_held_diff(), ManagedObject, object() (+2 more)

### Community 261 - "features"
Cohesion: 0.13
Nodes (14): apiVersion, allowedGroupRefs, allowedProjects, allowedRepoUrls, applicationNamespace, identity, authentik, che (+6 more)

### Community 262 - "features"
Cohesion: 0.17
Nodes (12): catalog, default, dwocPin, kubearmorPolicy, podSecurity, resourceQuotas, catalog, default (+4 more)

### Community 263 - "metadata"
Cohesion: 0.13
Nodes (14): controller.devfile.io/mount-as, controller.devfile.io/mount-path, apiVersion, data, config.toml, kind, controller.devfile.io/mount-to-devworkspace, controller.devfile.io/watch-configmap (+6 more)

### Community 264 - "`endpoint-gateway`"
Cohesion: 0.09
Nodes (23): Argo CD, Before you turn it on, Break-glass, Calling an endpoint without a browser, Carrying traffic: the OpenShift shape — deferred, Certificate annotations, Configuration, `endpoint-gateway` (+15 more)

### Community 265 - "workspace-image"
Cohesion: 0.14
Nodes (15): permissions, permissions, jobs, tests, workspace-image, contents, name, permissions (+7 more)

### Community 266 - "with"
Cohesion: 0.13
Nodes (15): with, cache-from, cache-to, context, file, merge-multiple, name, outputs (+7 more)

### Community 267 - "jobs"
Cohesion: 0.13
Nodes (14): name, needs, permissions, uses, concurrency, cancel-in-progress, group, jobs (+6 more)

### Community 268 - "check_file"
Cohesion: 0.27
Nodes (12): check_english_only(), check_file(), fail(), is_iso_date(), rfc-check.sh script, rfc-index.sh script, rfc_files(), rfc_fm() (+4 more)

### Community 269 - "spike-0009-che.sh"
Cohesion: 0.28
Nodes (13): cluster_dns(), down(), forward(), install_sso(), kind_config(), make_ca(), node_hosts(), realm_json() (+5 more)

### Community 271 - "enabled"
Cohesion: 0.14
Nodes (14): type, type, type, additionalProperties, properties, type, additionalProperties, properties (+6 more)

### Community 272 - "properties"
Cohesion: 0.14
Nodes (14): type, type, type, type, grantTtlSecs, hostSliding, hostTtlSecs, maxGroups (+6 more)

### Community 273 - "webhook"
Cohesion: 0.14
Nodes (14): metrics, service, maxSurge, maxUnavailable, enabled, port, targetPort, webhook (+6 more)

### Community 274 - "weebo-net-internet.yaml"
Cohesion: 0.14
Nodes (13): apiVersion, toEntities, matchLabels, kind, hardening.weebo.io/template, hardening.weebo.io/template, metadata, labels (+5 more)

### Community 275 - "`WeeboSiTeam` and `WeeboSiUser`"
Cohesion: 0.14
Nodes (14): 1. Grant the RBAC, and read what you are granting, 2. Write the feature block, starting at `DryRun`, 3. Flip to `Enforce`, Failure modes, Install, Known limitations, Migrating from `spec.teams`, Observability (+6 more)

### Community 276 - "`WeeboSiUser` — the person reference"
Cohesion: 0.14
Nodes (14): `active`, Deleting a person, `displayName`, `email`, Keys, Provisioning, and who owns what, `spec`, `spec.authentik` (+6 more)

### Community 277 - "with"
Cohesion: 0.14
Nodes (14): with, cache-from, cache-to, context, file, images, labels, password (+6 more)

### Community 278 - "Production-readiness TODO"
Cohesion: 0.14
Nodes (13): Blockers, CI / release, Deferred with the OpenShift dialect (RFC 0010, Draft), endpoint-gateway (agent), Follow-ups found while fixing, High, Low, Medium (+5 more)

### Community 279 - "probes"
Cohesion: 0.15
Nodes (13): failureThreshold, periodSeconds, timeoutSeconds, probes, liveness, readiness, startup, failureThreshold (+5 more)

### Community 281 - "managed/diff.rs"
Cohesion: 0.21
Nodes (13): a_delete_carries_the_uid_the_object_was_listed_with(), a_field_content_eq_ignores_does_not_force_an_update(), a_uid_alone_does_not_force_an_update(), identical_in_both_is_unchanged(), object(), present_only_in_desired_is_a_create(), present_only_in_existing_is_a_delete_carrying_its_backend(), same_key_different_backend_is_an_update() (+5 more)

### Community 282 - "value"
Cohesion: 0.15
Nodes (12): machine, seccompProfiles, name, value, action, args, errnoRet, names (+4 more)

### Community 283 - "bricks"
Cohesion: 0.17
Nodes (13): name, needs, permissions, strategy, uses, strategy, crate, path (+5 more)

### Community 284 - "check:envtest"
Cohesion: 0.10
Nodes (19): cmds, desc, cmds, deps, desc, env, KUBEBUILDER_ASSETS, REQUIRE_ENVTEST (+11 more)

### Community 285 - "endpoint-gateway/Chart.yaml"
Cohesion: 0.17
Nodes (11): apiVersion, appVersion, description, home, keywords, maintainers, name, name (+3 more)

### Community 286 - "properties"
Cohesion: 0.17
Nodes (12): additionalProperties, properties, type, type, additionalProperties, properties, type, backchannelLogout (+4 more)

### Community 287 - "properties"
Cohesion: 0.17
Nodes (12): type, type, clientIpHeader, podNetwork, selfOrigin, serviceAccountToken, trustedProxy, additionalProperties (+4 more)

### Community 288 - "properties"
Cohesion: 0.17
Nodes (12): type, additionalProperties, properties, type, digest, image, pullPolicy, repository (+4 more)

### Community 289 - "preauth-proxy/Chart.yaml"
Cohesion: 0.17
Nodes (11): apiVersion, appVersion, description, home, keywords, maintainers, name, name (+3 more)

### Community 290 - "weebo-si-operator/Chart.yaml"
Cohesion: 0.17
Nodes (11): apiVersion, appVersion, description, home, keywords, maintainers, name, name (+3 more)

### Community 291 - "enabled"
Cohesion: 0.17
Nodes (12): rbac, identity, argoNamespace, rbac, kubearmorPolicy, rbac, podSecurity, rbac (+4 more)

### Community 292 - "DomainError"
Cohesion: 0.05
Nodes (34): DomainError, InvalidConfiguration, NamespaceNotObserved, PortFailed, ReconcileFeature, Context, Feature, registry_preserves_declaration_order() (+26 more)

### Community 293 - "RFC 0020 — team tools"
Cohesion: 0.05
Nodes (41): Admission, Alternatives considered, Architecture, Before / after, Behaviour rules, BuildKit: the reference entry, Changelog, Contract (+33 more)

### Community 294 - "weebo-si-kubearmor-policy/src/application.rs"
Cohesion: 0.18
Nodes (35): a_second_enforce_pass_with_nothing_changed_reports_unchanged(), a_stale_object_of_the_same_workspace_is_still_deleted(), a_workspace_on_a_node_with_an_lsm_is_reported_enforced(), a_workspace_on_a_node_without_one_is_reported_not_enforced_not_absent(), a_workspace_reconcile_never_deletes_the_baseline_or_a_sibling_workspace_object(), a_workspace_with_no_scheduled_pod_is_unknown_rather_than_a_zero(), all_templates(), an_unresolved_baseline_template_holds_the_live_baseline_and_still_writes_the_posture() (+27 more)

### Community 295 - "RFC 0019 — devfile contract"
Cohesion: 0.05
Nodes (40): Alternatives considered, Annotations written (`Enforce` only), Architecture, Attributes and annotations read, Before / after, Behaviour rules, Changelog, Chassis: admission warnings (+32 more)

### Community 296 - "resourceQuotas"
Cohesion: 0.15
Nodes (13): limitRangeRef, quotaRef, resourceQuotas, name, namespace, name, namespace, catalog (+5 more)

### Community 297 - "labels"
Cohesion: 0.17
Nodes (11): che.eclipse.org/username, apiVersion, kind, app.kubernetes.io/component, app.kubernetes.io/part-of, hardening.weebo.io/workspace-namespace, weebo.io/team, metadata (+3 more)

### Community 298 - "spec"
Cohesion: 0.17
Nodes (11): apiVersion, kind, weebo.io/team, metadata, name, matchLabels, spec, displayName (+3 more)

### Community 299 - "RFC 0009 — endpoint-auth"
Cohesion: 0.17
Nodes (12): Alternatives considered, Changelog, Drawbacks and risks, Future work, Implementation plan, Motivation, Operational considerations, References (+4 more)

### Community 300 - "Runtime matrix"
Cohesion: 0.17
Nodes (12): Adding a runtime, Cluster: Pods, Cluster tier, kind, 2026-10-31, Cluster tier, other runtimes, 2026-11-01, In CI, Local: rootless podman, Local tier, 2026-10-31, Results (+4 more)

### Community 301 - "Seccomp profiles for workspace nodes"
Cohesion: 0.17
Nodes (12): Container runtimes, How it was measured, Installing on the nodes, Kubernetes, OpenShift, Running containers (Che's container-run mode), Seccomp profiles for workspace nodes, Talos (weebo-si) (+4 more)

### Community 302 - "nodes"
Cohesion: 0.17
Nodes (11): apiVersion, containerPath, hostPath, readOnly, kind, name, nodes, extraMounts (+3 more)

### Community 303 - "tests/team_tools.rs"
Cohesion: 0.11
Nodes (35): fail(), stays(), wait_until(), a_forged_tools_namespace_is_never_written(), a_phase_zero_tool_is_adopted_in_place(), a_renewed_client_certificate_is_used_without_a_restart(), a_requested_tool_renders_at_zero_scales_with_its_workspace_and_idles_after_grace(), an_ungranted_key_is_refused_under_deny_and_nothing_is_rendered() (+27 more)

### Community 304 - "bearer"
Cohesion: 0.18
Nodes (11): audiences, authorizedParties, foreign, introspection, serviceAccountToken, verifyOwnIssuer, bearer, enabled (+3 more)

### Community 305 - "networkPolicy"
Cohesion: 0.20
Nodes (11): namespaceSelector, podSelector, kubernetes.io/metadata.name, namespaceSelector, podSelector, matchLabels, networkPolicy, enabled (+3 more)

### Community 306 - "gateway"
Cohesion: 0.18
Nodes (11): gateway, allowedMiddlewares, clusterDomain, dialect, enforcement, externalUrl, haproxyPrerequisite, service (+3 more)

### Community 307 - "podSecurity"
Cohesion: 0.18
Nodes (11): podSecurity, namespaceSelection, namespaceSelection, annotation, namespaceSelection, backend, ceiling, default (+3 more)

### Community 308 - "spec"
Cohesion: 0.18
Nodes (10): apiVersion, kind, weebo.io/team, metadata, name, matchLabels, spec, displayName (+2 more)

### Community 309 - "che"
Cohesion: 0.18
Nodes (11): destination, mode, name, project, source, namespace, server, path (+3 more)

### Community 310 - "`image-policy`"
Cohesion: 0.18
Nodes (11): `image-policy`, Install checklist, Known limitations, Observability, Reading the logs, Rollback, Rollout, The upgrade that actually breaks this is Che's, not ours (+3 more)

### Community 311 - "`registry-config`"
Cohesion: 0.18
Nodes (11): A mounted change needs a workspace restart, Before you put a `Secret` in the catalogue, Install checklist, Known limitations, specific to this feature, Observability, Reading the logs, `registry-config`, Rollback (+3 more)

### Community 312 - "kind.yaml"
Cohesion: 0.18
Nodes (10): apiVersion, containerPath, hostPath, readOnly, kind, name, nodes, extraMounts (+2 more)

### Community 313 - "crate"
Cohesion: 0.18
Nodes (11): description, required, type, crate, path, on, workflow_call, description (+3 more)

### Community 314 - "e2e"
Cohesion: 0.18
Nodes (11): env, name, needs, runs-on, strategy, timeout-minutes, E2E_CA_FILE, E2E_REPO_ROOT (+3 more)

### Community 315 - "crate"
Cohesion: 0.18
Nodes (11): description, required, type, crate, path, on, workflow_call, description (+3 more)

### Community 316 - "contents"
Cohesion: 0.24
Nodes (11): permissions, name, needs, permissions, uses, permissions, helm, contents (+3 more)

### Community 317 - "dependencies"
Cohesion: 0.18
Nodes (11): lucide-react, react, react-dom, shiki, dependencies, fumadocs-ui@16.16.2, lucide-react@^1.24.0, react@^19.3.0 (+3 more)

### Community 318 - "kind-che.yaml"
Cohesion: 0.18
Nodes (10): apiVersion, containerPath, hostPath, readOnly, kind, name, nodes, extraMounts (+2 more)

### Community 319 - "RFC 0021 — namespace-only grants"
Cohesion: 0.05
Nodes (37): Alternatives considered, Annotations, Architecture, Before / after, Behaviour rules, Changelog, Contract, CRD fields (+29 more)

### Community 320 - "properties"
Cohesion: 0.20
Nodes (10): additionalProperties, properties, type, type, type, autoscaling, maxReplicas, minReplicas (+2 more)

### Community 321 - "properties"
Cohesion: 0.20
Nodes (10): additionalProperties, properties, type, type, type, cache, identityMaxEntries, identityTtlSecs (+2 more)

### Community 322 - "rules"
Cohesion: 0.20
Nodes (10): type, type, maxPerEndpoint, onUnknownKey, rejectUnnormalisedPath, rules, type, additionalProperties (+2 more)

### Community 323 - "controller"
Cohesion: 0.20
Nodes (10): controller, extraArgs, leaderElection, podAntiAffinity, podDisruptionBudget, replicaCount, enabled, maxUnavailable (+2 more)

### Community 324 - "endpointAuth"
Cohesion: 0.33
Nodes (6): endpointAuth, dialect, failurePolicy, namespaceLabel, key, value

### Community 325 - "restricted.rs"
Cohesion: 0.12
Nodes (18): a_forgotten_object_reports_once_more(), a_retained_object_is_remembered_and_a_dropped_one_reports_again(), AnnotationChanges, keys(), namespace(), objects_without_a_restricted_key_are_not_remembered(), only_an_annotation_change_requeues_the_namespaces_workspaces(), reporter() (+10 more)

### Community 327 - "TemplateRef"
Cohesion: 0.09
Nodes (27): TemplateRef, copy_name(), RegistryConfigViolation, CatalogKeyConflict, DuplicateCopyName, DuplicateRegistryKey, EntryHasDuplicateSource, EntryHasNoSources (+19 more)

### Community 328 - "defaultPosture"
Cohesion: 0.20
Nodes (10): enabled, intervalSeconds, capabilities, file, network, backend, canary, defaultPosture (+2 more)

### Community 329 - "key"
Cohesion: 0.25
Nodes (8): anonymous, delegation, key, patterns, variants, catalog, catalog, catalog

### Community 330 - "dwocPin"
Cohesion: 0.20
Nodes (10): name, namespace, catalog, default, mode, namespaceSelection, namespaceSelector, onMissingTarget (+2 more)

### Community 331 - "cheUser"
Cohesion: 0.20
Nodes (10): server, setupApply, access, email, teamLabel, username, values, batlehub (+2 more)

### Community 332 - "How `weebo-si-operator` works inside"
Cohesion: 0.20
Nodes (10): A reconcile, end to end, Adding a feature, An admission request, end to end, Configuration: one singleton, hot-reloaded, Features: the two shapes, How `weebo-si-operator` works inside, Observability, One binary, two roles (+2 more)

### Community 333 - "`preauth-proxy`"
Cohesion: 0.20
Nodes (10): Behaviour, Configuration, Deploying, Exit codes, Failure modes, Known limitations, `preauth-proxy`, Reading the logs (+2 more)

### Community 334 - "`weebo-si-operator`"
Cohesion: 0.18
Nodes (11): Chart values, Events, Install, Known limitations, Observability, Reading the logs, Rollback, Rollout (+3 more)

### Community 335 - "binary"
Cohesion: 0.22
Nodes (9): name, permissions, runs-on, timeout-minutes, jobs, binary, name, permissions (+1 more)

### Community 336 - "steps"
Cohesion: 0.22
Nodes (10): steps, CC_x86_64_unknown_linux_musl, CRATE, CRATE_PATH, steps, env, if, name (+2 more)

### Community 337 - "images"
Cohesion: 0.20
Nodes (10): name, path, name, runs-on, strategy, timeout-minutes, images, brick (+2 more)

### Community 338 - "suite"
Cohesion: 0.20
Nodes (10): suite, on, schedule, workflow_dispatch, cron, default, description, options (+2 more)

### Community 339 - "steps"
Cohesion: 0.27
Nodes (10): CRATE, OWNER, REF, steps, steps, env, id, name (+2 more)

### Community 340 - "proxy.ts"
Cohesion: 0.20
Nodes (7): fumadocs-core, fumadocs-mdx, fumadocs-core@16.16.2, fumadocs-mdx@15.4.6, { rewrite: rewriteDocs }, { rewrite: rewriteSuffix }, docs

### Community 341 - "t6-probe.sh"
Cohesion: 0.44
Nodes (7): case_result(), die(), host_of(), pod(), say(), secret(), t6-probe.sh script

### Community 343 - "imagePolicy"
Cohesion: 0.25
Nodes (8): imagePolicy, default, mode, onNotGranted, platform, variables, builtin, extra

### Community 344 - "features"
Cohesion: 0.22
Nodes (8): networkProfiles, policyGuard, registryConfig, mode, mode, mode, spec, features

### Community 345 - "catalog"
Cohesion: 0.22
Nodes (9): limitRangeRef, quotaRef, resourceQuotas, name, namespace, name, namespace, catalog (+1 more)

### Community 346 - "features"
Cohesion: 0.20
Nodes (10): default, default, dwocPin, endpointAuth, imagePolicy, podSecurity, default, level (+2 more)

### Community 347 - "key"
Cohesion: 0.22
Nodes (9): key, patterns, variants, imagePolicy, networkProfiles, catalog, default, catalog (+1 more)

### Community 348 - "Hexagonal architecture"
Cohesion: 0.22
Nodes (9): Enforcement, Hexagonal architecture, Layout, Ports live in the domain, in domain vocabulary, Testing expectation, The composition root, The dependency rule, When to apply it (+1 more)

### Community 349 - "weebo-si-hardening"
Cohesion: 0.40
Nodes (5): Conventions, Getting started, How work happens here, weebo-si-hardening, What lives here

### Community 350 - "`kubearmor-policy`"
Cohesion: 0.22
Nodes (9): Install checklist, Known limitations, specific to this feature, `kubearmor-policy`, Observability, Reading the logs, Rollback, Rollout, What gets written (+1 more)

### Community 351 - "`pod-security`"
Cohesion: 0.22
Nodes (9): Install checklist, Known limitations, specific to this feature, Observability, OpenShift, `pod-security`, Reading the logs, Rollback, Rollout (+1 more)

### Community 352 - "`resource-quotas`"
Cohesion: 0.22
Nodes (9): Install checklist, Known limitations, specific to this feature, Observability, Reading the logs, `resource-quotas`, Rollback, Rollout, What a profile must satisfy (+1 more)

### Community 353 - "Cleanup"
Cohesion: 0.16
Nodes (11): apply(), Cleanup, delete(), Namespace, team(), payments_team(), payments_team_with(), no_rpm_team() (+3 more)

### Community 354 - "workflows/e2e.yaml"
Cohesion: 0.22
Nodes (8): concurrency, cancel-in-progress, group, env, KIND_SHA256, KIND_VERSION, name, permissions

### Community 355 - "[[...slug]]/page.tsx"
Cohesion: 0.28
Nodes (5): docsPage, getMDXComponents(), MDXProvidedComponents, useMDXComponents, CHOICES

### Community 356 - "seccomp-profiles.sh"
Cohesion: 0.42
Nodes (8): build_profile(), file_entry(), generate(), machineconfig(), override(), resolve(), seccomp-profiles.sh script, talos_patch()

### Community 357 - "tasks"
Cohesion: 0.22
Nodes (8): cmds, desc, cmds, desc, tasks, check, gen, version

### Community 358 - "tasks"
Cohesion: 0.22
Nodes (8): cmds, desc, cmds, desc, tasks, lock:gen, lock:update, version

### Community 359 - "tasks"
Cohesion: 0.22
Nodes (8): cmds, desc, cmds, desc, tasks, check, gen, version

### Community 360 - "Cidr"
Cohesion: 0.36
Nodes (3): Cidr, String, trusted_proxy_networks_are_matched_as_networks_and_not_as_strings()

### Community 361 - "errorPage"
Cohesion: 0.25
Nodes (8): errorPage, enabled, query, service, service, name, port, trafficDistribution

### Community 362 - "ingress"
Cohesion: 0.25
Nodes (8): ingress, annotations, className, enabled, host, tls, enabled, secretName

### Community 363 - "rateLimit"
Cohesion: 0.25
Nodes (8): type, type, backchannelLogoutPerMinute, loginPerAddressPerMinute, rateLimit, additionalProperties, properties, type

### Community 364 - "claims"
Cohesion: 0.25
Nodes (8): additionalProperties, properties, type, type, claims, groups, username, type

### Community 365 - "revalidation"
Cohesion: 0.25
Nodes (8): type, type, intervalSecs, mode, revalidation, additionalProperties, properties, type

### Community 366 - "rollingUpdate"
Cohesion: 0.25
Nodes (8): type, type, maxSurge, maxUnavailable, rollingUpdate, additionalProperties, properties, type

### Community 369 - "RFC 0018 — workspace pod identity"
Cohesion: 0.06
Nodes (35): Alternatives considered, Architecture, Before / after, Changelog, Contract, Data and privacy, Data and state, Design (+27 more)

### Community 370 - "registryConfig"
Cohesion: 0.25
Nodes (8): ecosystem, sources, registryConfig, catalog, mode, namespaceSelection, namespaceSelector, onNotGranted

### Community 371 - "kubearmorPolicy"
Cohesion: 0.22
Nodes (9): templateRef, kubearmorPolicy, baseline, catalog, mode, namespaceSelector, onNotGranted, name (+1 more)

### Community 372 - "matchLabels"
Cohesion: 0.15
Nodes (13): imageRewrite, policyGuard, mode, namespaceSelector, rules, hardening.weebo.io/workspace-namespace, matchLabels, namespaceSelector (+5 more)

### Community 373 - "key"
Cohesion: 0.22
Nodes (9): anonymous, delegation, key, name, namespace, patterns, catalog, catalog (+1 more)

### Community 374 - "`network-profiles` and `policy-guard`"
Cohesion: 0.25
Nodes (8): Install checklist, Known limitations, `network-profiles` and `policy-guard`, Observability, Reading the logs, Rollback, Rollout, The enforcement canary

### Community 375 - "Request cost"
Cohesion: 0.25
Nodes (8): Cache the identity, never the verdict, Capacity, in numbers rather than adjectives, Compile at write time, not at read time, Request cost, The invariant: no I/O on the request path, What is configured, and what is measured, Where the milliseconds actually are, Why not Valkey

### Community 376 - "RFC process"
Cohesion: 0.25
Nodes (8): Checking a RFC, Index, Language, Life of an RFC, Numbering and naming, RFC process, Statuses, When is an RFC required

### Community 377 - "steps"
Cohesion: 0.43
Nodes (8): steps, steps, if, name, run, uses, steps, steps

### Community 378 - "sign"
Cohesion: 0.25
Nodes (7): jobs, sign, name, name, needs, runs-on, timeout-minutes

### Community 379 - "images"
Cohesion: 0.29
Nodes (8): with, name, needs, uses, with, images, crate, path

### Community 380 - "with"
Cohesion: 0.25
Nodes (8): with, args, command, fetch-depth, password, registry, username, version

### Community 381 - ".markdownlint.yaml"
Cohesion: 0.25
Nodes (7): default, MD013, MD024, siblings_only, MD025, front_matter_title, MD036

### Community 382 - "app/layout.tsx"
Cohesion: 0.25
Nodes (5): next, next@16.4.1, jetbrainsMono, metadata, silkscreen

### Community 383 - "scripts"
Cohesion: 0.25
Nodes (8): scripts, build, dev, gen:crds, lint, postinstall, start, types:check

### Community 384 - "weebo-si-pod-identity/src/lib.rs"
Cohesion: 0.14
Nodes (13): container(), Admission, Create, EphemeralUpdate, ContainerIdentity, ContainerKind, Container, Ephemeral (+5 more)

### Community 385 - "compute_diff"
Cohesion: 0.29
Nodes (15): compute_diff(), Create, Unchanged, Update, a_listed_uid_alone_does_not_rewrite_the_object(), a_live_object_already_carrying_its_owner_is_unchanged(), a_live_object_lacking_its_owner_is_updated_so_it_is_adopted(), a_live_object_owned_by_a_different_uid_is_updated() (+7 more)

### Community 386 - "secrets"
Cohesion: 0.29
Nodes (7): existingSecret, key, secrets, clientSecret, sessionKeys, existingSecret, key

### Community 387 - "certificates"
Cohesion: 0.29
Nodes (7): certificates, certManager, provider, secretName, issuerRef, kind, name

### Community 388 - "serviceAccount"
Cohesion: 0.29
Nodes (7): create, name, serviceAccount, controller, webhook, create, name

### Community 389 - "requests"
Cohesion: 0.33
Nodes (7): resources, memory, cpu, memory, limits, requests, resources

### Community 390 - "set_features"
Cohesion: 0.13
Nodes (35): operator_pods(), set_features(), text(), a_group_outside_the_allow_list_refuses_the_whole_person_and_writes_nothing(), a_person_becomes_a_real_authentik_account_in_their_teams_groups_and_leaves_with_their_object(), a_persons_workspace_application_is_synced_by_argo_cd_with_their_own_values(), a_second_person_claiming_a_taken_username_is_in_conflict(), an_account_somebody_else_made_is_adopted_and_never_written() (+27 more)

### Community 391 - "cspell.json"
Cohesion: 0.29
Nodes (6): ignorePaths, ignoreWords, language, $schema, version, words

### Community 392 - "networkProfiles"
Cohesion: 0.22
Nodes (9): networkProfiles, workspaceSelection, workspaceSelection, baseline, mode, namespaceSelector, onNotGranted, workspaceSelection (+1 more)

### Community 393 - "features"
Cohesion: 0.29
Nodes (6): podSecurity, resourceQuotas, mode, mode, spec, features

### Community 394 - "endpointAuth"
Cohesion: 0.29
Nodes (6): gateway, mode, endpointAuth, enforcement, spec, features

### Community 395 - "Guide-level explanation"
Cohesion: 0.29
Nodes (7): An endpoint you wrote yourself, Calling your own endpoint from your own workspace, Guide-level explanation, Two ways in, and which one takes effect when, What everyone sees, What the admin installs, What the developer writes

### Community 396 - "che-user/Chart.yaml"
Cohesion: 0.29
Nodes (6): apiVersion, appVersion, description, name, type, version

### Community 397 - "push"
Cohesion: 0.29
Nodes (7): push, digest, image, name, outputs, runs-on, timeout-minutes

### Community 398 - "charts"
Cohesion: 0.29
Nodes (7): name, needs, outputs, runs-on, timeout-minutes, charts, refs

### Community 399 - "verify"
Cohesion: 0.29
Nodes (7): verify, prerelease, version, name, outputs, runs-on, timeout-minutes

### Community 400 - "identity_violations"
Cohesion: 0.26
Nodes (15): each_refusal_reason_has_its_message(), identity_violations(), out_of_range(), pod_level_ids_above_65535_are_refused(), Violation, EphemeralOnHostUserns, FsGroupZero, GidUnset (+7 more)

### Community 401 - "session"
Cohesion: 0.33
Nodes (6): session, grantTtlSecs, hostSliding, hostTtlSecs, maxGroups, ssoTtlSecs

### Community 402 - "resources"
Cohesion: 0.33
Nodes (6): memory, cpu, memory, resources, limits, requests

### Community 403 - "quantity.rs"
Cohesion: 0.21
Nodes (10): binary_suffixes(), decimal_suffixes(), display(), exponents_and_fractions(), NANO_PER_UNIT, per_mille(), pow10(), q() (+2 more)

### Community 404 - "gateway"
Cohesion: 0.33
Nodes (5): gateway, endpointAuth, enforcement, spec, features

### Community 405 - "templateRef"
Cohesion: 0.33
Nodes (6): templateRef, kubearmorPolicy, catalog, default, name, namespace

### Community 406 - "devfile.yaml"
Cohesion: 0.33
Nodes (5): metadata, name, parent, uri, schemaVersion

### Community 407 - "catalog"
Cohesion: 0.40
Nodes (5): anonymous, delegation, catalog, default, endpointAuth

### Community 408 - "che-user/values.yaml"
Cohesion: 0.33
Nodes (5): email, storage, size, team, username

### Community 409 - "image"
Cohesion: 0.33
Nodes (6): name, permissions, runs-on, timeout-minutes, image, security-events

### Community 410 - "permissions"
Cohesion: 0.40
Nodes (6): permissions, contents, id-token, packages, permissions, permissions

### Community 411 - "release"
Cohesion: 0.33
Nodes (6): release, name, needs, permissions, runs-on, timeout-minutes

### Community 412 - "runtime-matrix-k8s.sh"
Cohesion: 0.73
Nodes (5): expected(), pod_failure(), pod_yaml(), preflight(), runtime-matrix-k8s.sh script

### Community 413 - "weebosiuser.mdx"
Cohesion: 0.33
Nodes (5): Build a manifest, Example, `spec.authentik` [#spec.authentik], `spec.che` [#spec.che], Spec fields

### Community 414 - "lint"
Cohesion: 0.33
Nodes (5): cmds, desc, tasks, lint, version

### Community 415 - "lint"
Cohesion: 0.33
Nodes (5): cmds, desc, tasks, lint, version

### Community 416 - "image"
Cohesion: 0.40
Nodes (5): image, digest, pullPolicy, repository, tag

### Community 417 - "networkProfiles"
Cohesion: 0.40
Nodes (5): image, enabled, networkProfiles, canary, cilium

### Community 418 - "image"
Cohesion: 0.40
Nodes (5): image, digest, pullPolicy, repository, tag

### Community 419 - "teamTools"
Cohesion: 0.20
Nodes (11): certManagerUsername, enabled, resourceQuotas, rbac, templateNamespace, teamTools, caGuard, rbac (+3 more)

### Community 420 - "dwocPin"
Cohesion: 0.40
Nodes (4): mode, dwocPin, spec, features

### Community 421 - "imagePolicy"
Cohesion: 0.29
Nodes (6): imagePolicy, imageRewrite, mode, mode, spec, features

### Community 422 - "kubearmorPolicy"
Cohesion: 0.40
Nodes (4): kubearmorPolicy, mode, spec, features

### Community 423 - "identity"
Cohesion: 0.40
Nodes (4): identity, mode, spec, features

### Community 424 - "syncPolicy"
Cohesion: 0.40
Nodes (5): prune, selfHeal, syncPolicy, automated, options

### Community 425 - "catalog"
Cohesion: 0.40
Nodes (5): ecosystem, sources, registryConfig, catalog, default

### Community 426 - "catalog"
Cohesion: 0.40
Nodes (5): ecosystem, sources, registryConfig, catalog, default

### Community 427 - "tests/pod_identity.rs"
Cohesion: 0.11
Nodes (30): kubectl(), must(), repo_root(), preauth_proxy_logs_in_once_injects_the_credential_and_renews_it_on_a_401(), a_managed_kubearmor_policy_is_guarded_like_a_network_policy(), a_volume_from_before_enforce_keeps_its_owner_and_the_cleanup_job_is_rewritten(), counter(), dry_run() (+22 more)

### Community 428 - "envtest"
Cohesion: 0.40
Nodes (5): name, needs, permissions, uses, envtest

### Community 429 - "sign-charts"
Cohesion: 0.40
Nodes (5): sign-charts, name, needs, runs-on, timeout-minutes

### Community 430 - "test"
Cohesion: 0.40
Nodes (5): test, name, needs, permissions, uses

### Community 431 - "spike-0009-rig.sh"
Cohesion: 0.70
Nodes (4): down(), prerequisite(), spike-0009-rig.sh script, up()

### Community 432 - "cache"
Cohesion: 0.50
Nodes (4): identityMaxEntries, identityTtlSecs, tokenReviewMaxEntries, cache

### Community 433 - "extraCa"
Cohesion: 0.50
Nodes (4): extraCa, configMap, key, secret

### Community 435 - "networkProfiles"
Cohesion: 0.50
Nodes (4): variants, networkProfiles, catalog, default

### Community 436 - "Design"
Cohesion: 0.50
Nodes (4): Architecture, Data and state, Design, Developer continuity

### Community 437 - "runtime-matrix.sh"
Cohesion: 0.83
Nodes (3): expected(), resolve_runtime(), runtime-matrix.sh script

### Community 438 - "claims"
Cohesion: 0.67
Nodes (3): groups, username, claims

### Community 439 - "hosts"
Cohesion: 0.67
Nodes (3): hosts, exclude, suffix

### Community 441 - "Documentation"
Cohesion: 0.67
Nodes (3): Documentation, Map, Reading order for a newcomer

### Community 442 - "Unresolved questions"
Cohesion: 0.67
Nodes (3): Resolved, Still open, Unresolved questions

### Community 484 - "config"
Cohesion: 0.26
Nodes (14): a_stripped_annotation_is_put_back_on_the_next_pass(), an_object_that_already_agrees_is_left_alone(), attached(), break_glass_survives_the_sweep_rather_than_being_quietly_undone(), config(), off_leaves_a_chain_on_an_object_this_feature_never_gated(), off_on_an_object_that_was_never_gated_does_nothing(), off_strips_the_dialects_keys_and_never_the_developers() (+6 more)

### Community 485 - "streamext"
Cohesion: 0.29
Nodes (5): drive(), drive_consumes_every_item_and_survives_errors(), HEALTH, report(), report_to()

### Community 486 - "teardown.rs"
Cohesion: 0.33
Nodes (8): CONTROLLER_MANAGER, GARBAGE_COLLECTOR, is_teardown_identity(), nobody_else_is_let_through(), TEARDOWN_IDENTITIES, teardown_may(), the_garbage_collector_may_orphan_as_well_as_delete(), the_namespace_controller_may_delete_but_never_update()

### Community 487 - "weebo-si-pod-identity/src/feature.rs"
Cohesion: 0.18
Nodes (18): a_pod_the_mutation_would_fix_is_refused_as_fixable(), both_halves_share_one_feature_id(), exempt_dwoc_key_is_untouched(), FEATURE_ID, granted_group_zero_is_logged_as_such(), Harness, harness(), no_config_is_an_error_not_an_allow() (+10 more)

### Community 488 - "kubearmor_policy_store.rs"
Cohesion: 0.08
Nodes (22): PodSelector, DevWorkspaceId, Empty, a_listed_object_carries_its_uid_into_the_delete_precondition(), a_profile_object_round_trips_its_owner_through_what_this_adapter_writes(), a_selector_round_trips_through_the_shape_this_adapter_writes_and_reads_back(), a_workspace_selector_names_the_devworkspace_id_label(), an_object_with_no_selector_at_all_reads_back_as_the_baseline_selector() (+14 more)

### Community 489 - "src/workspace_gate.rs"
Cohesion: 0.12
Nodes (38): TeamTeamTools, config(), config_with(), grant(), keys(), team(), a_key_the_crd_could_not_admit_is_never_echoed(), a_namespace_with_no_team_gets_no_tool_ever() (+30 more)

### Community 490 - "ResourceQuotasFeature"
Cohesion: 0.11
Nodes (13): NamespaceSubject, ResourceQuotasFeature, ProfileViolation, DefaultsOutOfOrder, InvalidQuantity, NoContainerDefault, OutsideTemplateNamespace, ScopedQuota (+5 more)

### Community 491 - "names"
Cohesion: 0.09
Nodes (26): apiVersion, kind, metadata, spec, apiVersion, kind, metadata, spec (+18 more)

### Community 492 - "weebo-si-team-tools/src/lib.rs"
Cohesion: 0.08
Nodes (38): ToolEntry, ToolService, ToolTls, ToolWorkload, WorkloadKind, Deployment, StatefulSet, a_forbidden_write_is_its_own_reason() (+30 more)

### Community 494 - "team_tools_ca_envtest.rs"
Cohesion: 0.17
Nodes (19): ALICE_TOKEN, apply_all(), CERT_MANAGER, CERT_MANAGER_CRDS, CERT_MANAGER_TOKEN, certificate(), certificate_requests(), certificates() (+11 more)

### Community 495 - "webhook_cmd.rs"
Cohesion: 0.11
Nodes (9): DEFAULT_HOLDER_ID, DEFAULT_LEASE_NAMESPACE, LEASE_NAME, reconcile(), run(), DRAIN_DELAY, MAX_REVIEW_BYTES, run() (+1 more)

### Community 496 - "weebo-si-network-profiles/src/model/diff.rs"
Cohesion: 0.29
Nodes (12): a_listed_uid_alone_does_not_rewrite_the_object(), a_live_object_already_carrying_its_owner_is_unchanged(), a_live_object_lacking_its_owner_is_updated_so_it_is_adopted(), a_live_object_owned_by_a_different_uid_is_updated(), a_renamed_profile_key_alone_does_not_rewrite_the_object(), desired_state_objects_leaves_every_provenance_field_empty(), object(), owner() (+4 more)

### Community 497 - "scale.rs"
Cohesion: 0.11
Nodes (17): Clock, FakeClock, a_lost_timer_rearms_and_a_backwards_clock_never_scales_down_early(), a_requester_scales_up(), a_returning_requester_cancels_the_grace(), a_stopped_requester_keeps_it_rendered_at_zero(), a_zero_grace_scales_down_at_once(), decide() (+9 more)

### Community 498 - "status.rs"
Cohesion: 0.37
Nodes (10): an_unchanged_status_keeps_its_transition_time(), condition(), CONDITION, identitys_condition_is_kept_and_ours_replaced(), merge_conditions(), no_block_removes_only_our_condition(), now(), TeamReport (+2 more)

### Community 499 - "Posture"
Cohesion: 0.18
Nodes (4): Posture, Audit, Block, there_is_no_process_posture_because_kubearmor_has_none()

### Community 500 - "Foreign"
Cohesion: 0.22
Nodes (8): BearerConfig, BearerMode, default_introspection_rate(), default_negative_ttl(), Foreign, Passthrough, Reject, IntrospectionConfig

### Community 501 - "compile_annotations"
Cohesion: 0.25
Nodes (10): admission_compiles_with_the_namespace_grant(), alice(), an_unusable_rule_list_is_refused_at_admission_with_the_reason(), annotations_that_are_fine_are_not_an_opinion(), compile_annotations(), compile_error(), NamespaceInputs, UnknownKey (+2 more)

### Community 503 - "Verdict"
Cohesion: 0.25
Nodes (5): Verdict, Applied, Differs, Extra, Missing

### Community 505 - "TrustedProxy"
Cohesion: 0.20
Nodes (9): default_client_ip_header(), PodNetwork, Auto, Off, On, SelfOriginConfig, TrustedProxy, Any (+1 more)

### Community 507 - "WeeboSiTeam"
Cohesion: 0.06
Nodes (39): allow_listed(), IdentityConfigViolation, DuplicateUsername, EmailRequired, GroupRefNotAllowed, ProjectNotAllowed, RenderFailed, RepoUrlNotAllowed (+31 more)

### Community 508 - "`team-tools`"
Cohesion: 0.12
Nodes (16): Add a team tools namespace, CA guard, Configure it, Failure modes, How it works, Install checklist, Observability, Open points (+8 more)

### Community 509 - "weebo-si-controller/src/reconcile.rs"
Cohesion: 0.07
Nodes (24): ControllerShared, run(), TeamToolsReport, an_invalid_rule_set_is_degraded_and_reaches_the_conditions(), Ctx, degraded_status(), Error, error_policy() (+16 more)

### Community 510 - "weebo-si-team-tools-adapters/src/metrics.rs"
Cohesion: 0.25
Nodes (5): a_tool_no_longer_seen_loses_its_series(), gauges(), RESULTS, TeamToolsMetrics, ToolGauges

### Community 511 - "Field"
Cohesion: 0.20
Nodes (8): Field, FsGroup, FsGroupChangePolicy, HostUsers, RunAsGroup, RunAsNonRoot, RunAsUser, SupplementalGroupsPolicy

### Community 512 - "`pod-identity`"
Cohesion: 0.20
Nodes (10): Configure it, Failure modes, Install checklist, My sidecar now gets "Permission denied", Observability, `pod-identity`, Refusals and their fixes, Rollback (+2 more)

### Community 514 - "flag"
Cohesion: 0.67
Nodes (6): argv(), flag(), flag_does_not_match_a_longer_flag_sharing_its_prefix(), flag_is_none_when_absent_or_valueless(), flag_reads_the_equals_form_the_chart_renders(), flag_reads_the_space_separated_form()

### Community 515 - "`image-rewrite`"
Cohesion: 0.20
Nodes (10): Configure it, GitOps, How it works, `image-rewrite`, Moving a mirror, Operate it, Private upstream images, Roll it out (+2 more)

### Community 517 - "Restricted keys and namespace grants"
Cohesion: 0.20
Nodes (10): Grant it to a namespace, Mark a key restricted, Not implemented, Restricted keys and namespace grants, Rollback, Rollout, Timing, What happens (+2 more)

### Community 518 - "CI"
Cohesion: 0.22
Nodes (9): CI, End to end, Known gaps, Per-brick builds, Releases, Report first, gate second, Running the gates locally, Two things CI does that the pre-commit hook cannot (+1 more)

### Community 520 - "weebo-si-operator: the controller's resource budget"
Cohesion: 0.22
Nodes (9): 2026-10-31, release build, laptop, 500 namespaces, 2026-11-12, release build, laptop, image admission (RFC 0017), 2026-11-25, release build, laptop, devfile-contract (RFC 0019), 2026-11-25, release build, laptop, pod-identity (RFC 0018), How it is measured, The budget, weebo-si-operator: the controller's resource budget, What the budget found (+1 more)

### Community 521 - "PodSubject"
Cohesion: 0.17
Nodes (11): metrics(), mode_label(), pod(), PodIdentityMetrics, refusals_carry_mode_reason_and_fixability(), rewrites_are_counted_per_field_and_nothing_for_unchanged(), series(), Judged (+3 more)

### Community 522 - "`passwd-append`"
Cohesion: 0.22
Nodes (9): Adopting it, Case 1 — an entrypoint you do not own (che-code, `WeeboDevImage`), Case 2 — an entrypoint you do own, Exit codes, `passwd-append`, Reading the logs, Things it will not do, Usage (+1 more)

### Community 525 - "Fake"
Cohesion: 0.20
Nodes (4): Fake, FakeBackend, One, Two

### Community 528 - "weebo-si-endpoint-auth-adapters/src/lib.rs"
Cohesion: 0.22
Nodes (7): endpoint_auth_router(), MUTATE_INGRESSES_PATH, MUTATE_ROUTES_PATH, VALIDATE_INGRESSES_PATH, VALIDATE_ROUTES_PATH, admission_routes(), controller_deps()

### Community 529 - "Managed"
Cohesion: 0.15
Nodes (3): Managed, Selected, ManagedObject

### Community 530 - "`devfile-contract`"
Cohesion: 0.25
Nodes (8): Configure it, `devfile-contract`, Failure modes, How it works, Operate it, Roll it out, The denied list, What a developer sees

### Community 531 - "Mutation"
Cohesion: 0.25
Nodes (6): Mutation, Annotate, SetBool, SetConfigRef, SetInt, SetString

### Community 532 - "Value"
Cohesion: 0.29
Nodes (4): Value, Bool, Int, Str

### Community 533 - "endpoint-auth: what the gate costs, and what to do about it"
Cohesion: 0.40
Nodes (5): endpoint-auth: what the gate costs, and what to do about it, How it is measured, Improvements, What was measured (2026-10-01, release build, loopback), Where the time goes

### Community 534 - "Repository layout"
Cohesion: 0.50
Nodes (4): `bins/` or `crates/`?, Naming, Repository layout, Shared configuration

### Community 556 - "ConfigError"
Cohesion: 0.33
Nodes (4): ConfigError, Invalid, Unparseable, Unreadable

### Community 557 - "RevalidationMode"
Cohesion: 0.29
Nodes (6): default_revalidation(), RevalidationConfig, RevalidationMode, Always, Never, WhenNoBackchannel

### Community 558 - "OnUnknownKey"
Cohesion: 0.33
Nodes (5): default_max_rules(), OnUnknownKey, Default, Deny, RulesConfig

### Community 559 - "RoutingKind"
Cohesion: 0.33
Nodes (3): RoutingKind, Ingress, Route

## Knowledge Gaps
- **532 isolated node(s):** `Proxy<S, U>`, `Delete`, `One`, `Two`, `DevWorkspaceId` (+527 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 4591 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **83 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `NamespaceName` connect `NamespaceName` to `weebo-si-pod-identity/src/lib.rs`, `feature/registry_config.rs`, `team_tools_envtest.rs`, `PodSubject`, `config_store.rs`, `variable.rs`, `weebo-si-team-tools-adapters/src/controller.rs`, `TemplateRef`, `kube_policy_store.rs`, `workspace_images.rs`, `weebo-si-resource-quotas-adapters/src/controller.rs`, `weebo-si-endpoint-auth-adapters/src/endpoint_auth.rs`, `weebo-si-team-tools/src/validate.rs`, `weebo-si-resource-quotas/src/application.rs`, `weebo-si-kubearmor-policy-adapters/src/controller.rs`, `Applied`, `ManagedObject`, `DomainError`, `weebo-si-policy-guard-adapters/src/policy_guard.rs`, `weebo-si-crd/src/lib.rs`, `weebo-si-endpoint-auth-adapters/src/controller.rs`, `src/network_profiles.rs`, `core.rs`, `weebo-si-kubearmor-policy/src/application.rs`, `arc`, `pod_security_metrics.rs`, `guard.rs`, `weebo-si-resource-quotas/src/lib.rs`, `FeatureId`, `weebo-si-team-tools/src/render.rs`, `objects.rs`, `registry_object_store.rs`, `weebo-si-network-profiles/src/application.rs`, `router.rs`, `webhook_cmd.rs`, `weebo-si-pod-security/src/lib.rs`, `feature.rs`, `perf_envtest.rs`, `endpoint_routing.rs`, `weebo-si-registry-config-adapters/src/controller.rs`, `quota_metrics.rs`, `TemplateRef`, `feature/image_rewrite.rs`, `images_cmd.rs`, `Team`, `image_metrics.rs`, `feature/kubearmor_policy.rs`, `weebo-si-pod-security-adapters/src/controller.rs`, `weebo-si-team-tools-adapters/src/reconcile.rs`, `registry_metrics.rs`, `RuntimeBackend`, `node_enforcer.rs`, `weebo-si-team-tools/src/feature.rs`, `weebo-si-registry-config/src/application.rs`, `feature/network_profiles.rs`, `kubearmor_policy_store.rs`, `src/workspace_gate.rs`, `kubearmor_metrics.rs`, `ResourceQuotasFeature`, `weebo-si-team-tools/src/lib.rs`, `admit.rs`, `scale.rs`, `weebo-si-pod-security/src/application.rs`, `compile_annotations`, `weebo-si-network-profiles-adapters/src/controller.rs`, `feature/workspace_gate.rs`, `feature/pod_security.rs`, `Subject`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **What connects `Proxy<S, U>`, `Delete`, `One` to the rest of the system?**
  _532 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Host` be split into smaller, more focused modules?**
  _Cohesion score 0.05974025974025974 - nodes in this community are weakly interconnected._
- **Why does `DomainError` connect `DomainError` to `scope.rs`, `feature/registry_config.rs`, `weebo-si-identity/src/application.rs`, `kube_policy_store.rs`, `workspace_images.rs`, `weebo-si-endpoint-auth-adapters/src/endpoint_auth.rs`, `weebo-si-resource-quotas/src/application.rs`, `weebo-si-kubearmor-policy-adapters/src/controller.rs`, `Applied`, `NamespaceName`, `ManagedObject`, `weebo-si-kubearmor-policy/src/application.rs`, `guard.rs`, `core.rs`, `pod_security_metrics.rs`, `weebo-si-resource-quotas/src/lib.rs`, `registry_object_store.rs`, `weebo-si-network-profiles/src/application.rs`, `router.rs`, `kube_provisioner.rs`, `kube_canary.rs`, `weebo-si-pod-security/src/lib.rs`, `feature.rs`, `endpoint_routing.rs`, `feature/image_rewrite.rs`, `TemplateRef`, `feature/kubearmor_policy.rs`, `weebo-si-team-tools-adapters/src/reconcile.rs`, `weebo-si-crd/tests/envtest.rs`, `weebo-si-devfile-contract/src/feature.rs`, `weebo-si-team-tools/src/feature.rs`, `feature/network_profiles.rs`, `kubearmor_policy_store.rs`, `kubearmor_metrics.rs`, `weebo-si-pod-identity/src/feature.rs`, `ResourceQuotasFeature`, `src/workspace_gate.rs`, `admit.rs`, `weebo-si-pod-security/src/application.rs`, `feature/workspace_gate.rs`, `Subject`, `weebo-si-registry-config/src/application.rs`, `feature/pod_security.rs`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Should `kube_workload.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.04553264604810996 - nodes in this community are weakly interconnected._
- **Why does `RuntimeBackend` connect `RuntimeBackend` to `compute_diff`, `kubearmor_metrics.rs`, `weebo-si-crd/src/lib.rs`, `weebo-si-kubearmor-policy/src/application.rs`, `kubearmor_policy_store.rs`, `kubearmor_metrics.rs`, `config_store.rs`, `kubearmor_envtest.rs`, `DesiredState`, `controller_envtest.rs`, `Posture`, `src/kubearmor_policy.rs`, `feature/kubearmor_policy.rs`, `weebo-si-crd/tests/envtest.rs`, `weebo-si-controller/src/reconcile.rs`?**
  _High betweenness centrality (0.012) - this node is a cross-community bridge._
- **Should `weebo-si-endpoint-auth/src/application.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.04819848293299621 - nodes in this community are weakly interconnected._