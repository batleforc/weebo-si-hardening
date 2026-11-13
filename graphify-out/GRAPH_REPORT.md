# Graph Report - tooling  (2026-11-13)

## Corpus Check
- 555 files · ~722,051 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 25 file(s) not represented in the graph (top: (none) 14, .toml 6, .tpl 3)

## Summary
- 11553 nodes · 27236 edges · 528 communities (445 shown, 83 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 1375 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `03a43fd0`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- compute_diff
- kube_catalog.rs
- fake_apiserver
- weebo-si-endpoint-auth/src/application.rs
- http.rs
- inbound_http.rs
- weebo-si-identity/src/application.rs
- src/validate.rs
- EndpointAuthConfigViolation
- kube_catalog.rs
- config_store.rs
- TeamName
- weebo-si-crd/src/endpoint_auth.rs
- oidc.rs
- pattern.rs
- TemplateRef
- kube_policy_store.rs
- Spec fields
- weebo-si-resource-quotas-adapters/src/controller.rs
- weebo-si-endpoint-auth-adapters/src/endpoint_auth.rs
- conformance.rs
- pod_images.rs
- src/template.rs
- weebo-si-crd/src/image_policy.rs
- merge_catalogs
- hashmap
- weebo-si-crd/src/identity.rs
- weebo-si-e2e/src/lib.rs
- passwd-append/tests/integration.rs
- PodSecurityLevel
- PodSelector
- reference.rs
- exchange.rs
- Reachability
- openshift_envtest.rs
- domain/config.rs
- weebo-si-policy-guard-adapters/src/policy_guard.rs
- super
- guard.rs
- weebo-si-endpoint-auth-adapters/src/controller.rs
- src/network_profiles.rs
- weebo-si-image-policy/src/lib.rs
- pod_security_metrics.rs
- arc
- endpoint-gateway/src/main.rs
- jwt_crypto.rs
- core.rs
- FeatureId
- session.rs
- admission_envtest.rs
- Credential
- weebo-si-operator/tests/envtest.rs
- envtest_or_skip!
- registry_object_store.rs
- weebo-si-network-profiles/src/application.rs
- router.rs
- Timestamp
- namespace_label_store.rs
- spec.rs
- jobs
- bearer.rs
- proxy.rs
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
- variable.rs
- feature/kubearmor_policy.rs
- tasks
- entry.rs
- src/registry_config.rs
- team.rs
- registry_metrics.rs
- preauth-proxy/values.yaml
- Decision
- quotas_cmd.rs
- Backend
- http_client.rs
- ns_index.rs
- kube_workload.rs
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
- workspace_gate.rs
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
- config_file.rs
- spike-0009.sh
- Reason
- teams_cmd.rs
- env
- steps
- tasks
- GatewayMetrics
- EnvTest
- weebo-si-dwoc-pin/src/resolve.rs
- kubearmor_envtest.rs
- e2e/values/endpoint-gateway.yaml
- analyze-rust
- config
- registry_envtest.rs
- developer_continuity.rs
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
- btreemap
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
- Applied
- matchDirectories
- RFC 0008 — policy-guard-coverage
- RFC 0014 — resource-quotas
- RFC 0016 — WeeboSiProject
- RFC 0017 — image-rewrite
- with
- preauth-proxy/src/main.rs
- TokenReviewer
- versions
- pod_security_envtest.rs
- RuntimeClass crun
- lint
- duration
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
- Owner
- Weebo Dev Env - Guideline for the Weebo Dev Env
- TargetState
- spec
- podSecurityContext
- podSecurityContext
- compilerOptions
- tasks
- write
- service
- networkPolicy
- weebo-si-pod-security-adapters/src/controller.rs
- resource_quotas_envtest.rs
- Contract
- weebo-si-operator/values.yaml
- TemplateRef
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
- GatewayConfig
- properties
- kubearmor_metrics.rs
- KubeWorkloadIdentity
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
- fmt
- weebo-net-kube-api.yaml
- Enforcement
- append_locked
- WebhookMetrics
- found.rs
- quotas_cmd.rs
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
- weebo-si-resource-quotas/src/resolve.rs
- flag
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
- try_apply
- weebo-si-kubearmor-policy/src/application.rs
- .spawn
- resourceQuotas
- labels
- spec
- RFC 0009 — endpoint-auth
- CI
- Seccomp profiles for workspace nodes
- nodes
- Foreign
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
- TrustedProxy
- properties
- properties
- rules
- controller
- endpointAuth
- outbound.rs
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
- ReviewError
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
- Issuer
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
- ConfigError
- RevalidationMode
- secrets
- certificates
- serviceAccount
- requests
- text
- cspell.json
- networkProfiles
- features
- endpointAuth
- Guide-level explanation
- che-user/Chart.yaml
- push
- charts
- verify
- OnUnknownKey
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
- resourceQuotas
- dwocPin
- imagePolicy
- kubearmorPolicy
- identity
- syncPolicy
- catalog
- catalog
- time.rs
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
- DeleteParams
- streamext
- teardown.rs
- NamespaceFacts
- NetworkProfilesConfigViolation
- rfc5_stack
- Verdict
- arc
- flag
- `image-rewrite`
- `passwd-append`
- Floor

## God Nodes (most connected - your core abstractions)
1. `NamespaceName` - 243 edges
2. `DomainError` - 132 edges
3. `TeamName` - 112 edges
4. `FeatureMode` - 108 edges
5. `Team` - 105 edges
6. `Timestamp` - 83 edges
7. `TemplateRef` - 79 edges
8. `Spec fields` - 78 edges
9. `GatewayState` - 75 edges
10. `WeeboSiTeam` - 71 edges

## Surprising Connections (you probably didn't know these)
- `a_component_rewritten_under_a_changed_or_removed_rule_is_a_stale_mirror()` --references--> `rules`  [INFERRED]
  crates/weebo-si-operator/src/images_cmd.rs → charts/endpoint-gateway/values.yaml
- `start_webhook()` --calls--> `free_port()`  [INFERRED]
  crates/weebo-si-operator/tests/admission_envtest.rs → bins/preauth-proxy/tests/integration.rs
- `an_unreachable_webhook_fails_closed()` --calls--> `free_port()`  [INFERRED]
  crates/weebo-si-operator/tests/admission_envtest.rs → bins/preauth-proxy/tests/integration.rs
- `the_real_chart_namespace_selector_excludes_labelled_namespaces_live()` --calls--> `free_port()`  [INFERRED]
  crates/weebo-si-operator/tests/admission_envtest.rs → bins/preauth-proxy/tests/integration.rs
- `serve_router()` --calls--> `free_port()`  [INFERRED]
  crates/weebo-si-operator/tests/admission_envtest.rs → bins/preauth-proxy/tests/integration.rs

## Import Cycles
- 1-file cycle: `crates/weebo-si-controller/src/events.rs -> crates/weebo-si-controller/src/events.rs`
- 1-file cycle: `crates/weebo-si-network-profiles/src/port.rs -> crates/weebo-si-network-profiles/src/port.rs`
- 1-file cycle: `crates/weebo-si-webhook/src/router.rs -> crates/weebo-si-webhook/src/router.rs`
- 1-file cycle: `bins/preauth-proxy/src/adapters/http_client.rs -> bins/preauth-proxy/src/adapters/http_client.rs`
- 1-file cycle: `crates/weebo-si-endpoint-auth/src/compile.rs -> crates/weebo-si-endpoint-auth/src/compile.rs`
- 2-file cycle: `crates/weebo-si-image-policy/src/platform.rs -> crates/weebo-si-image-policy/src/rewrite.rs -> crates/weebo-si-image-policy/src/platform.rs`
- 2-file cycle: `crates/weebo-si-endpoint-auth/src/index.rs -> crates/weebo-si-endpoint-auth/src/testing.rs -> crates/weebo-si-endpoint-auth/src/index.rs`
- 2-file cycle: `crates/weebo-si-endpoint-auth/src/compile.rs -> crates/weebo-si-endpoint-auth/src/testing.rs -> crates/weebo-si-endpoint-auth/src/compile.rs`
- 2-file cycle: `crates/weebo-si-crd/src/argo.rs -> crates/weebo-si-crd/src/identity.rs -> crates/weebo-si-crd/src/argo.rs`
- 2-file cycle: `crates/weebo-si-crd/src/identity.rs -> crates/weebo-si-crd/src/user.rs -> crates/weebo-si-crd/src/identity.rs`
- 2-file cycle: `crates/weebo-si-image-policy/src/port.rs -> crates/weebo-si-image-policy/src/variable.rs -> crates/weebo-si-image-policy/src/port.rs`
- 2-file cycle: `crates/weebo-si-crd/src/resource_quotas.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/resource_quotas.rs`
- 2-file cycle: `crates/weebo-si-crd/src/dwoc_pin.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/dwoc_pin.rs`
- 2-file cycle: `crates/weebo-si-crd/src/pod_security.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/pod_security.rs`
- 2-file cycle: `crates/weebo-si-crd/src/registry_config.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/registry_config.rs`
- 2-file cycle: `crates/weebo-si-crd/src/image_policy.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/image_policy.rs`
- 2-file cycle: `crates/weebo-si-crd/src/endpoint_auth.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/endpoint_auth.rs`
- 2-file cycle: `crates/weebo-si-crd/src/kubearmor_policy.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/kubearmor_policy.rs`
- 2-file cycle: `crates/weebo-si-crd/src/network_profiles.rs -> crates/weebo-si-crd/src/team.rs -> crates/weebo-si-crd/src/network_profiles.rs`
- 3-file cycle: `crates/weebo-si-endpoint-auth/src/index.rs -> crates/weebo-si-endpoint-auth/src/testing.rs -> crates/weebo-si-endpoint-auth/src/port.rs -> crates/weebo-si-endpoint-auth/src/index.rs`

## Communities (528 total, 83 thin omitted)

### Community 0 - "compute_diff"
Cohesion: 0.05
Nodes (62): a_delete_carries_the_uid_the_object_was_listed_with(), a_field_content_eq_ignores_does_not_force_an_update(), a_uid_alone_does_not_force_an_update(), compute_diff(), Diff, Create, Delete, Unchanged (+54 more)

### Community 1 - "kube_catalog.rs"
Cohesion: 0.04
Nodes (38): a_user_in_two_teams_gets_the_same_one_whatever_the_order(), an_anonymous_and_delegating_entry_is_dropped_alone(), fnv(), grant_for(), hosts_of(), KubeCatalog, Owner, owner() (+30 more)

### Community 2 - "fake_apiserver"
Cohesion: 0.20
Nodes (18): a_flood_of_distinct_tokens_is_held_to_the_limits_and_fails_closed(), a_forged_signature_under_a_proven_key_costs_no_token_review(), a_known_client_keeps_a_reserve_when_strangers_spend_the_global_budget(), a_new_key_set_has_to_prove_itself_again(), a_refused_token_review_is_remembered_rather_than_repeated(), a_slow_apiserver_is_given_up_on_and_not_asked_again_at_once(), a_waiter_hanging_up_does_not_start_a_second_review(), an_abandoned_review_does_not_leave_its_single_flight_entry_behind() (+10 more)

### Community 3 - "weebo-si-endpoint-auth/src/application.rs"
Cohesion: 0.03
Nodes (71): SystemClock, a_back_channel_logout_cuts_off_a_bearer_minted_from_that_session(), a_back_channel_logout_cuts_off_a_cached_session(), a_cookie_cached_for_one_host_is_not_an_identity_on_another(), a_foreign_bearer_is_not_an_identity_and_does_not_cost_a_token_review_twice(), a_name_the_owner_never_wrote_is_not_delegated_to(), a_page_load_of_two_hundred_assets_verifies_one_token(), a_policy_change_lands_on_the_next_request_with_the_same_credential() (+63 more)

### Community 4 - "http.rs"
Cohesion: 0.04
Nodes (78): random_id(), a_caller_cannot_state_an_input_a_second_time_through_the_request_uri(), a_host_cookie_is_capped_at_its_sessions_expiry(), a_preflight_is_the_pair_of_headers_and_not_merely_an_options(), a_redemption_only_redirects_to_a_path_on_the_same_host(), a_return_url_must_be_an_endpoint_of_this_cluster(), a_return_url_with_a_fragment_or_another_port_is_refused(), an_input_the_controller_always_states_is_never_defaulted() (+70 more)

### Community 5 - "inbound_http.rs"
Cohesion: 0.05
Nodes (42): a_body_over_the_cap_is_413(), a_caller_that_never_finishes_its_headers_is_disconnected(), a_client_that_pauses_reading_does_not_get_the_upstream_cut(), a_dropped_body_releases_its_slot(), a_saturated_proxy_answers_503_at_once(), a_stalled_upload_holds_no_slot_and_is_408_after_the_read_timeout(), an_exhausted_body_budget_answers_503_and_bodyless_requests_still_pass(), an_idle_response_body_is_cut_after_the_idle_timeout() (+34 more)

### Community 6 - "weebo-si-identity/src/application.rs"
Cohesion: 0.11
Nodes (34): a_namespace_another_team_won_is_reported_and_not_counted(), a_report_counts_the_namespaces_it_owns_and_the_people_naming_it(), a_username_claim_ignores_case_and_breaks_ties_by_name(), Action, Absent, Adopt, Conflict, Create (+26 more)

### Community 7 - "src/validate.rs"
Cohesion: 0.21
Nodes (28): ResolvedImagePolicyConfig, ImageRewriteConfig, a_declared_variable_is_not_reported_as_undeclared(), a_declared_variable_no_pattern_uses_is_reported(), a_default_entry_with_one_non_interpolating_pattern_is_fine(), a_rule_no_pattern_permits_and_an_empty_set_warn_and_off_warns_nothing(), a_team_name_illegal_only_by_case_or_space_is_still_reported(), a_top_level_default_entry_that_can_only_grant_nothing_is_reported() (+20 more)

### Community 8 - "EndpointAuthConfigViolation"
Cohesion: 0.14
Nodes (16): EndpointAuthConfigViolation, AnonymousEntryDelegates, BadErrorPageMiddleware, BadHostOwnership, CatalogKeyConflict, CustomDialectHasNoTemplate, DefaultNotAllowed, DuplicateAccessKey (+8 more)

### Community 9 - "kube_catalog.rs"
Cohesion: 0.04
Nodes (102): catalogue_from(), translate(), HOST, main(), measure(), policy(), request(), a_compile_failure_still_leaves_the_owner_able_to_reach_their_own_endpoint() (+94 more)

### Community 10 - "config_store.rs"
Cohesion: 0.06
Nodes (40): allow_listed(), AuthentikProvisioning, IdentityConfig, IdentityConfigViolation, DuplicateUsername, EmailRequired, GroupRefNotAllowed, ProjectNotAllowed (+32 more)

### Community 11 - "TeamName"
Cohesion: 0.05
Nodes (33): a_changed_bound_annotation_is_counted(), a_namespace_with_no_team_gets_a_named_label_not_an_empty_one(), a_platform_only_image_ticks_its_own_counter_as_well_as_the_main_one(), a_variable_resolution_is_counted_by_name_and_result(), a_verdict_is_counted_by_result_resource_and_team(), an_ungranted_request_is_one_tick_per_decision_not_per_key(), counter(), ImageMetrics (+25 more)

### Community 12 - "weebo-si-crd/src/endpoint_auth.rs"
Cohesion: 0.04
Nodes (81): NamespaceSelection, OnUnknownKey, Default, Deny, a_custom_template_must_declare_every_key_it_writes(), a_host_is_claimed_by_another_only_when_the_patterns_definitely_say_so(), a_host_names_its_owner_through_the_first_matching_pattern(), a_host_two_users_could_claim_is_owned_by_neither() (+73 more)

### Community 13 - "oidc.rs"
Cohesion: 0.06
Nodes (45): install(), a_failed_first_jwks_fetch_is_retried_with_backoff_not_on_the_schedule(), a_jwks_generation_bump_is_what_invalidates_a_cached_identity(), a_logout_token_is_a_logout_token_and_not_any_signed_token_with_a_sid(), a_signed_token_is_only_an_identity_when_it_is_also_for_us(), a_verifier_with_no_keys_refuses_rather_than_trusting_the_header(), ALLOWED_ALGORITHMS, an_opaque_token_is_labelled_opaque_rather_than_invalid() (+37 more)

### Community 14 - "pattern.rs"
Cohesion: 0.06
Nodes (55): a_declared_variable_interpolates_in_a_path_segment(), a_digest_only_reference_does_not_satisfy_a_tag_constraint_by_default(), a_digested_reference_matches_only_tag_agnostic_patterns(), a_double_star_matches_one_or_more_segments_never_zero(), a_literal_pattern_matches_only_itself(), a_pattern_never_matches_a_reference_whose_normalized_host_differs(), a_pattern_with_a_tag_constraint_matches_only_a_matching_tag(), a_pattern_with_no_tag_constraint_matches_any_tag_or_a_digest() (+47 more)

### Community 15 - "TemplateRef"
Cohesion: 0.10
Nodes (38): limit_items_are_read_from_the_spec(), LimitItem, LimitRangeTemplate, QuotaTemplate, string_map(), a_compute_quota_without_a_container_default_is_an_outage_and_refused(), a_compute_quota_without_any_limit_range_is_refused(), a_missing_template_is_reported_by_kind() (+30 more)

### Community 16 - "kube_policy_store.rs"
Cohesion: 0.05
Nodes (47): BACKEND_LABEL, CANARY_LABEL, DEVWORKSPACE_ID_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, PROFILE_LABEL, a_listed_object_carries_its_uid_into_the_delete_precondition(), a_profile_object_round_trips_its_owner_through_what_this_adapter_writes() (+39 more)

### Community 17 - "Spec fields"
Cohesion: 0.03
Nodes (78): `spec.features.dwocPin.catalog[]` [#spec.features.dwocPin.catalog], `spec.features.dwocPin.namespaceSelection` [#spec.features.dwocPin.namespaceSelection], `spec.features.dwocPin.namespaceSelector.matchExpressions[]` [#spec.features.dwocPin.namespaceSelector.matchExpressions], `spec.features.dwocPin.namespaceSelector` [#spec.features.dwocPin.namespaceSelector], `spec.features.dwocPin` [#spec.features.dwocPin], `spec.features.endpointAuth.catalog[]` [#spec.features.endpointAuth.catalog], `spec.features.endpointAuth.endpointSelection` [#spec.features.endpointAuth.endpointSelection], `spec.features.endpointAuth.gateway.custom` [#spec.features.endpointAuth.gateway.custom] (+70 more)

### Community 18 - "weebo-si-resource-quotas-adapters/src/controller.rs"
Cohesion: 0.08
Nodes (17): configured_off(), Ctx, Error, error_policy(), FEATURE, Fingerprint, fingerprint_changes(), log() (+9 more)

### Community 19 - "weebo-si-endpoint-auth-adapters/src/endpoint_auth.rs"
Cohesion: 0.06
Nodes (43): RoutingKind, Ingress, Route, a_host_another_namespace_owns_is_refused_and_a_hostless_object_is_not_judged(), a_hyphenated_owner_is_admitted_their_host_unless_another_reading_is_a_user(), an_annotation_dwo_dropped_is_put_back_on_an_update(), an_unusable_rule_list_is_refused_at_admission_with_the_reason(), an_update_that_tampers_with_the_chain_is_left_for_the_guard_to_refuse() (+35 more)

### Community 20 - "conformance.rs"
Cohesion: 0.06
Nodes (50): ALICE_HOST, ALICE_POD_IP, Answer, BOB_HOST, BOB_POD_IP, BURST, CAROL_HOST, CAROL_POD_IP (+42 more)

### Community 21 - "pod_images.rs"
Cohesion: 0.13
Nodes (16): a_namespace_with_no_team_gets_the_top_level_default(), a_platform_image_is_permitted_in_a_namespace_whose_team_is_granted_nothing(), an_unparseable_reference_on_a_pod_is_denied_too(), both_halves_report_the_same_feature_id_so_one_mode_gates_both(), config(), evaluate(), every_container_list_is_judged_because_the_subject_carries_them_flattened(), PodImagesFeature (+8 more)

### Community 22 - "src/template.rs"
Cohesion: 0.13
Nodes (27): is_legal_variable_name(), legal_variable_names_are_exactly_the_documented_charset(), a_misspelled_variable_is_never_a_literal(), a_rendered_namespace_has_to_be_one(), an_unbound_variable_is_an_error_not_a_literal(), an_unterminated_passthrough_is_refused(), an_unterminated_variable_is_refused(), Bindings (+19 more)

### Community 23 - "weebo-si-crd/src/image_policy.rs"
Cohesion: 0.07
Nodes (46): a_declared_variable_outside_the_name_charset_is_reported(), a_declared_variable_rebinding_a_reserved_name_is_reported(), a_declared_variable_with_an_empty_binding_is_reported(), a_grant_allowed_naming_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_top_level_default_naming_an_uncatalogued_key_is_reported(), a_well_formed_configuration_produces_no_violations() (+38 more)

### Community 24 - "merge_catalogs"
Cohesion: 0.18
Nodes (11): Decision<S>, a_redefinition_is_reported_and_the_first_definition_wins(), a_team_cannot_shadow_a_cluster_entry(), CatalogConflict, Entry, entry(), merge_catalogs(), team() (+3 more)

### Community 25 - "hashmap"
Cohesion: 0.06
Nodes (35): an_introspection_response_is_read_with_the_same_claim_names_as_a_jwt(), Introspected, Introspector, MAX_INFLIGHT, a_burst_is_allowed_and_the_next_call_is_not(), a_flood_of_new_addresses_does_not_reset_anybody_elses_limit(), Bucket, Buckets (+27 more)

### Community 26 - "weebo-si-crd/src/identity.rs"
Cohesion: 0.05
Nodes (71): a_clean_template_has_no_violation(), a_namespace_naming_itself_is_refused(), a_namespace_override_wins_and_rebinds_the_variable(), a_person_overrides_one_value_and_keeps_its_siblings(), a_source_naming_both_chart_and_path_is_refused(), an_unknown_variable_inside_values_is_found(), ApplicationDestination, ApplicationSource (+63 more)

### Community 27 - "weebo-si-e2e/src/lib.rs"
Cohesion: 0.09
Nodes (21): a_dashboard_shaped_workspace_carries_the_dashboards_config_attribute(), a_sample_is_found_by_name_and_a_subset_of_its_labels(), AllToLoopback, config_status(), delete(), DOMAIN, Endpoint, fail() (+13 more)

### Community 28 - "passwd-append/tests/integration.rs"
Cohesion: 0.10
Nodes (46): a_command_after_the_separator_is_exec_ed(), a_database_without_a_trailing_newline_is_repaired_not_corrupted(), a_fresh_run_appends_both_entries(), a_hostile_home_exits_two_without_touching_the_files(), a_login_name_taken_by_another_uid_is_not_duplicated(), a_missing_target_is_reported(), a_non_utf8_passwd_database_still_gets_its_entry(), a_re_run_with_different_fields_still_writes_nothing() (+38 more)

### Community 29 - "PodSecurityLevel"
Cohesion: 0.12
Nodes (21): default_ceiling(), PodSecurityLevel, .ALL, Baseline, Privileged, Restricted, a_namespace_of_no_team_gets_the_default_and_no_team(), config() (+13 more)

### Community 30 - "PodSelector"
Cohesion: 0.14
Nodes (17): PodSelector, DevWorkspaceId, Empty, a_desired_object_colliding_with_another_scopes_live_object_is_refused(), a_desired_object_with_a_foreign_selector_is_refused(), a_held_object_is_neither_deleted_nor_updated(), a_stale_object_of_the_same_scope_is_still_deleted(), a_workspace_scope_never_deletes_the_baseline_or_a_sibling_workspace_object() (+9 more)

### Community 31 - "reference.rs"
Cohesion: 0.06
Nodes (47): is_legal_pattern_char(), parse_host(), split_pattern_host(), split_pattern_tag(), validate_host_literal_label(), a_digest_drops_the_tag_because_the_tag_is_not_evidence(), a_first_component_with_no_dot_and_no_port_is_a_path_not_a_host(), a_port_is_a_host_and_a_tag_is_a_tag_even_together() (+39 more)

### Community 32 - "exchange.rs"
Cohesion: 0.11
Nodes (38): a_cookie_merely_ending_in_the_marker_name_is_not_the_marker(), a_credential_whose_cookie_name_is_unclear_drops_every_set_cookie(), a_failed_acquisition_is_an_error_not_an_unauthenticated_forward(), a_non_cookie_injection_drops_every_set_cookie(), a_non_cookie_injection_still_relays_set_cookie_on_passthrough(), a_passed_through_request_is_not_renewed_on_a_401(), a_passed_through_response_keeps_its_set_cookie(), a_relay_reports_what_it_did_so_the_adapter_can_log_it() (+30 more)

### Community 33 - "Reachability"
Cohesion: 0.15
Nodes (11): a_target_unreachable_before_any_policy_is_unknown_never_enforcing(), an_inconclusive_leg_is_never_folded_into_a_definite_verdict(), Reachability, Blocked, Inconclusive, Reached, reachable_in_both_legs_means_the_cni_ignores_policy(), reachable_then_blocked_is_the_only_proof_of_enforcement() (+3 more)

### Community 34 - "openshift_envtest.rs"
Cohesion: 0.05
Nodes (39): COMPANION_SERVICE, UPSTREAM_ANNOTATION, ALICE, BREAK_GLASS, CHAIN, config_yaml(), create_namespace(), DEVWORKSPACE_OPERATOR_CONFIG_CRD (+31 more)

### Community 35 - "domain/config.rs"
Cohesion: 0.06
Nodes (38): non_empty(), a_bare_dollar_is_literal(), an_origin_builds_absolute_uris(), an_origin_with_userinfo_query_fragment_or_whitespace_is_refused_without_echoing_it(), an_unclosed_reference_is_malformed(), an_unset_reference_is_an_error_not_an_empty_string(), ConfigError, Empty (+30 more)

### Community 36 - "weebo-si-policy-guard-adapters/src/policy_guard.rs"
Cohesion: 0.10
Nodes (19): FeatureGate, admission_routes(), guarded_write_from_request(), log_decision(), log_unguarded(), policy_guard_router(), PolicyGuardState, VALIDATE_KUBEARMOR_POLICIES_PATH (+11 more)

### Community 37 - "super"
Cohesion: 0.05
Nodes (35): IMAGE_REWRITE_ANNOTATION, MAX_REWRITE_RULES, RewriteRule, a_ceiling_of_privileged_makes_every_level_legal(), a_team_violation_is_reported_once_and_names_its_team(), config(), default_pod_security_annotation(), PodSecurityConfigViolation (+27 more)

### Community 38 - "guard.rs"
Cohesion: 0.13
Nodes (25): a_create_of_an_unmanaged_object_by_a_non_allowed_identity_is_denied(), a_create_of_an_unmanaged_object_by_an_allowed_identity_is_allowed(), a_non_operator_touching_a_managed_object_is_denied_on_every_operation(), an_update_of_an_unmanaged_object_by_anyone_is_allowed(), any_write_from_the_operator_is_allowed(), ctx(), guard(), GuardedWrite (+17 more)

### Community 39 - "weebo-si-endpoint-auth-adapters/src/controller.rs"
Cohesion: 0.08
Nodes (45): ResolvedEndpointAuthConfig, a_stripped_annotation_is_put_back_on_the_next_pass(), an_object_that_already_agrees_is_left_alone(), annotation_patch(), attached(), break_glass_survives_the_sweep_rather_than_being_quietly_undone(), CHAIN, companion_service() (+37 more)

### Community 40 - "src/network_profiles.rs"
Cohesion: 0.11
Nodes (29): a_baseline_absent_from_the_catalog_is_reported(), a_grant_allowed_naming_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_profile_with_no_variants_is_reported(), a_profile_with_two_variants_for_the_same_backend_is_reported(), a_well_formed_configuration_produces_no_violations(), an_empty_grant_is_not_a_violation() (+21 more)

### Community 41 - "weebo-si-image-policy/src/lib.rs"
Cohesion: 0.06
Nodes (42): PlatformConfig, FEATURE_ID, a_rule_derives_the_mirrored_form_of_the_four_platform_images_only(), an_unparseable_extra_is_an_error_not_a_silent_skip(), builtin_false_empties_the_compiled_in_half(), BUILTIN_PLATFORM_PATTERNS, derived_platform_patterns(), DerivedPattern (+34 more)

### Community 42 - "pod_security_metrics.rs"
Cohesion: 0.10
Nodes (25): a_pass_that_writes_nothing_keeps_the_last_writes_violations(), every_series_starts_at_zero(), gauge(), outcome(), PodSecurityMetrics, results_and_drift_are_counted_and_teardown_forgets(), the_gauges_follow_the_namespaces_and_forget_drops_one(), the_summary_warning_is_not_a_pod() (+17 more)

### Community 43 - "arc"
Cohesion: 0.08
Nodes (56): a_container_with_no_image_is_skipped_not_denied(), a_created_pod_offers_every_image_location_to_the_rewrite(), a_plugin_component_is_not_read_because_dwo_resolves_it_after_admission(), a_pod_with_only_containers_still_works(), a_workspace_offers_its_component_images_and_its_existing_record(), a_workspace_update_matches_components_by_name_not_position(), a_workspace_with_no_components_yields_no_images_rather_than_failing(), all_three_pod_container_lists_are_read() (+48 more)

### Community 44 - "endpoint-gateway/src/main.rs"
Cohesion: 0.06
Nodes (32): IntrospectorPorts, installed(), discover(), Discovery, OidcClient, refresh_jwks(), TokenResponse, metrics_router() (+24 more)

### Community 45 - "jwt_crypto.rs"
Cohesion: 0.06
Nodes (18): a_key_of_the_wrong_family_is_refused_before_any_signature_is_tried(), an_algorithm_ring_does_not_take_over_still_goes_to_rust_crypto(), compute_digest(), es256_pair(), es256_verifies_its_own_signature_and_nothing_else(), extract_ec_public_key_coordinates(), new_signer(), new_verifier() (+10 more)

### Community 46 - "core.rs"
Cohesion: 0.11
Nodes (32): a_declared_variable_the_adapter_could_not_resolve_is_reported_undefined(), a_declared_variable_the_adapter_resolved_is_not_reported_undefined(), a_dropped_not_granted_key_is_counted_once_per_decision(), a_platform_only_image_is_flagged_as_such_for_its_own_counter(), an_attacker_controlled_reference_is_escaped_before_it_reaches_the_api_error(), an_unparseable_reference_denies_and_says_so(), bind_builtins(), both_builtins_report_their_outcome_every_request() (+24 more)

### Community 47 - "FeatureId"
Cohesion: 0.08
Nodes (14): FeatureId, FeatureOutcome, Observer, RecordingObserver, FeatureMode, DryRun, Enforce, Off (+6 more)

### Community 48 - "session.rs"
Cohesion: 0.06
Nodes (40): a_grant_is_not_a_session(), a_key_is_accepted_in_whichever_base64_the_admin_generated_it(), a_login_state_cookie_is_not_an_sso_cookie_and_an_sso_cookie_is_not_a_login_state(), a_sealed_cookie_opens_on_the_host_it_was_sealed_for_and_on_no_other(), a_tampered_cookie_does_not_open(), an_expired_cookie_does_not_open(), Binding, HostBound (+32 more)

### Community 49 - "admission_envtest.rs"
Cohesion: 0.04
Nodes (34): a_kubearmor_policy_is_guarded_exactly_as_a_network_policy_is(), a_resource_no_guard_variant_covers_is_allowed_but_counted_and_warned(), CONTROLLER_IDENTITY, CONTROLLER_TOKEN, create_policy_template(), DEVWORKSPACE_CRD, DEVWORKSPACE_OPERATOR_CONFIG_CRD, install_kubearmor_crd() (+26 more)

### Community 50 - "Credential"
Cohesion: 0.08
Nodes (18): a_failed_acquisition_caches_nothing(), AlwaysFails, Cache, concurrent_misses_produce_exactly_one_login(), CountingSource, invalidating_a_credential_that_is_no_longer_held_is_a_no_op(), invalidating_the_held_credential_empties_the_cache(), the_first_call_acquires_and_the_second_reuses() (+10 more)

### Community 51 - "weebo-si-operator/tests/envtest.rs"
Cohesion: 0.08
Nodes (33): apply_document(), assert_forbidden(), controller_role_matches_the_documented_grants(), CONTROLLER_TOKEN, create_release_namespace(), create_weebosiconfig(), DEVWORKSPACE_CRD, DEVWORKSPACE_OPERATOR_CONFIG_CRD (+25 more)

### Community 52 - "envtest_or_skip!"
Cohesion: 0.29
Nodes (29): a_devworkspace_is_pinned_by_a_real_running_webhook(), a_devworkspace_is_refused_until_its_namespace_has_a_baseline_live(), a_dwoc_pin_block_added_after_boot_is_observed_without_a_restart(), a_namespace_annotation_inside_the_allowed_set_is_honoured_live(), a_started_toggle_on_an_already_pinned_workspace_is_a_no_op(), a_status_only_update_bypasses_the_webhook_live(), an_unreachable_webhook_fails_closed(), an_upstream_image_is_rewritten_onto_the_mirror_before_image_policy_judges_it() (+21 more)

### Community 53 - "registry_object_store.rs"
Cohesion: 0.08
Nodes (21): a_malformed_body_is_a_port_failure_rather_than_a_half_written_object(), a_secret_copy_names_the_secret_kind_and_carries_its_type(), API_VERSION, apply_document(), delete(), FIELD_MANAGER, KubeRegistryObjectStore, object() (+13 more)

### Community 54 - "weebo-si-network-profiles/src/application.rs"
Cohesion: 0.18
Nodes (34): a_canary_that_reaches_in_both_legs_reports_not_enforcing(), a_canary_that_reaches_then_is_blocked_reports_enforcing(), a_canary_whose_first_leg_fails_skips_the_second_and_reports_unknown(), a_live_profile_object_without_an_owner_is_updated_to_carry_its_workspace(), a_second_enforce_pass_with_nothing_changed_reports_unchanged_and_leaves_the_store_alone(), a_stale_object_of_the_same_workspace_is_still_deleted(), a_workspace_reconcile_never_deletes_the_baseline_or_a_sibling_workspace_object(), all_templates() (+26 more)

### Community 55 - "router.rs"
Cohesion: 0.09
Nodes (25): Registry, Subject, DwocCatalog, Workspace, absent_attribute_is_none(), an_empty_attribute_key_disables_the_channel_entirely(), CONFIG_REF_ATTRIBUTE, every_operation_other_than_create_maps_to_update() (+17 more)

### Community 56 - "Timestamp"
Cohesion: 0.09
Nodes (8): a_revocation_prunes_the_expired_and_refuses_to_overflow(), ADDRESS_FORGERY_ANNOTATION, KubeRevocations, MAX_REVOCATIONS, plan_revocation(), RevokeError, Full, Kube

### Community 57 - "namespace_label_store.rs"
Cohesion: 0.17
Nodes (9): apply_body(), KubeNamespaceLabelStore, release_body(), restore_body(), the_apply_body_carries_the_six_labels_and_the_annotation_only(), the_restore_body_sets_back_removes_the_rest_and_drops_the_annotation(), warnings(), warnings_are_unwrapped_from_the_299_format() (+1 more)

### Community 58 - "spec.rs"
Cohesion: 0.07
Nodes (50): a_default_absent_from_the_catalog_is_reported(), a_grant_allowed_naming_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_grant_with_an_empty_allowed_set_is_reported(), a_well_formed_configuration_produces_no_violations(), Catalog, catalog_entry_wire_shape_is_flat() (+42 more)

### Community 59 - "jobs"
Cohesion: 0.06
Nodes (46): name, runs-on, steps, timeout-minutes, run, name, runs-on, steps (+38 more)

### Community 60 - "bearer.rs"
Cohesion: 0.07
Nodes (21): a_nonce_on_its_own_is_not_an_id_token(), a_token_minted_for_another_client_of_the_same_realm_is_not_an_identity(), an_id_token_is_refused_even_where_its_party_is_listed(), BearerResult, Accepted, AcceptedAuthorizedParty, Expired, Foreign (+13 more)

### Community 61 - "proxy.rs"
Cohesion: 0.11
Nodes (21): HOST_COOKIE, a_forward_auth_deployment_never_carries_application_traffic(), a_request_with_only_our_cookie_arrives_with_no_cookie_header_at_all(), an_endpoint_hosts_request_is_the_applications_whatever_its_path(), both_shapes(), client(), fallback(), forward() (+13 more)

### Community 62 - "webhook_cmd.rs"
Cohesion: 0.07
Nodes (10): DEFAULT_HOLDER_ID, DEFAULT_LEASE_NAMESPACE, LEASE_NAME, DRAIN_DELAY, MAX_REVIEW_BYTES, devworkspace_operator_config_resource(), KubeDwocStore, KubeNsStore (+2 more)

### Community 63 - "kube_canary.rs"
Cohesion: 0.09
Nodes (26): build(), canary_deny_policy_spec(), canary_pod_spec(), client_args(), CLIENT_POD, CLIENT_TERMINAL_TIMEOUT, CONNECT_TIMEOUT, DENY_POLICY (+18 more)

### Community 64 - "weebo-si-pod-security/src/lib.rs"
Cohesion: 0.07
Nodes (27): PodSecurityVersion, a_namespaces_other_labels_are_dropped(), AUDIT, AUDIT_VERSION, desired_writes_exactly_the_six_keys(), diff(), diff_lists_sets_and_removals_in_key_order(), ENFORCE (+19 more)

### Community 65 - "includes"
Cohesion: 0.05
Nodes (45): cmds, desc, cmds, desc, task, includes, ci, crd (+37 more)

### Community 66 - "feature.rs"
Cohesion: 0.17
Nodes (30): FakeDwocCatalog, DwocRef, ResolvedDwocPinConfig, add_when_no_current_reference(), allowed_override_when_current_is_inside_the_grants_allowed_set(), already_pinned_when_current_equals_resolved(), an_annotation_value_is_escaped_and_bounded_before_it_reaches_a_message(), an_invalid_config_where_the_resolved_key_is_not_in_the_catalog_is_a_domain_error() (+22 more)

### Community 67 - "perf_envtest.rs"
Cohesion: 0.07
Nodes (18): preauth_proxy_logs_in_once_injects_the_credential_and_renews_it_on_a_401(), apply(), clock_ticks(), configure(), Controller, cpu_seconds(), env_or(), FIXTURES (+10 more)

### Community 68 - "endpoint_routing.rs"
Cohesion: 0.11
Nodes (29): a_developer_may_not_create_or_update_an_endpoint_into_bypass(), a_host_this_namespace_does_not_own_is_refused_whoever_wrote_it(), CHAIN, DWO, EndpointRoutingGuard, EndpointRoutingWrite, expected(), EXPECTED_CHAIN (+21 more)

### Community 69 - "quota_metrics.rs"
Cohesion: 0.07
Nodes (27): a_namespace_moving_profile_leaves_the_old_series(), namespaces_and_saturation_follow_the_picture(), NO_PROFILE, only_a_change_of_the_annotation_counts(), outcome(), Picture, profiles_are_set_not_added(), ResourceQuotasMetrics (+19 more)

### Community 70 - "bricks/readme.md"
Cohesion: 0.22
Nodes (3): `deploy/weebo-si/`, Architecture, Bricks

### Community 71 - "weebo-si/values/weebo-si-operator.yaml"
Cohesion: 0.05
Nodes (44): certificates, provider, enabled, controller, leaderElection, replicaCount, endpointAuth, dialect (+36 more)

### Community 72 - "tests/endpoint_auth.rs"
Cohesion: 0.12
Nodes (31): ca_file(), gateway_metric_sum(), Ingress, a_caller_stated_identity_never_reaches_the_workspace(), a_developer_cannot_take_the_gate_off_their_own_endpoint(), a_host_cookie_minted_for_one_endpoint_is_refused_on_another(), a_second_namespace_claiming_a_host_the_patterns_give_to_another_is_refused(), a_team_endpoint_opens_to_a_teammate_and_stays_shut_to_a_stranger() (+23 more)

### Community 73 - "weebo-si-identity-adapters/src/controller.rs"
Cohesion: 0.10
Nodes (26): WeeboSiTeamStatus, WeeboSiUser, a_team_change_requeues_its_members_and_nobody_else(), claimant(), condition(), Ctx, Error, error_policy() (+18 more)

### Community 74 - "images_cmd.rs"
Cohesion: 0.08
Nodes (22): Verdict, NoMatchingPattern, Permitted, Unparseable, a_component_rewritten_under_a_changed_or_removed_rule_is_a_stale_mirror(), a_listed_namespace_view_answers_labels_and_annotations(), audit(), AuditRow (+14 more)

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
Cohesion: 0.17
Nodes (43): ImageGrant, a_catalogued_image_is_attributed_to_its_entry(), a_namespace_with_no_team_reaches_no_team_registry_image_at_all(), a_platform_image_is_attributed_to_the_platform_set(), a_team_with_no_grant_is_the_same_case_as_no_team(), allowed_set(), an_empty_workspace_attribute_means_explicitly_nothing_and_does_not_fall_through(), an_entry_with_an_unparseable_pattern_grants_nothing_at_all() (+35 more)

### Community 79 - "controller_envtest.rs"
Cohesion: 0.14
Nodes (34): a_config_under_the_wrong_name_is_reported_degraded(), a_dry_run_reports_what_it_would_create_and_creates_nothing(), a_kind_this_cluster_does_not_serve_is_absent_not_missing(), a_person_gets_an_authentik_user_owned_by_their_own_object(), a_persons_workspace_application_is_rendered_from_their_teams_template(), a_second_person_claiming_a_taken_username_writes_nothing(), a_team_redefining_a_catalogue_key_is_reported_degraded(), a_team_reports_its_namespaces_its_members_and_what_it_lost() (+26 more)

### Community 80 - "deploy"
Cohesion: 0.05
Nodes (41): defaults, name, runs-on, steps, timeout-minutes, concurrency, cancel-in-progress, group (+33 more)

### Community 81 - "tasks"
Cohesion: 0.05
Nodes (41): cmds, desc, status, cmds, desc, status, cmds, desc (+33 more)

### Community 82 - "preauth-proxy/tests/integration.rs"
Cohesion: 0.13
Nodes (25): a_401_renews_and_replays_once(), a_caller_cookie_without_the_marker_is_joined_not_replaced(), a_first_request_acquires_and_injects(), a_refusing_origin_stops_the_rollout_with_exit_three(), a_request_carrying_the_marker_is_passed_through_untouched(), an_origin_that_mints_nothing_also_exits_three(), an_unreachable_upstream_is_a_502_never_an_open_door(), an_unset_secret_is_exit_two_and_never_an_empty_password() (+17 more)

### Community 83 - "versions"
Cohesion: 0.06
Nodes (40): jsonPath, name, type, apiVersion, kind, metadata, spec, apiVersion (+32 more)

### Community 84 - "src/kubearmor_policy.rs"
Cohesion: 0.05
Nodes (70): a_baseline_absent_from_the_catalog_is_reported(), a_default_outside_its_own_allowed_set_is_reported(), a_grant_allowing_an_uncatalogued_key_is_reported(), a_grant_naming_an_undeclared_team_is_reported(), a_well_formed_configuration_produces_no_violations(), an_empty_grant_is_not_a_violation(), an_invalid_runtime_profile_key_is_reported(), clean_catalog() (+62 more)

### Community 85 - "variable.rs"
Cohesion: 0.10
Nodes (19): vars(), a_declared_variable_resolves_from_its_bound_annotation(), a_hostile_value_is_still_seen_by_the_detection_control(), a_missing_annotation_leaves_the_variable_undefined(), a_namespace_binds_because_dns_1123_is_a_subset_of_a_path_component(), a_reserved_or_illegal_declared_name_is_skipped_rather_than_resolved(), a_team_name_with_a_space_is_illegal_not_silently_trimmed(), an_absent_name_is_undefined_rather_than_empty() (+11 more)

### Community 86 - "feature/kubearmor_policy.rs"
Cohesion: 0.18
Nodes (30): ResolvedKubeArmorPolicyConfig, a_baseline_key_absent_from_the_catalog_is_a_domain_error(), a_granted_key_whose_template_has_not_landed_writes_nothing_for_that_key_alone(), a_missing_baseline_template_still_carries_the_posture(), a_workspace_asking_for_nothing_beyond_the_default_gets_the_grant_default(), a_workspace_with_two_granted_profiles_gets_two_objects_keyed_by_workspace_id(), an_ungranted_request_under_deny_writes_nothing_beyond_the_baseline(), BASELINE_NAME (+22 more)

### Community 87 - "tasks"
Cohesion: 0.05
Nodes (39): cmds, desc, silent, cmds, deps, desc, env, silent (+31 more)

### Community 88 - "entry.rs"
Cohesion: 0.08
Nodes (24): Case, empty_shell_is_allowed_and_renders_as_an_empty_field(), group_line_matches_upstream_byte_for_byte(), GroupEntry, InvalidField, MAX_NAME_LEN, passwd_line_matches_upstream_byte_for_byte(), PasswdEntry (+16 more)

### Community 89 - "src/registry_config.rs"
Cohesion: 0.11
Nodes (35): a_configmap_and_a_secret_of_the_same_name_are_two_different_sources(), a_grant_allowing_an_uncatalogued_key_is_reported(), a_grant_default_outside_its_own_allowed_is_reported(), a_grant_naming_a_team_nobody_declared_is_reported(), a_well_formed_configuration_produces_no_violations(), an_empty_grant_is_not_a_violation(), an_entry_with_no_sources_is_reported(), clean_catalog() (+27 more)

### Community 90 - "team.rs"
Cohesion: 0.07
Nodes (41): TeamNetworkProfiles, TeamPodSecurity, a_redefined_key_is_a_conflict_and_the_first_definition_stands(), a_team_default_it_cannot_reach_is_reported(), a_team_reaches_its_own_profiles_and_the_cluster_default(), an_empty_catalogue_is_reported(), config(), default_quota_annotation() (+33 more)

### Community 91 - "registry_metrics.rs"
Cohesion: 0.18
Nodes (18): a_create_is_not_drift(), a_dry_run_pass_never_lands_on_a_write_result(), a_forgotten_namespace_stops_being_counted_at_all(), a_namespace_that_recovers_moves_between_states_rather_than_being_counted_twice(), a_refused_template_is_counted_by_key_and_reason(), an_enforce_pass_counts_what_was_applied(), an_object_whose_key_left_the_catalogue_is_still_counted(), an_update_in_enforce_is_counted_as_restored_drift() (+10 more)

### Community 92 - "preauth-proxy/values.yaml"
Cohesion: 0.05
Nodes (37): affinity, config, containerPort, credentials, existingSecret, secretKey, userKey, namespaceSelector (+29 more)

### Community 93 - "Decision"
Cohesion: 0.13
Nodes (20): Decision, a_break_glass_identity_may_touch_a_managed_object(), a_secret_is_guarded_exactly_as_a_configmap_is(), a_user_touching_a_managed_object_is_denied_on_every_operation(), an_ordinary_configmap_a_developer_creates_is_never_this_guards_business(), any_write_from_the_operator_is_allowed(), BREAK_GLASS, decide() (+12 more)

### Community 94 - "quotas_cmd.rs"
Cohesion: 0.17
Nodes (11): Quantity, .ZERO, compute(), Over, over(), parse_or_zero(), pod(), PodResources (+3 more)

### Community 95 - "Backend"
Cohesion: 0.08
Nodes (23): Backend, Cilium, NetworkPolicy, EnforcementBackend, Auto, Cilium, NetworkPolicy, CILIUM_GROUP (+15 more)

### Community 96 - "http_client.rs"
Cohesion: 0.14
Nodes (20): a_cookie_that_deletes_is_not_a_credential(), a_header_value_that_cannot_be_a_header_never_echoes_the_value(), a_silent_origin_is_an_acquisition_failure_after_the_response_timeout(), a_silent_upstream_is_a_gateway_error_after_the_response_timeout(), acquisition(), client(), HttpClient, HttpCredentialSource (+12 more)

### Community 97 - "ns_index.rs"
Cohesion: 0.18
Nodes (10): a_relist_replaces_the_index_at_init_done_like_the_store(), dynamic_object_keys_look_up_in_a_store_built_with_the_same_resource(), feed(), Inner, it_answers_per_namespace_and_follows_applies_and_deletes(), names(), np(), NsIndex (+2 more)

### Community 98 - "kube_workload.rs"
Cohesion: 0.13
Nodes (15): a_reviewed_token_is_cached_no_longer_than_its_own_exp(), a_terminated_or_deleting_pod_does_not_own_its_address(), address_index(), an_address_two_namespaces_claim_resolves_to_neither(), GLOBAL_KEY, KNOWN_CLIENT_TTL_SECS, LEGACY_ISSUER, OWN_TOKEN (+7 more)

### Community 99 - "Spec fields"
Cohesion: 0.05
Nodes (36): Build a manifest, Example, `spec.features.dwocPin.catalog[]` [#spec.features.dwocPin.catalog], `spec.features.dwocPin` [#spec.features.dwocPin], `spec.features.endpointAuth.catalog[]` [#spec.features.endpointAuth.catalog], `spec.features.endpointAuth` [#spec.features.endpointAuth], `spec.features.imagePolicy.catalog[]` [#spec.features.imagePolicy.catalog], `spec.features.imagePolicy` [#spec.features.imagePolicy] (+28 more)

### Community 100 - "kubearmor_metrics.rs"
Cohesion: 0.17
Nodes (19): a_create_is_not_drift(), a_dry_run_pass_never_lands_on_a_write_result(), an_enforce_pass_counts_what_was_applied(), an_update_in_enforce_is_counted_as_restored_drift(), kind_label(), KubeArmorMetrics, managed_objects_are_counted_by_kind_and_scope(), no_metric_carries_a_namespace_or_a_workspace_label() (+11 more)

### Community 101 - "cost.rs"
Cohesion: 0.14
Nodes (13): HOST, ISSUER, KEY, NoRevocations, now(), payload(), policy(), realm() (+5 more)

### Community 102 - "registry_template_store.rs"
Cohesion: 0.12
Nodes (19): a_config_map_with_no_data_at_all_still_has_a_body(), a_config_maps_body_carries_data_and_binary_data_and_nothing_else(), a_secrets_body_carries_data_and_type_but_never_string_data(), an_object_with_no_metadata_maps_at_all_projects_to_empty_maps(), body_from(), config_map_body(), copied_metadata(), find() (+11 more)

### Community 103 - "feature/network_profiles.rs"
Cohesion: 0.19
Nodes (24): ResolvedNetworkProfilesConfig, a_workspace_asking_for_nothing_beyond_the_default_gets_the_grant_default(), a_workspace_with_two_granted_profiles_gets_two_objects_keyed_by_workspace_id(), an_ungranted_request_under_deny_writes_nothing_beyond_the_baseline(), BASELINE_NAME, config(), ctx(), evaluate_with_no_config_at_all_is_a_domain_error() (+16 more)

### Community 104 - "mount.rs"
Cohesion: 0.09
Nodes (25): a_template_with_no_mount_path_at_all_is_admitted(), a_template_without_the_automount_label_is_refused(), admit(), an_absent_mount_as_over_a_home_is_refused_too(), an_env_mount_over_a_home_path_is_admitted(), an_ordinary_directory_below_a_home_does_not_shadow(), automountable(), dot_segments_are_resolved_before_the_path_is_judged() (+17 more)

### Community 105 - "runtime-matrix.yaml"
Cohesion: 0.06
Nodes (35): concurrency, cancel-in-progress, group, env, KIND_SHA256, KIND_VERSION, OUT, RUNC_BIN (+27 more)

### Community 106 - "deploy_weebo_si.rs"
Cohesion: 0.14
Nodes (25): api(), dry_apply(), every_feature_is_present_from_stage_zero_and_enforced_by_the_last(), every_policy_template_selects_no_pod_where_it_lives(), every_reference_names_a_template_in_this_directory(), every_stage_resolves_with_no_violation(), every_team_reaches_the_access_keys_the_guide_offers(), install() (+17 more)

### Community 107 - "access.rs"
Cohesion: 0.13
Nodes (15): a_denial_after_a_retry_is_still_a_denial(), a_transient_error_is_retried_not_read_as_a_denial(), an_apiserver_that_never_answers_is_an_error_once_the_budget_is_spent(), an_explicit_denial_is_not_allowed_and_stops_asking(), both_verbs_allowed_is_allowed(), can(), can_patch(), can_watch() (+7 more)

### Community 108 - "Findings"
Cohesion: 0.08
Nodes (24): C1 — Immutable tags, a pinned base, signatures, C2 — A size budget in CI, `che-min-mise` review, Effect on the weebo-si standard, Findings, H1 — Remove the setuid bits nothing needs, H2 — Stop writing `/etc/passwd`: ship `libnss-wrapper` in the base, H3 — Make `/globals` and `/home/tooling` read-only for the user (+16 more)

### Community 109 - "steps"
Cohesion: 0.07
Nodes (34): name, runs-on, steps, timeout-minutes, jobs, build, lint, test (+26 more)

### Community 110 - "admit.rs"
Cohesion: 0.17
Nodes (23): a_denial_in_dry_run_mode_is_recorded_but_never_blocks_admission(), a_denial_in_enforce_mode_short_circuits_admission_and_applies_no_mutation(), admit(), AdmitOutcome, Allow, Deny, AlwaysDenies, AlwaysMutates (+15 more)

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
Cohesion: 0.11
Nodes (31): a_clamped_level_counts_as_clamped_and_applied(), a_second_pass_over_what_it_wrote_is_unchanged_and_writes_nothing(), a_stricter_level_set_by_hand_is_reported_and_left_alone(), config(), dry_run_says_what_it_would_write_and_writes_nothing(), enforce_then_teardown_gives_the_namespace_back_exactly_as_found(), enforce_writes_exactly_the_six_labels_and_the_previous_annotation(), facts() (+23 more)

### Community 115 - "e2e.sh"
Cohesion: 0.15
Nodes (31): addon_argocd(), addon_authentik(), addon_kubearmor(), addons(), build(), cluster_dns(), deploy(), deploy_gateway() (+23 more)

### Community 116 - "tasks"
Cohesion: 0.06
Nodes (32): cmds, desc, task, vars, cmds, desc, cmds, desc (+24 more)

### Community 117 - "workspace_gate.rs"
Cohesion: 0.07
Nodes (36): NamespaceName, BaselineView, FakeBaselineView, an_ordinary_workspace_namespace_is_not_excluded(), CHE_NAMESPACE, ches_namespace_is_excluded_whatever_the_operator_runs_in(), is_excluded_namespace(), operator_ns() (+28 more)

### Community 118 - "weebo-si-network-profiles-adapters/src/controller.rs"
Cohesion: 0.07
Nodes (30): a_change_yields_and_a_rewrite_of_the_same_value_does_not(), config_changes(), CONFIG_POLL, devworkspace_id(), devworkspace_owner(), devworkspace_resource(), held_warnings(), OFF_RECHECK (+22 more)

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
Cohesion: 0.12
Nodes (13): Ecosystem, .ALL, Cargo, Composer, Conda, Go, Maven, Npm (+5 more)

### Community 128 - "feature/registry_config.rs"
Cohesion: 0.28
Nodes (24): ResolvedRegistryConfig, a_granted_key_with_two_sources_produces_two_objects(), a_resolved_key_absent_from_the_catalog_is_a_domain_error(), a_template_shadowing_a_home_directory_is_refused_and_never_copied(), a_template_that_has_not_landed_is_reported_as_not_found_and_not_ready(), a_template_without_the_automount_label_is_refused(), an_ungranted_request_under_deny_writes_nothing_at_all(), an_ungranted_team_gets_nothing_and_is_still_ready() (+16 more)

### Community 129 - "config_file.rs"
Cohesion: 0.12
Nodes (27): a_form_body_encodes_secrets_and_other_bodies_do_not(), a_missing_required_key_is_refused(), an_unknown_key_is_refused(), an_unset_env_reference_fails_the_load(), creds(), DEFAULT_MAX_REPLAYS, env(), every_field_level_rule_is_enforced() (+19 more)

### Community 130 - "spike-0009.sh"
Cohesion: 0.24
Nodes (29): che_namespaces(), controller_service(), fetch(), haproxy_ingresses(), has_header(), has_kind(), have_cluster(), heading() (+21 more)

### Community 131 - "Reason"
Cohesion: 0.08
Nodes (65): a_contested_host_denies_rather_than_picking_a_winner(), a_foreign_bearer_is_refused_unless_the_path_asked_for_it(), a_genuine_preflight_is_allowed_and_the_request_after_it_is_not(), a_host_nothing_answers_for_denies_even_for_the_owner(), a_host_outside_the_governed_suffix_is_never_this_gates_business(), a_named_user_or_group_is_allowed_only_where_the_profile_delegates_that_way(), a_path_the_gate_and_the_application_would_read_differently_is_denied(), a_preflight_is_not_allowed_on_a_host_with_no_single_policy() (+57 more)

### Community 132 - "teams_cmd.rs"
Cohesion: 0.21
Nodes (22): a_configuration_with_no_team_exports_nothing_and_does_not_fail(), a_grant_becomes_the_teams_own_catalogue_minus_the_cluster_floor(), a_grant_naming_a_team_nobody_declared_is_reported_not_silently_dropped(), a_grant_that_only_named_the_cluster_floor_is_not_carried_over(), a_granted_key_the_catalogue_never_declared_is_reported(), a_team_with_no_grant_carries_no_block_for_that_feature(), check(), check_is_clean_when_every_team_is_applied_as_declared() (+14 more)

### Community 133 - "env"
Cohesion: 0.07
Nodes (29): concurrency, cancel-in-progress, group, ENVTEST_K8S_VERSION, ENVTEST_SHA512, KUBEBUILDER_ASSETS, REQUIRE_ENVTEST, TRAEFIK_SHA256 (+21 more)

### Community 134 - "steps"
Cohesion: 0.07
Nodes (29): jobs, semgrep, name, on, pull_request, push, schedule, workflow_dispatch (+21 more)

### Community 135 - "tasks"
Cohesion: 0.07
Nodes (29): cmds, desc, cmds, desc, cmds, desc, cmds, desc (+21 more)

### Community 136 - "GatewayMetrics"
Cohesion: 0.08
Nodes (6): every_label_value_comes_from_a_closed_enum(), GatewayMetrics, TokenShape, Jwt, Opaque, ServiceAccount

### Community 137 - "EnvTest"
Cohesion: 0.12
Nodes (7): assets_dir(), EnvTest, free_port(), generate_service_account_keys(), install_crypto_provider(), STARTUP_TIMEOUT, TEST_TOKEN

### Community 138 - "weebo-si-dwoc-pin/src/resolve.rs"
Cohesion: 0.37
Nodes (18): a_disallowed_workspace_attribute_is_ignored_and_falls_through(), a_team_with_no_grant_falls_back_to_the_synthetic_default_grant(), an_uncatalogued_workspace_attribute_is_ignored_and_falls_through(), an_unknown_annotation_key_under_default_falls_through_to_the_grant_default_and_is_flagged(), an_unknown_annotation_key_under_deny_is_refused(), catalog(), config(), dwoc() (+10 more)

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

### Community 144 - "developer_continuity.rs"
Cohesion: 0.19
Nodes (25): RequestShape, Framed, Navigation, Other, a_colleague_reaches_it_and_a_stranger_does_not(), a_probe_an_uptime_check_or_a_third_party_webhook(), a_session_expiring_mid_task_is_a_401_and_never_a_redirect(), alice() (+17 more)

### Community 145 - "workspace_images.rs"
Cohesion: 0.26
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
Cohesion: 0.07
Nodes (29): Catalogue and grants, `features.dwocPin`, `features.endpointAuth`, `features.identity`, `features.imagePolicy`, `features.imageRewrite`, `features.kubearmorPolicy`, `features.networkProfiles` (+21 more)

### Community 151 - "deny"
Cohesion: 0.07
Nodes (27): name, permissions, runs-on, steps, timeout-minutes, jobs, deny, name (+19 more)

### Community 152 - "weebo-si-resource-quotas/src/application.rs"
Cohesion: 0.10
Nodes (31): OnNotGranted, Default, Deny, a_second_pass_is_unchanged_and_writes_nothing(), an_invalid_profile_keeps_the_existing_ceiling(), an_invalid_profile_on_a_bare_namespace_writes_nothing(), check_catalog_names_the_invalid_profile(), config() (+23 more)

### Community 153 - "openAPIV3Schema"
Cohesion: 0.07
Nodes (26): apiVersion, kind, metadata, name, kind, plural, singular, description (+18 more)

### Community 154 - "weebo-si-registry-config/src/resolve.rs"
Cohesion: 0.24
Nodes (25): RegistryGrant, RegistryKey, a_namespace_annotation_is_a_request_never_a_grant(), a_partially_granted_request_under_deny_names_only_the_ungranted_keys(), a_team_with_no_grant_gets_nothing_rather_than_a_baseline(), an_empty_annotation_means_explicitly_nothing_and_does_not_fall_through(), an_ungranted_request_under_default_falls_back_and_is_flagged(), an_ungranted_request_under_deny_is_refused() (+17 more)

### Community 155 - "weebo-si-kubearmor-policy-adapters/src/controller.rs"
Cohesion: 0.10
Nodes (28): a_namespace_the_index_has_not_seen_is_retried_in_seconds(), a_namespace_the_index_has_seen_keeps_the_slow_recheck(), indexed(), off_recheck(), warn_held(), DefaultPosture, configured_off(), Ctx (+20 more)

### Community 156 - "Applied"
Cohesion: 0.11
Nodes (14): apply_document(), delete(), KubeManagedQuotaStore, KubeQuotaTemplateStore, managed_label(), managed_object(), only_the_management_label_makes_an_object_ours(), spawn_reflector() (+6 more)

### Community 157 - "btreemap"
Cohesion: 0.08
Nodes (20): TargetState, Absent, Adopted, Conflict, Created, Off, TargetStatus, provision() (+12 more)

### Community 158 - "weebo-si-network-profiles-adapters/tests/envtest.rs"
Cohesion: 0.16
Nodes (23): a_leftover_server_pod_from_an_interrupted_run_is_reused(), a_server_pod_that_terminated_is_inconclusive_never_blocked(), a_workspace_with_two_granted_profiles_gets_two_real_objects(), canary_fixture(), CANARY_NAMESPACE, cleanup_is_a_no_op_when_the_probe_never_ran(), cleanup_removes_every_object_the_probe_created(), config() (+15 more)

### Community 159 - "events.rs"
Cohesion: 0.12
Nodes (12): a_devworkspace_reference_carries_its_kind(), DynamicObject, every_reason_is_a_valid_event_reason(), regarding_typed!, ReasonCode, .SUCCESS, reconciled(), recorder() (+4 more)

### Community 160 - "container"
Cohesion: 0.07
Nodes (26): hardening.weebo.io/access, attributes, hardening.weebo.io/image-policy, hardening.weebo.io/network-profiles, components, container, name, cpuLimit (+18 more)

### Community 161 - "package.json"
Cohesion: 0.11
Nodes (25): eslint, eslint-config-next, postcss, tailwindcss, @tailwindcss/postcss, @types/mdx, @types/node, @types/react (+17 more)

### Community 162 - "weebo-si-crd"
Cohesion: 0.34
Nodes (26): endpoint-gateway, weebo-si-chassis, weebo-si-controller, weebo-si-crd, weebo-si-dwoc-pin, weebo-si-endpoint-auth, weebo-si-endpoint-auth-adapters, weebo-si-identity (+18 more)

### Community 163 - "tasks"
Cohesion: 0.08
Nodes (25): cmds, desc, dir, cmds, desc, dir, task, cmds (+17 more)

### Community 164 - "src/config.rs"
Cohesion: 0.10
Nodes (18): BackchannelConfig, CacheConfig, default_backchannel_rate(), default_grant_ttl(), default_host_ttl(), default_identity_entries(), default_identity_ttl(), default_login_rate() (+10 more)

### Community 165 - "endpoint-gateway/values.yaml"
Cohesion: 0.08
Nodes (24): autoscaling, enabled, maxReplicas, minReplicas, targetCPUUtilizationPercentage, imagePullSecrets, metrics, enabled (+16 more)

### Community 166 - "openshift_pod_security_envtest.rs"
Cohesion: 0.10
Nodes (7): auto_observes_on_openshift_and_reports_a_looser_synced_level_without_writing(), feature(), install_scc(), envtest_or_skip!, pass(), scc_crd(), synced_namespace()

### Community 167 - "tests/workspace.rs"
Cohesion: 0.10
Nodes (40): kubectl(), metric_sum(), must(), operator_pods(), set_features(), a_managed_kubearmor_policy_is_guarded_like_a_network_policy(), a_catalogue_entry_pointing_at_nothing_is_refused_under_on_missing_target_deny(), a_chained_rule_set_is_refused_at_write_and_the_previous_rules_stay() (+32 more)

### Community 168 - "versions"
Cohesion: 0.08
Nodes (24): apiVersion, kind, metadata, name, kind, listKind, plural, singular (+16 more)

### Community 169 - "versions"
Cohesion: 0.08
Nodes (24): apiVersion, kind, metadata, name, kind, listKind, plural, singular (+16 more)

### Community 170 - "versions"
Cohesion: 0.08
Nodes (24): apiVersion, kind, metadata, name, kind, listKind, plural, singular (+16 more)

### Community 171 - "Applied"
Cohesion: 0.07
Nodes (27): Applied, tally(), QuotaGrant, QuotaProfileKey, ResolutionStep, GrantDefault, NamespaceAnnotation, TeamGrant (+19 more)

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
Cohesion: 0.14
Nodes (18): serve(), a_flag_missing_its_value_is_refused(), an_unknown_flag_is_refused(), Args, argv(), check_is_a_boolean(), CONFIG, DEFAULT_CONFIG (+10 more)

### Community 179 - "TokenReviewer"
Cohesion: 0.17
Nodes (7): InFlightEntry, namespace_of_review(), Offline, Forged, Undecided, Valid, TokenReviewer

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

### Community 184 - "duration"
Cohesion: 0.08
Nodes (23): kubearmor_policy(), a_build_workspace_builds_an_image_under_its_profile_and_not_under_runtime_default(), build(), build_dwoc(), build_workspace(), BUILDAH, BUSYBOX, ENFORCE (+15 more)

### Community 185 - "kube_provisioner.rs"
Cohesion: 0.14
Nodes (6): ARGO_GROUP, AUTHENTIK_GROUP, FIELD_MANAGER, KubeProvisioner, OWNER_API_VERSION, owner_uid()

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
Cohesion: 0.20
Nodes (28): ProfileGrant, ProfileKey, a_partially_granted_request_under_deny_names_only_the_ungranted_keys(), a_team_with_no_grant_falls_back_to_the_synthetic_empty_grant(), an_empty_workspace_attribute_means_explicitly_nothing_and_does_not_fall_through(), an_ungranted_request_under_default_falls_back_to_the_grant_default_and_is_flagged(), an_ungranted_request_under_deny_is_refused(), catalog() (+20 more)

### Community 197 - "weebo-si-registry-config-adapters/src/controller.rs"
Cohesion: 0.12
Nodes (17): CatalogSnapshot, configured_off(), Ctx, Error, error_policy(), FEATURE, managed_objects_loop(), MANAGED_OBJECTS_TICK (+9 more)

### Community 198 - "spec"
Cohesion: 0.09
Nodes (21): apiVersion, kind, metadata, name, kind, plural, singular, properties (+13 more)

### Community 199 - "feature/image_rewrite.rs"
Cohesion: 0.29
Nodes (14): a_hostile_name_cannot_break_out_of_the_annotation_json(), a_matching_image_is_set_in_place_and_its_original_recorded(), a_write_that_cannot_carry_an_annotation_gets_only_the_image(), an_invalid_rule_set_rewrites_nothing(), evaluate(), every_image_is_counted_once_with_its_result(), feature(), feature_observed() (+6 more)

### Community 200 - "RFC 0004 — network-profiles"
Cohesion: 0.09
Nodes (22): Alternatives considered, Architecture, Changelog, CLI, Contract, Data and state, Design, Drawbacks and risks (+14 more)

### Community 201 - "`spec.features`"
Cohesion: 0.09
Nodes (22): `features.dwocPin`, `features.endpointAuth`, `features.imagePolicy`, `features.kubearmorPolicy`, `features.networkProfiles`, `features.podSecurity`, `features.registryConfig`, `features.resourceQuotas` (+14 more)

### Community 202 - "tasks"
Cohesion: 0.09
Nodes (21): cmds, desc, cmds, desc, cmds, desc, dir, cmds (+13 more)

### Community 203 - "Owner"
Cohesion: 0.33
Nodes (10): Owner, a_foreign_owner_is_ignored_in_favour_of_the_devworkspace(), an_object_with_no_owner_references_reads_back_unowned(), an_owner_round_trips_through_the_shape_this_adapter_writes_and_reads_back(), an_unowned_object_writes_no_owner_references_at_all(), owner(), owner_from_references(), OWNER_KIND (+2 more)

### Community 204 - "Weebo Dev Env - Guideline for the Weebo Dev Env"
Cohesion: 0.10
Nodes (20): Backend, Code, Command, Command output, CRD validation: CEL or `validate()`, Devfile, Doc / Gen / Guideline, Dockerfile / Containerfile (+12 more)

### Community 205 - "TargetState"
Cohesion: 0.25
Nodes (3): every_state_has_a_lowercase_label(), IdentityMetrics, state_label()

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

### Community 211 - "write"
Cohesion: 0.15
Nodes (17): a_host_cookie_may_not_outlive_the_session_it_was_minted_from(), a_suffix_that_governs_too_much_refuses_to_start(), an_unknown_field_is_refused_rather_than_ignored(), carrying_traffic_while_believing_any_callers_address_header_refuses_to_start(), forward_auth_without_a_trusted_proxy_is_warned_about_and_nothing_else_is(), introspection_is_off_by_default_and_remembers_a_refusal_for_half_a_minute(), plain_http_endpoints_for_the_issuer_or_the_callback_refuse_to_start(), the_back_channel_has_a_limit_of_its_own_and_generous_by_default() (+9 more)

### Community 212 - "service"
Cohesion: 0.10
Nodes (20): additionalProperties, properties, type, additionalProperties, properties, type, type, type (+12 more)

### Community 213 - "networkPolicy"
Cohesion: 0.11
Nodes (20): enabled, namespaceSelector, podSelector, cidrs, namespaceSelector, podSelector, ports, k8s-app (+12 more)

### Community 214 - "weebo-si-pod-security-adapters/src/controller.rs"
Cohesion: 0.13
Nodes (18): a_namespace_the_selector_excludes_is_left_once_the_index_knows_it(), an_unloaded_configuration_never_restores_anything(), config(), Ctx, Error, error_policy(), FEATURE, leaving() (+10 more)

### Community 215 - "resource_quotas_envtest.rs"
Cohesion: 0.27
Nodes (16): a_foreign_quota_is_counted_and_survives_teardown(), an_invalid_profile_keeps_the_ceiling_the_namespace_already_has(), config(), create(), create_namespace(), enforce_writes_the_two_objects_and_a_second_pass_is_unchanged(), key(), envtest_or_skip! (+8 more)

### Community 216 - "Contract"
Cohesion: 0.10
Nodes (20): Attaching the gate: one contract, several dialects, Checking that assumption rather than configuring it, Contract, Group claims, and why the cookie only carries some of them, How a host session is minted, HTTP surface, Nothing here is restart-time configuration, Operator-side: mutate, reconcile, guard (+12 more)

### Community 217 - "weebo-si-operator/values.yaml"
Cohesion: 0.11
Nodes (18): imagePolicy, podWebhook, imagePullSecrets, imageRewrite, webhooks, namespace, create, extraLabels (+10 more)

### Community 218 - "TemplateRef"
Cohesion: 0.22
Nodes (6): TemplateRef, policy_bodies_with_different_bytes_are_not_equal(), policy_bodies_with_equal_bytes_are_equal(), PolicyBody, FakeTemplateStore, FakeTemplateStore

### Community 219 - "weebo-si-crd/tests/envtest.rs"
Cohesion: 0.32
Nodes (15): a_well_formed_dwoc_pin_block_is_accepted(), admission_rejects_a_dwoc_pin_block_missing_mode(), an_empty_features_block_is_accepted(), apply_crd(), config(), configs(), DynamicApi, image_rewrite_cel_rules_accept_the_standard_and_refuse_each_mistake() (+7 more)

### Community 220 - "RuntimeBackend"
Cohesion: 0.07
Nodes (19): RuntimeBackend, KubeArmor, a_cluster_with_the_crd_offers_kubearmor(), a_cluster_without_the_crd_offers_nothing(), KubeArmorCapabilities, backend_label_value(), KUBEARMOR_GROUP, KubeArmorTemplateStore (+11 more)

### Community 221 - "network_metrics.rs"
Cohesion: 0.10
Nodes (23): a_reconcile_with_no_team_is_still_counted_under_a_real_label_value(), a_shrinking_population_shrinks_the_gauge(), an_error_is_its_own_result_not_a_missing_increment(), an_ungranted_key_is_counted_per_team_and_profile(), an_update_is_drift_restored_and_a_create_is_not(), dry_run_never_lands_on_a_write_result(), enforce_counts_what_was_applied_under_the_matched_team(), kind_label() (+15 more)

### Community 222 - "node_enforcer.rs"
Cohesion: 0.08
Nodes (16): KUBEARMOR_ENFORCER_LABEL, a_node_naming_its_lsm_is_enforced_and_the_gauge_reads_one(), a_node_with_no_enforcer_label_is_not_enforced_rather_than_unknown(), an_empty_enforcer_label_is_treated_as_no_enforcer(), an_unscheduled_pod_projects_with_no_node_name(), enforcement_from_label(), KubeNodeEnforcerView, PodFacts (+8 more)

### Community 223 - "weebo-si-operator/src/main.rs"
Cohesion: 0.19
Nodes (13): CACHES_NEVER_SYNCED, every_rendered_crd_has_no_unquoted_yaml11_boolean(), INTERNAL, main(), OK, print_crd(), print_features(), quote_yaml11_booleans() (+5 more)

### Community 224 - "plan.rs"
Cohesion: 0.25
Nodes (25): a_bare_namespace_gets_the_six_labels_and_an_empty_previous(), a_foreign_owner_before_the_first_write_is_not_drift(), a_label_changed_by_somebody_else_after_the_first_write_is_drift(), a_looser_existing_level_is_taken_over_and_remembered(), a_stricter_level_somebody_else_set_is_left_alone(), a_stricter_level_this_feature_wrote_is_lowered_when_the_resolution_loosens(), an_equal_level_somebody_else_set_is_taken_over(), an_unreadable_previous_is_kept_as_is_and_reported() (+17 more)

### Community 225 - "endpointAuth"
Cohesion: 0.11
Nodes (19): breakGlassIdentities, default, endpointSelection, hosts, mode, overrides, owner, selfOrigin (+11 more)

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
Cohesion: 0.15
Nodes (15): Mutation, Annotate, SetConfigRef, SetString, a_null_parent_is_replaced_rather_than_written_under(), add(), annotate_adds_the_whole_annotations_map_when_absent(), is_map() (+7 more)

### Community 230 - "GatewayConfig"
Cohesion: 0.13
Nodes (10): ClaimsConfig, default_deny_per_minute(), Enforcement, Enforce, Observe, GatewayConfig, HostsConfig, LoggingConfig (+2 more)

### Community 231 - "properties"
Cohesion: 0.11
Nodes (18): type, additionalProperties, properties, type, enum, type, type, clientId (+10 more)

### Community 232 - "kubearmor_metrics.rs"
Cohesion: 0.09
Nodes (11): KubeArmorPolicyStore, Diff, ManagedObject, delete(), FakePolicyStore, live(), PolicyStore, ReconcileObserver (+3 more)

### Community 233 - "KubeWorkloadIdentity"
Cohesion: 0.15
Nodes (3): KubeWorkloadIdentity, only_a_token_claiming_this_clusters_issuer_and_not_expired_is_worth_a_review(), worth_reviewing()

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
Cohesion: 0.18
Nodes (12): apply(), classify(), FORGED_ADDRESS, only_an_answered_selftest_is_conclusive(), probe_once(), ProbeResult, Clean, Forged (+4 more)

### Community 243 - "Failure"
Cohesion: 0.18
Nodes (12): apply(), Args, config_command(), env_flag(), Failure, Field, Internal, Usage (+4 more)

### Community 244 - "key"
Cohesion: 0.13
Nodes (17): additionalProperties, properties, type, type, minLength, type, clientSecret, existingSecret (+9 more)

### Community 245 - "pods_cmd.rs"
Cohesion: 0.16
Nodes (18): FakeFeatureGate, SINGLETON_NAME, Team, owner_of(), has_flag(), an_unknown_level_is_a_usage_error(), audit(), config() (+10 more)

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

### Community 254 - "fmt"
Cohesion: 0.13
Nodes (12): an_excluded_host_is_not_governed_even_though_it_is_under_the_suffix(), HostError, Empty, NotAHostname, TooLong, MAX_HOST_LEN, one_host_has_one_normal_form(), ScopeError (+4 more)

### Community 255 - "weebo-net-kube-api.yaml"
Cohesion: 0.12
Nodes (15): apiVersion, toEntities, toPorts, matchLabels, kind, hardening.weebo.io/template, hardening.weebo.io/template, metadata (+7 more)

### Community 256 - "Enforcement"
Cohesion: 0.17
Nodes (11): a_workspace_on_a_node_with_an_lsm_is_reported_enforced(), a_workspace_on_a_node_without_one_is_reported_not_enforced_not_absent(), a_workspace_with_no_scheduled_pod_is_unknown_rather_than_a_zero(), observe_enforcement(), an_enforced_node_gauges_one_and_names_its_enforcer(), Enforcement, Enforced, NotEnforced (+3 more)

### Community 257 - "append_locked"
Cohesion: 0.16
Nodes (12): append_locked(), AppendError, Prepare, Write, NameOwner, Uid, Unparseable, Outcome (+4 more)

### Community 258 - "WebhookMetrics"
Cohesion: 0.32
Nodes (4): no_series_exists_until_a_request_is_actually_skipped(), the_two_guard_routes_are_distinguishable_under_one_feature_label(), unguarded_series(), WebhookMetrics

### Community 259 - "found.rs"
Cohesion: 0.33
Nodes (10): a_bare_namespace_is_neither_owned_nor_foreign(), a_foreign_entry_for_a_label_no_longer_present_does_not_count(), a_key_kubectl_set_is_foreign(), an_update_under_this_managers_name_is_not_an_apply(), entry(), found(), keys_applied_by_this_field_manager_are_owned(), namespace() (+2 more)

### Community 260 - "quotas_cmd.rs"
Cohesion: 0.22
Nodes (7): audit(), count(), load(), render(), resources(), run(), usage()

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
Nodes (22): Argo CD, Before you turn it on, Break-glass, Calling an endpoint without a browser, Carrying traffic: the OpenShift shape — deferred, Configuration, `endpoint-gateway`, Exit codes (+14 more)

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

### Community 280 - "weebo-si-resource-quotas/src/resolve.rs"
Cohesion: 0.21
Nodes (18): Resolved, Resolved<C, G, K>, a_namespace_of_no_team_can_only_name_the_cluster_default(), a_namespace_of_no_team_gets_the_cluster_default(), a_team_namespace_gets_the_team_default(), an_empty_annotation_is_no_request(), an_ungranted_key_falls_back_to_the_default_and_is_reported(), an_ungranted_key_under_deny_changes_nothing() (+10 more)

### Community 281 - "flag"
Cohesion: 0.20
Nodes (7): reconcile(), run(), health(), LIVENESS_THRESHOLD, serve(), run(), serve()

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
Cohesion: 0.09
Nodes (11): DomainError, InvalidConfiguration, NamespaceNotObserved, PortFailed, ReconcileFeature, Context, Feature, registry_preserves_declaration_order() (+3 more)

### Community 293 - "try_apply"
Cohesion: 0.19
Nodes (15): apply(), kubectl_with(), repo_root(), try_apply(), a_build_team_gets_baseline_and_a_che_workspace_starts_there(), enforce_refuses_a_privileged_pod_and_off_gives_the_namespace_back(), measure_whether_a_che_workspace_starts_under_restricted(), namespace_object() (+7 more)

### Community 294 - "weebo-si-kubearmor-policy/src/application.rs"
Cohesion: 0.21
Nodes (31): a_second_enforce_pass_with_nothing_changed_reports_unchanged(), a_stale_object_of_the_same_workspace_is_still_deleted(), a_workspace_reconcile_never_deletes_the_baseline_or_a_sibling_workspace_object(), all_templates(), an_unresolved_baseline_template_holds_the_live_baseline_and_still_writes_the_posture(), an_unresolved_baseline_with_no_live_baseline_writes_no_posture(), an_unresolved_profile_template_holds_the_live_profile_object(), config() (+23 more)

### Community 295 - ".spawn"
Cohesion: 0.25
Nodes (3): address_trust_starts_where_the_mode_says_and_a_shared_forgery_wins(), AddressTrust, refresh_service_account_keys()

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

### Community 300 - "CI"
Cohesion: 0.05
Nodes (33): CI, End to end, Known gaps, Per-brick builds, Releases, Report first, gate second, Running the gates locally, Two things CI does that the pre-commit hook cannot (+25 more)

### Community 301 - "Seccomp profiles for workspace nodes"
Cohesion: 0.17
Nodes (12): Container runtimes, How it was measured, Installing on the nodes, Kubernetes, OpenShift, Running containers (Che's container-run mode), Seccomp profiles for workspace nodes, Talos (weebo-si) (+4 more)

### Community 302 - "nodes"
Cohesion: 0.17
Nodes (11): apiVersion, containerPath, hostPath, readOnly, kind, name, nodes, extraMounts (+3 more)

### Community 303 - "Foreign"
Cohesion: 0.22
Nodes (8): BearerConfig, BearerMode, default_introspection_rate(), default_negative_ttl(), Foreign, Passthrough, Reject, IntrospectionConfig

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
Cohesion: 0.20
Nodes (10): podSecurity, namespaceSelection, annotation, namespaceSelection, backend, ceiling, default, mode (+2 more)

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

### Community 319 - "TrustedProxy"
Cohesion: 0.20
Nodes (9): default_client_ip_header(), PodNetwork, Auto, Off, On, SelfOriginConfig, TrustedProxy, Any (+1 more)

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

### Community 325 - "outbound.rs"
Cohesion: 0.31
Nodes (5): a_bundle_with_no_certificate_is_a_refusal_to_start(), a_missing_bundle_is_a_refusal_to_start(), build(), CLIENT, init()

### Community 327 - "TemplateRef"
Cohesion: 0.10
Nodes (19): copy_name(), SourceKind, .ALL, ConfigMap, Secret, the_copy_name_carries_both_the_key_and_the_template_name(), check(), check_entry() (+11 more)

### Community 328 - "defaultPosture"
Cohesion: 0.20
Nodes (10): enabled, intervalSeconds, capabilities, file, network, backend, canary, defaultPosture (+2 more)

### Community 329 - "key"
Cohesion: 0.20
Nodes (10): anonymous, delegation, key, patterns, templateRef, catalog, catalog, catalog (+2 more)

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
Cohesion: 0.19
Nodes (9): `bins/` or `crates/`?, Naming, Repository layout, Shared configuration, Conventions, Getting started, How work happens here, weebo-si-hardening (+1 more)

### Community 350 - "`kubearmor-policy`"
Cohesion: 0.22
Nodes (9): Install checklist, Known limitations, specific to this feature, `kubearmor-policy`, Observability, Reading the logs, Rollback, Rollout, What gets written (+1 more)

### Community 351 - "`pod-security`"
Cohesion: 0.22
Nodes (9): Install checklist, Known limitations, specific to this feature, Observability, OpenShift, `pod-security`, Reading the logs, Rollback, Rollout (+1 more)

### Community 352 - "`resource-quotas`"
Cohesion: 0.22
Nodes (9): Install checklist, Known limitations, specific to this feature, Observability, Reading the logs, `resource-quotas`, Rollback, Rollout, What a profile must satisfy (+1 more)

### Community 353 - "ReviewError"
Cohesion: 0.33
Nodes (4): kube::Error, ReviewError, NoStatus, Request

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

### Community 370 - "registryConfig"
Cohesion: 0.25
Nodes (8): ecosystem, sources, registryConfig, catalog, mode, namespaceSelection, namespaceSelector, onNotGranted

### Community 371 - "kubearmorPolicy"
Cohesion: 0.22
Nodes (9): kubearmorPolicy, workspaceSelection, baseline, mode, namespaceSelection, onNotGranted, workspaceSelection, workspaceSelection (+1 more)

### Community 372 - "matchLabels"
Cohesion: 0.14
Nodes (14): imageRewrite, policyGuard, mode, namespaceSelector, rules, namespaceSelector, hardening.weebo.io/workspace-namespace, matchLabels (+6 more)

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

### Community 384 - "ConfigError"
Cohesion: 0.33
Nodes (4): ConfigError, Invalid, Unparseable, Unreadable

### Community 385 - "RevalidationMode"
Cohesion: 0.29
Nodes (6): default_revalidation(), RevalidationConfig, RevalidationMode, Always, Never, WhenNoBackchannel

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

### Community 390 - "text"
Cohesion: 0.13
Nodes (31): Cleanup, stays(), team(), text(), wait_until(), payments_team(), a_group_outside_the_allow_list_refuses_the_whole_person_and_writes_nothing(), a_person_becomes_a_real_authentik_account_in_their_teams_groups_and_leaves_with_their_object() (+23 more)

### Community 391 - "cspell.json"
Cohesion: 0.29
Nodes (6): ignorePaths, ignoreWords, language, $schema, version, words

### Community 392 - "networkProfiles"
Cohesion: 0.29
Nodes (7): variants, networkProfiles, baseline, catalog, mode, namespaceSelector, onNotGranted

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

### Community 400 - "OnUnknownKey"
Cohesion: 0.33
Nodes (5): default_max_rules(), OnUnknownKey, Default, Deny, RulesConfig

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

### Community 419 - "resourceQuotas"
Cohesion: 0.40
Nodes (5): resourceQuotas, rbac, templateNamespace, create, name

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

### Community 485 - "streamext"
Cohesion: 0.29
Nodes (5): drive(), drive_consumes_every_item_and_survives_errors(), HEALTH, report(), report_to()

### Community 486 - "teardown.rs"
Cohesion: 0.33
Nodes (8): CONTROLLER_MANAGER, GARBAGE_COLLECTOR, is_teardown_identity(), nobody_else_is_let_through(), TEARDOWN_IDENTITIES, teardown_may(), the_garbage_collector_may_orphan_as_well_as_delete(), the_namespace_controller_may_delete_but_never_update()

### Community 488 - "NamespaceFacts"
Cohesion: 0.14
Nodes (5): Context<'a>, context_exposes_teams_namespace_and_catalog_and_nothing_else(), NamespaceFacts, FakeNamespaceView, NamespaceView

### Community 490 - "NetworkProfilesConfigViolation"
Cohesion: 0.15
Nodes (11): is_valid_profile_key(), NetworkProfilesConfigViolation, BaselineNotInCatalog, CatalogKeyConflict, DuplicateProfileKey, GrantAllowedUnknownKey, GrantDefaultOutsideAllowed, GrantNamesUndeclaredTeam (+3 more)

### Community 502 - "rfc5_stack"
Cohesion: 0.28
Nodes (14): a_devworkspace_naming_a_granted_image_is_admitted(), a_devworkspace_naming_an_ungranted_image_is_refused_with_a_readable_message(), a_namespace_without_the_workspace_label_is_out_of_the_pod_rules_scope(), a_platform_image_is_admitted_at_the_pod_layer_whatever_the_grant_says(), a_pod_naming_an_ungranted_image_is_refused_at_the_floor(), an_ephemeral_debug_container_is_refused_through_its_own_subresource(), an_unparseable_reference_is_refused_rather_than_passed_through(), devworkspace_with_image() (+6 more)

### Community 503 - "Verdict"
Cohesion: 0.25
Nodes (5): Verdict, Applied, Differs, Extra, Missing

### Community 509 - "arc"
Cohesion: 0.12
Nodes (13): ControllerShared, run(), an_invalid_rule_set_is_degraded_and_reaches_the_conditions(), Ctx, degraded_status(), Error, error_policy(), image_rewrite_status() (+5 more)

### Community 514 - "flag"
Cohesion: 0.35
Nodes (9): DEFAULT_CANARY_IMAGE, DEFAULT_NAMESPACE, run(), argv(), flag(), flag_does_not_match_a_longer_flag_sharing_its_prefix(), flag_is_none_when_absent_or_valueless(), flag_reads_the_equals_form_the_chart_renders() (+1 more)

### Community 515 - "`image-rewrite`"
Cohesion: 0.20
Nodes (10): Configure it, GitOps, How it works, `image-rewrite`, Moving a mirror, Operate it, Private upstream images, Roll it out (+2 more)

### Community 522 - "`passwd-append`"
Cohesion: 0.20
Nodes (9): Adopting it, Case 1 — an entrypoint you do not own (che-code, `WeeboDevImage`), Case 2 — an entrypoint you do own, Exit codes, `passwd-append`, Reading the logs, Things it will not do, Usage (+1 more)

### Community 525 - "Floor"
Cohesion: 0.33
Nodes (6): FEATURES, Floor, Baseline, Default, DefaultList, None

## Knowledge Gaps
- **455 isolated node(s):** `Team`, `UsersAndGroups`, `Unreadable`, `Observe`, `Enforce` (+450 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 4164 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **83 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `NamespaceName` connect `workspace_gate.rs` to `compute_diff`, `Enforcement`, `feature/registry_config.rs`, `config_store.rs`, `TeamName`, `TemplateRef`, `kube_policy_store.rs`, `workspace_images.rs`, `weebo-si-resource-quotas-adapters/src/controller.rs`, `weebo-si-endpoint-auth-adapters/src/endpoint_auth.rs`, `pod_images.rs`, `weebo-si-resource-quotas/src/application.rs`, `weebo-si-kubearmor-policy-adapters/src/controller.rs`, `Applied`, `PodSelector`, `DomainError`, `weebo-si-policy-guard-adapters/src/policy_guard.rs`, `super`, `weebo-si-endpoint-auth-adapters/src/controller.rs`, `src/network_profiles.rs`, `weebo-si-kubearmor-policy/src/application.rs`, `openshift_pod_security_envtest.rs`, `arc`, `pod_security_metrics.rs`, `guard.rs`, `core.rs`, `FeatureId`, `Applied`, `registry_object_store.rs`, `weebo-si-network-profiles/src/application.rs`, `router.rs`, `namespace_label_store.rs`, `webhook_cmd.rs`, `feature.rs`, `perf_envtest.rs`, `endpoint_routing.rs`, `weebo-si-registry-config-adapters/src/controller.rs`, `quota_metrics.rs`, `images_cmd.rs`, `variable.rs`, `feature/kubearmor_policy.rs`, `weebo-si-pod-security-adapters/src/controller.rs`, `TemplateRef`, `registry_metrics.rs`, `Decision`, `node_enforcer.rs`, `feature/network_profiles.rs`, `NamespaceFacts`, `kubearmor_metrics.rs`, `admit.rs`, `weebo-si-pod-security/src/application.rs`, `pods_cmd.rs`, `weebo-si-network-profiles-adapters/src/controller.rs`, `weebo-si-registry-config/src/application.rs`, `feature/pod_security.rs`?**
  _High betweenness centrality (0.020) - this node is a cross-community bridge._
- **What connects `Team`, `UsersAndGroups`, `Unreadable` to the rest of the system?**
  _455 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `compute_diff` be split into smaller, more focused modules?**
  _Cohesion score 0.04514533085961658 - nodes in this community are weakly interconnected._
- **Why does `template` connect `endpointAuth` to `feature/registry_config.rs`, `weebo-si-crd/src/identity.rs`, `Applied`?**
  _High betweenness centrality (0.014) - this node is a cross-community bridge._
- **Should `kube_catalog.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.043239533287577216 - nodes in this community are weakly interconnected._
- **Should `weebo-si-endpoint-auth/src/application.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.03457172342621259 - nodes in this community are weakly interconnected._
- **Should `http.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.0440897597977244 - nodes in this community are weakly interconnected._