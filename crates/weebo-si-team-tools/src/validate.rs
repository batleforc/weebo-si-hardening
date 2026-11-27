//! The validation table — RFC 0020, *Validation*, every `validate()` row, plus the checks the
//! CRD leaves here (`default` within `allowed`, `issuerRef` when an allowed entry has `tls`,
//! `clientDuration`). An invalid entry or team block is reported `Degraded`; what it already
//! rendered is kept.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde_json::Value;
use weebo_si_crd::{
    NamespaceName, TeamTeamTools, ToolEntry, ToolKey, ToolTemplateRef, WorkloadKind,
};

use crate::port::{ToolTemplate, ToolTemplateStore};

/// The kinds a tool template may be.
pub const TOOL_KINDS: [&str; 5] = [
    "Deployment",
    "StatefulSet",
    "Service",
    "ConfigMap",
    "CiliumNetworkPolicy",
];
/// The kinds a requester template may be.
pub const REQUESTER_KINDS: [&str; 1] = ["ConfigMap"];
/// The prefix of every generated object name; no template may use it.
pub const GENERATED_PREFIX: &str = "weebo-team-tool-";
/// The name prefixes of the objects Kubernetes and OpenShift put in every namespace
/// (`kube-root-ca.crt`, `openshift-service-ca.crt`): adoption would take them over.
pub const SYSTEM_PREFIXES: [&str; 2] = ["kube-", "openshift-"];
/// cert-manager refuses a `Certificate` shorter than this.
pub const MIN_CLIENT_DURATION: Duration = Duration::from_secs(3600);

/// What is wrong with a workload template's pod spec (RFC 0020, T4 and E1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodSpecViolation {
    /// `automountServiceAccountToken` is not `false`.
    TokenAutomounted,
    /// A projected volume carries a `serviceAccountToken` source.
    ProjectedToken(String),
    /// `serviceAccountName` is neither absent nor `default`.
    ServiceAccount(String),
    /// A container is `privileged: true`.
    Privileged(String),
    /// A container adds capabilities.
    CapabilitiesAdded(String),
    /// `hostNetwork: true`.
    HostNetwork,
    /// `hostPID: true`.
    HostPid,
    /// `hostIPC: true`.
    HostIpc,
    /// A container port sets `hostPort`.
    HostPort(String),
    /// A `hostPath` volume.
    HostPath(String),
    /// `runtimeClassName` is not in the chart's `teamTools.allowedRuntimeClasses`.
    RuntimeClass(String),
}

impl fmt::Display for PodSpecViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenAutomounted => f.write_str("automountServiceAccountToken must be false"),
            Self::ProjectedToken(volume) => {
                write!(f, "volume {volume:?} projects a service-account token")
            }
            Self::ServiceAccount(name) => write!(
                f,
                "serviceAccountName {name:?} is not allowed (absent or default only)"
            ),
            Self::Privileged(container) => write!(f, "container {container:?} is privileged"),
            Self::CapabilitiesAdded(container) => {
                write!(f, "container {container:?} adds capabilities")
            }
            Self::HostNetwork => f.write_str("hostNetwork is set"),
            Self::HostPid => f.write_str("hostPID is set"),
            Self::HostIpc => f.write_str("hostIPC is set"),
            Self::HostPort(container) => write!(f, "container {container:?} sets a hostPort"),
            Self::HostPath(volume) => write!(f, "volume {volume:?} is a hostPath"),
            Self::RuntimeClass(name) => write!(
                f,
                "runtimeClassName {name:?} is not in teamTools.allowedRuntimeClasses"
            ),
        }
    }
}

/// What is wrong with a catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryViolation {
    /// The template does not exist, or is not in the cache yet.
    TemplateMissing(ToolTemplateRef),
    /// The template is not in the template namespace.
    TemplateOutsideNamespace(ToolTemplateRef),
    /// A tool template of a kind outside [`TOOL_KINDS`].
    ToolKindNotAllowed(ToolTemplateRef),
    /// A requester template of a kind outside [`REQUESTER_KINDS`].
    RequesterKindNotAllowed(ToolTemplateRef),
    /// `workload` is not the one `Deployment`/`StatefulSet` among the tool templates.
    WorkloadNotAmongTemplates,
    /// The workload template does not write `spec.replicas: 0`.
    WorkloadReplicasNotZero,
    /// The workload's `spec.selector` is not a non-empty `matchLabels` alone: the policies select
    /// by those labels, and would otherwise reach wider than the workload.
    WorkloadSelectorNotLabels,
    /// The template's name starts with `weebo-team-tool-`, the generated objects' prefix.
    TemplateNameReserved(ToolTemplateRef),
    /// The template's name starts with one of [`SYSTEM_PREFIXES`].
    TemplateNameSystem(ToolTemplateRef),
    /// Another catalogue entry names the same template: two keys would own one object.
    TemplateShared(ToolTemplateRef),
    /// The workload's pod spec.
    PodSpec(PodSpecViolation),
    /// `service.name` is not a `Service` among the tool templates.
    ServiceNotAmongTemplates,
    /// `service.port` is not a port of the `Service` template.
    ServicePortMissing(u16),
    /// `tls.clientDuration` is not a duration of at least one hour.
    ClientDuration(String),
    /// The template sets `immutable: true`: every later template update would fail.
    TemplateImmutable(ToolTemplateRef),
    /// The workload's `persistentVolumeClaimRetentionPolicy.whenDeleted` is `Delete`: the cache
    /// PVC must outlive the StatefulSet.
    WorkloadDeletesClaims,
}

fn template(r: &ToolTemplateRef) -> String {
    format!("{}/{} in {}", r.kind, r.name, r.namespace)
}

impl fmt::Display for EntryViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TemplateMissing(r) => write!(f, "template {} does not exist", template(r)),
            Self::TemplateOutsideNamespace(r) => write!(
                f,
                "template {} is not in the template namespace",
                template(r)
            ),
            Self::ToolKindNotAllowed(r) => write!(
                f,
                "tool template {} is not one of {}",
                template(r),
                TOOL_KINDS.join(", ")
            ),
            Self::RequesterKindNotAllowed(r) => {
                write!(f, "requester template {} is not a ConfigMap", template(r))
            }
            Self::WorkloadNotAmongTemplates => f.write_str(
                "workload must name the only Deployment or StatefulSet among the tool templates",
            ),
            Self::WorkloadReplicasNotZero => {
                f.write_str("the workload template must write spec.replicas: 0")
            }
            Self::WorkloadSelectorNotLabels => f.write_str(
                "the workload template's spec.selector must be a non-empty matchLabels alone",
            ),
            Self::TemplateNameReserved(r) => write!(
                f,
                "template {} uses the reserved prefix {GENERATED_PREFIX}",
                template(r)
            ),
            Self::TemplateNameSystem(r) => write!(
                f,
                "template {} uses a system prefix ({})",
                template(r),
                SYSTEM_PREFIXES.join(", ")
            ),
            Self::TemplateShared(r) => write!(
                f,
                "template {} is also named by another catalog entry",
                template(r)
            ),
            Self::PodSpec(violation) => write!(f, "workload pod spec: {violation}"),
            Self::ServiceNotAmongTemplates => {
                f.write_str("service.name must name a Service among the tool templates")
            }
            Self::ServicePortMissing(port) => {
                write!(
                    f,
                    "service.port {port} is not a port of the Service template"
                )
            }
            Self::ClientDuration(raw) => write!(
                f,
                "tls.clientDuration {raw:?} is not a duration of at least 1h (h, m, s, ms units)"
            ),
            Self::TemplateImmutable(r) => {
                write!(f, "template {} must not be immutable", template(r))
            }
            Self::WorkloadDeletesClaims => f.write_str(
                "the workload template's persistentVolumeClaimRetentionPolicy.whenDeleted must not be Delete",
            ),
        }
    }
}

/// What is wrong with a team block. The whole block is ignored (RFC 0020, *Validation*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeamViolation {
    /// An `allowed` or `default` key is not in the catalogue.
    UnknownKey(ToolKey),
    /// A `default` key is not in `allowed`.
    DefaultNotAllowed(ToolKey),
    /// An allowed entry has `tls` and the team has no `issuerRef`.
    IssuerRefRequired(ToolKey),
}

impl fmt::Display for TeamViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(key) => write!(f, "team tool {key} is not in the catalog"),
            Self::DefaultNotAllowed(key) => {
                write!(f, "default team tool {key} is not in allowed")
            }
            Self::IssuerRefRequired(key) => {
                write!(f, "team tool {key} uses tls: issuerRef is required")
            }
        }
    }
}

/// The port the policies open: the `Service` port's `targetPort` (a number or a container port
/// name, both of which Cilium accepts), or the port itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPort {
    /// `toPorts[].ports[].port`.
    pub port: String,
    /// `toPorts[].ports[].protocol`.
    pub protocol: String,
}

/// An entry that passed every row, with what the render needs.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidEntry {
    /// The entry.
    pub entry: ToolEntry,
    /// The tool templates, in order.
    pub tools: Vec<ToolTemplate>,
    /// The requester templates, in order.
    pub requesters: Vec<ToolTemplate>,
    /// The workload's `spec.selector.matchLabels`: the tool's pods.
    pub pod_labels: BTreeMap<String, String>,
    /// The port the ingress and egress policies open.
    pub port: PolicyPort,
}

fn kind_str(kind: WorkloadKind) -> &'static str {
    match kind {
        WorkloadKind::Deployment => "Deployment",
        WorkloadKind::StatefulSet => "StatefulSet",
    }
}

/// Parse a Go-style duration made of integer `h`, `m`, `s` and `ms` parts (`24h`, `1h30m`).
/// Fractions and the sub-millisecond units are refused: a certificate lifetime never needs them.
pub fn parse_duration(raw: &str) -> Option<Duration> {
    let mut rest = raw;
    let mut total = Duration::ZERO;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (number, tail) = rest.split_at(digits);
        let unit_len = tail
            .find(|c: char| !c.is_ascii_lowercase())
            .unwrap_or(tail.len());
        let (unit, tail) = tail.split_at(unit_len);
        let value: u64 = number.parse().ok()?;
        let part = match unit {
            "h" => Duration::from_secs(value.checked_mul(3600)?),
            "m" => Duration::from_secs(value.checked_mul(60)?),
            "s" => Duration::from_secs(value),
            "ms" => Duration::from_millis(value),
            _ => return None,
        };
        total = total.checked_add(part)?;
        rest = tail;
    }
    Some(total)
}

fn bool_at(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool) == Some(true)
}

fn name_of(value: &Value) -> String {
    value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn items<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// Every refused field of a pod spec (`spec.template.spec` of the workload).
pub fn pod_spec_violations(
    spec: &Value,
    allowed_runtime_classes: &[String],
) -> Vec<PodSpecViolation> {
    let mut found = Vec::new();
    if spec
        .get("automountServiceAccountToken")
        .and_then(Value::as_bool)
        != Some(false)
    {
        found.push(PodSpecViolation::TokenAutomounted);
    }
    for key in ["serviceAccountName", "serviceAccount"] {
        if let Some(name) = spec.get(key).and_then(Value::as_str)
            && !name.is_empty()
            && name != "default"
        {
            found.push(PodSpecViolation::ServiceAccount(name.to_string()));
        }
    }
    for (key, violation) in [
        ("hostNetwork", PodSpecViolation::HostNetwork),
        ("hostPID", PodSpecViolation::HostPid),
        ("hostIPC", PodSpecViolation::HostIpc),
    ] {
        if bool_at(spec, key) {
            found.push(violation);
        }
    }
    if let Some(class) = spec.get("runtimeClassName").and_then(Value::as_str)
        && !allowed_runtime_classes
            .iter()
            .any(|allowed| allowed == class)
    {
        found.push(PodSpecViolation::RuntimeClass(class.to_string()));
    }
    for volume in items(spec, "volumes") {
        if volume.get("hostPath").is_some() {
            found.push(PodSpecViolation::HostPath(name_of(volume)));
        }
        let projects_token = volume
            .get("projected")
            .map(|projected| {
                items(projected, "sources").any(|s| s.get("serviceAccountToken").is_some())
            })
            .unwrap_or(false);
        if projects_token {
            found.push(PodSpecViolation::ProjectedToken(name_of(volume)));
        }
    }
    for container in ["containers", "initContainers", "ephemeralContainers"]
        .into_iter()
        .flat_map(|key| items(spec, key))
    {
        let name = name_of(container);
        let context = container.get("securityContext");
        if context.is_some_and(|context| bool_at(context, "privileged")) {
            found.push(PodSpecViolation::Privileged(name.clone()));
        }
        let adds = context
            .and_then(|context| context.pointer("/capabilities/add"))
            .and_then(Value::as_array)
            .is_some_and(|add| !add.is_empty());
        if adds {
            found.push(PodSpecViolation::CapabilitiesAdded(name.clone()));
        }
        let host_port = items(container, "ports").any(|port| {
            port.get("hostPort")
                .is_some_and(|host| host.as_i64() != Some(0))
        });
        if host_port {
            found.push(PodSpecViolation::HostPort(name));
        }
    }
    found
}

/// Fetch every template, keeping those whose ref passes; record why the others fail.
#[expect(
    clippy::too_many_arguments,
    reason = "a private helper called twice, with the same arguments named at each call"
)]
fn fetch(
    key: &ToolKey,
    catalog: &[ToolEntry],
    refs: &[ToolTemplateRef],
    allowed: &[&str],
    store: &dyn ToolTemplateStore,
    template_namespace: &NamespaceName,
    wrong_kind: fn(ToolTemplateRef) -> EntryViolation,
    violations: &mut Vec<EntryViolation>,
) -> Vec<ToolTemplate> {
    let mut found = Vec::new();
    for r in refs {
        let shared = catalog.iter().any(|other| {
            &other.key != key
                && other
                    .tool_templates
                    .iter()
                    .chain(&other.requester_templates)
                    .any(|o| o.kind == r.kind && o.name == r.name)
        });
        if &r.namespace != template_namespace {
            violations.push(EntryViolation::TemplateOutsideNamespace(r.clone()));
        } else if r.name.starts_with(GENERATED_PREFIX) {
            violations.push(EntryViolation::TemplateNameReserved(r.clone()));
        } else if SYSTEM_PREFIXES.iter().any(|p| r.name.starts_with(p)) {
            violations.push(EntryViolation::TemplateNameSystem(r.clone()));
        } else if shared {
            violations.push(EntryViolation::TemplateShared(r.clone()));
        } else if !allowed.contains(&r.kind.as_str()) {
            violations.push(wrong_kind(r.clone()));
        } else if let Some(template) = store.template(r) {
            if bool_at(&template.body, "immutable") {
                violations.push(EntryViolation::TemplateImmutable(r.clone()));
            }
            found.push(template);
        } else {
            violations.push(EntryViolation::TemplateMissing(r.clone()));
        }
    }
    found
}

/// Check one catalogue entry, against the rest of `catalog` and the live templates.
pub fn validate_entry(
    entry: &ToolEntry,
    catalog: &[ToolEntry],
    store: &dyn ToolTemplateStore,
    template_namespace: &NamespaceName,
    allowed_runtime_classes: &[String],
) -> Result<ValidEntry, Vec<EntryViolation>> {
    let mut violations = Vec::new();
    let tools = fetch(
        &entry.key,
        catalog,
        &entry.tool_templates,
        &TOOL_KINDS,
        store,
        template_namespace,
        EntryViolation::ToolKindNotAllowed,
        &mut violations,
    );
    let requesters = fetch(
        &entry.key,
        catalog,
        &entry.requester_templates,
        &REQUESTER_KINDS,
        store,
        template_namespace,
        EntryViolation::RequesterKindNotAllowed,
        &mut violations,
    );

    let workload_kind = kind_str(entry.workload.kind);
    let workloads: Vec<&ToolTemplateRef> = entry
        .tool_templates
        .iter()
        .filter(|r| r.kind == "Deployment" || r.kind == "StatefulSet")
        .collect();
    let named = matches!(workloads.as_slice(), [only] if only.kind == workload_kind && only.name == entry.workload.name);
    let mut pod_labels = BTreeMap::new();
    if !named {
        violations.push(EntryViolation::WorkloadNotAmongTemplates);
    } else if let Some(workload) = tools
        .iter()
        .find(|t| t.kind == workload_kind && t.name == entry.workload.name)
    {
        if workload
            .body
            .pointer("/spec/replicas")
            .and_then(Value::as_i64)
            != Some(0)
        {
            violations.push(EntryViolation::WorkloadReplicasNotZero);
        }
        if workload
            .body
            .pointer("/spec/persistentVolumeClaimRetentionPolicy/whenDeleted")
            .and_then(Value::as_str)
            == Some("Delete")
        {
            violations.push(EntryViolation::WorkloadDeletesClaims);
        }
        pod_labels = workload
            .body
            .pointer("/spec/selector/matchLabels")
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let expressions = workload
            .body
            .pointer("/spec/selector/matchExpressions")
            .and_then(Value::as_array)
            .is_some_and(|e| !e.is_empty());
        if pod_labels.is_empty() || expressions {
            violations.push(EntryViolation::WorkloadSelectorNotLabels);
        }
        let spec = workload
            .body
            .pointer("/spec/template/spec")
            .unwrap_or(&Value::Null);
        violations.extend(
            pod_spec_violations(spec, allowed_runtime_classes)
                .into_iter()
                .map(EntryViolation::PodSpec),
        );
    }

    let mut port = None;
    if !entry
        .tool_templates
        .iter()
        .any(|r| r.kind == "Service" && r.name == entry.service.name)
    {
        violations.push(EntryViolation::ServiceNotAmongTemplates);
    } else if let Some(service) = tools
        .iter()
        .find(|t| t.kind == "Service" && t.name == entry.service.name)
    {
        port = items(&service.body["spec"], "ports")
            .find(|p| p.get("port").and_then(Value::as_u64) == Some(u64::from(entry.service.port)))
            .map(|p| PolicyPort {
                port: match p.get("targetPort") {
                    Some(Value::String(name)) => name.clone(),
                    Some(Value::Number(number)) => number.to_string(),
                    _ => entry.service.port.to_string(),
                },
                protocol: p
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("TCP")
                    .to_string(),
            });
        if port.is_none() {
            violations.push(EntryViolation::ServicePortMissing(entry.service.port));
        }
    }

    if let Some(tls) = &entry.tls
        && parse_duration(&tls.client_duration).is_none_or(|d| d < MIN_CLIENT_DURATION)
    {
        violations.push(EntryViolation::ClientDuration(tls.client_duration.clone()));
    }

    match port {
        Some(port) if violations.is_empty() => Ok(ValidEntry {
            entry: entry.clone(),
            tools,
            requesters,
            pod_labels,
            port,
        }),
        _ => Err(violations),
    }
}

/// Check one team block against the catalogue.
pub fn validate_team(grant: &TeamTeamTools, catalog: &[ToolEntry]) -> Vec<TeamViolation> {
    let entry = |key: &ToolKey| catalog.iter().find(|entry| &entry.key == key);
    let mut found = Vec::new();
    for key in &grant.allowed {
        match entry(key) {
            None => found.push(TeamViolation::UnknownKey(key.clone())),
            Some(entry) if entry.tls.is_some() && grant.issuer_ref.is_none() => {
                found.push(TeamViolation::IssuerRefRequired(key.clone()));
            }
            Some(_) => {}
        }
    }
    for key in &grant.default {
        if !grant.allowed.contains(key) {
            found.push(TeamViolation::DefaultNotAllowed(key.clone()));
        }
    }
    found
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::ToolIssuerRef;

    use super::*;
    use crate::fixtures::{TEMPLATE_NS, buildkit_entry, grant, keys, store, store_with};

    fn check(
        entry: &ToolEntry,
        store: &dyn ToolTemplateStore,
    ) -> Result<ValidEntry, Vec<EntryViolation>> {
        validate_entry(
            entry,
            &[],
            store,
            &NamespaceName::new(TEMPLATE_NS),
            &["gvisor".to_string()],
        )
    }

    /// The violations of the buildkit entry once `edit` changed its workload's pod spec.
    fn pod(mut edit: impl FnMut(&mut Value)) -> Vec<EntryViolation> {
        let store = store_with(|kind, body| {
            if kind == "StatefulSet" {
                edit(body.pointer_mut("/spec/template/spec").unwrap());
            }
        });
        check(&buildkit_entry(), &store).unwrap_err()
    }

    #[test]
    fn the_reference_entry_is_valid() {
        let valid = check(&buildkit_entry(), &store()).unwrap();
        assert_eq!(valid.tools.len(), 4);
        assert_eq!(valid.requesters.len(), 1);
        assert_eq!(valid.port.port, "1234");
        assert_eq!(valid.pod_labels["app"], "buildkitd");
    }

    #[test]
    fn a_missing_template_is_invalid() {
        let mut entry = buildkit_entry();
        entry.tool_templates[2].name = "absent".to_string();
        assert!(matches!(
            check(&entry, &store()).unwrap_err().as_slice(),
            [EntryViolation::TemplateMissing(_)]
        ));
    }

    #[test]
    fn a_template_outside_the_template_namespace_is_invalid() {
        let mut entry = buildkit_entry();
        entry.tool_templates[2].namespace = NamespaceName::new("kube-system");
        assert!(matches!(
            check(&entry, &store()).unwrap_err().as_slice(),
            [EntryViolation::TemplateOutsideNamespace(_)]
        ));
    }

    #[test]
    fn a_tool_or_requester_kind_outside_the_list_is_invalid() {
        let mut entry = buildkit_entry();
        entry.tool_templates[2].kind = "Secret".to_string();
        entry.requester_templates[0].kind = "Service".to_string();
        let violations = check(&entry, &store()).unwrap_err();
        assert!(matches!(
            violations.as_slice(),
            [
                EntryViolation::ToolKindNotAllowed(_),
                EntryViolation::RequesterKindNotAllowed(_)
            ]
        ));
    }

    #[test]
    fn the_workload_must_be_the_only_one_among_the_templates() {
        let mut entry = buildkit_entry();
        entry.workload.name = "other".to_string();
        assert_eq!(
            check(&entry, &store()).unwrap_err(),
            vec![EntryViolation::WorkloadNotAmongTemplates]
        );
        let mut entry = buildkit_entry();
        entry.workload.kind = WorkloadKind::Deployment;
        assert_eq!(
            check(&entry, &store()).unwrap_err(),
            vec![EntryViolation::WorkloadNotAmongTemplates]
        );
        let mut entry = buildkit_entry();
        let mut second = entry.tool_templates[0].clone();
        second.kind = "Deployment".to_string();
        entry.tool_templates.push(second);
        assert!(
            check(&entry, &store())
                .unwrap_err()
                .contains(&EntryViolation::WorkloadNotAmongTemplates)
        );
    }

    #[test]
    fn replicas_must_be_written_as_zero() {
        for replicas in [None, Some(1)] {
            let store = store_with(|kind, body| {
                if kind == "StatefulSet" {
                    let spec = body["spec"].as_object_mut().unwrap();
                    match replicas {
                        None => spec.remove("replicas"),
                        Some(n) => spec.insert("replicas".to_string(), n.into()),
                    };
                }
            });
            assert_eq!(
                check(&buildkit_entry(), &store).unwrap_err(),
                vec![EntryViolation::WorkloadReplicasNotZero]
            );
        }
    }

    #[test]
    fn a_selector_must_be_match_labels_alone() {
        for selector in [
            serde_json::json!({"matchExpressions": []}),
            serde_json::json!({"matchLabels": {"app": "buildkitd"}, "matchExpressions": [
                {"key": "tier", "operator": "In", "values": ["daemon"]}
            ]}),
        ] {
            let store = store_with(|kind, body| {
                if kind == "StatefulSet" {
                    body["spec"]["selector"] = selector.clone();
                }
            });
            assert_eq!(
                check(&buildkit_entry(), &store).unwrap_err(),
                vec![EntryViolation::WorkloadSelectorNotLabels]
            );
        }
    }

    #[test]
    fn a_template_name_is_reserved_or_owned_by_one_entry() {
        let mut entry = buildkit_entry();
        entry.requester_templates[0].name = "weebo-team-tool-buildkit".to_string();
        assert!(matches!(
            check(&entry, &store()).unwrap_err().as_slice(),
            [EntryViolation::TemplateNameReserved(_)]
        ));
        let mut other = buildkit_entry();
        other.key = ToolKey::new("buildkit-2");
        let catalog = [buildkit_entry(), other];
        let violations = validate_entry(
            &catalog[0],
            &catalog,
            &store(),
            &NamespaceName::new(TEMPLATE_NS),
            &[],
        )
        .unwrap_err();
        assert_eq!(violations.len(), 5);
        assert!(
            violations
                .iter()
                .all(|v| matches!(v, EntryViolation::TemplateShared(_)))
        );
    }

    #[test]
    fn an_immutable_template_is_invalid() {
        let store = store_with(|kind, body| {
            if kind == "ConfigMap" {
                body["immutable"] = true.into();
            }
        });
        let violations = check(&buildkit_entry(), &store).unwrap_err();
        assert_eq!(violations.len(), 2);
        assert!(
            violations
                .iter()
                .all(|v| matches!(v, EntryViolation::TemplateImmutable(_)))
        );
    }

    #[test]
    fn a_workload_deleting_its_claims_is_invalid() {
        let store = store_with(|kind, body| {
            if kind == "StatefulSet" {
                body["spec"]["persistentVolumeClaimRetentionPolicy"] =
                    serde_json::json!({"whenDeleted": "Delete", "whenScaled": "Retain"});
            }
        });
        assert_eq!(
            check(&buildkit_entry(), &store).unwrap_err(),
            vec![EntryViolation::WorkloadDeletesClaims]
        );
        let retain = store_with(|kind, body| {
            if kind == "StatefulSet" {
                body["spec"]["persistentVolumeClaimRetentionPolicy"] =
                    serde_json::json!({"whenDeleted": "Retain", "whenScaled": "Delete"});
            }
        });
        assert!(check(&buildkit_entry(), &retain).is_ok());
    }

    #[test]
    fn a_system_object_name_is_refused() {
        for name in ["kube-root-ca.crt", "openshift-service-ca.crt"] {
            let mut entry = buildkit_entry();
            entry.tool_templates[2].name = name.to_string();
            assert!(matches!(
                check(&entry, &store()).unwrap_err().as_slice(),
                [EntryViolation::TemplateNameSystem(_)]
            ));
        }
    }

    #[test]
    fn a_workload_with_a_token_is_invalid() {
        let absent = pod(|spec| {
            spec.as_object_mut()
                .unwrap()
                .remove("automountServiceAccountToken");
        });
        assert_eq!(
            absent,
            vec![EntryViolation::PodSpec(PodSpecViolation::TokenAutomounted)]
        );
        let set = pod(|spec| spec["automountServiceAccountToken"] = true.into());
        assert_eq!(set, absent);
    }

    #[test]
    fn a_projected_token_volume_is_invalid() {
        let violations = pod(|spec| {
            spec["volumes"] = serde_json::json!([{"name": "tok", "projected": {"sources": [
                {"serviceAccountToken": {"path": "token"}}
            ]}}]);
        });
        assert_eq!(
            violations,
            vec![EntryViolation::PodSpec(PodSpecViolation::ProjectedToken(
                "tok".to_string()
            ))]
        );
    }

    #[test]
    fn only_the_default_service_account_is_allowed() {
        assert_eq!(
            pod(|spec| spec["serviceAccountName"] = "builder".into()),
            vec![EntryViolation::PodSpec(PodSpecViolation::ServiceAccount(
                "builder".to_string()
            ))]
        );
        let store = store_with(|kind, body| {
            if kind == "StatefulSet" {
                body["spec"]["template"]["spec"]["serviceAccountName"] = "default".into();
            }
        });
        assert!(check(&buildkit_entry(), &store).is_ok());
    }

    #[test]
    fn a_privileged_template_is_invalid() {
        assert_eq!(
            pod(|spec| spec["containers"][0]["securityContext"]["privileged"] = true.into()),
            vec![EntryViolation::PodSpec(PodSpecViolation::Privileged(
                "buildkitd".to_string()
            ))]
        );
        assert_eq!(
            pod(|spec| spec["initContainers"] = serde_json::json!([
                {"name": "init", "securityContext": {"privileged": true}}
            ])),
            vec![EntryViolation::PodSpec(PodSpecViolation::Privileged(
                "init".to_string()
            ))]
        );
    }

    #[test]
    fn added_capabilities_are_invalid() {
        assert_eq!(
            pod(
                |spec| spec["containers"][0]["securityContext"]["capabilities"] =
                    serde_json::json!({"add": ["SYS_ADMIN"]})
            ),
            vec![EntryViolation::PodSpec(
                PodSpecViolation::CapabilitiesAdded("buildkitd".to_string())
            )]
        );
    }

    #[test]
    fn host_namespaces_are_invalid() {
        for (key, violation) in [
            ("hostNetwork", PodSpecViolation::HostNetwork),
            ("hostPID", PodSpecViolation::HostPid),
            ("hostIPC", PodSpecViolation::HostIpc),
        ] {
            assert_eq!(
                pod(|spec| spec[key] = true.into()),
                vec![EntryViolation::PodSpec(violation)]
            );
        }
    }

    #[test]
    fn a_host_port_is_invalid() {
        assert_eq!(
            pod(|spec| spec["containers"][0]["ports"] =
                serde_json::json!([{"containerPort": 1234, "hostPort": 1234}])),
            vec![EntryViolation::PodSpec(PodSpecViolation::HostPort(
                "buildkitd".to_string()
            ))]
        );
    }

    #[test]
    fn a_host_path_volume_is_invalid() {
        assert_eq!(
            pod(|spec| spec["volumes"] =
                serde_json::json!([{"name": "root", "hostPath": {"path": "/"}}])),
            vec![EntryViolation::PodSpec(PodSpecViolation::HostPath(
                "root".to_string()
            ))]
        );
    }

    #[test]
    fn a_runtime_class_must_be_allowed() {
        assert_eq!(
            pod(|spec| spec["runtimeClassName"] = "kata".into()),
            vec![EntryViolation::PodSpec(PodSpecViolation::RuntimeClass(
                "kata".to_string()
            ))]
        );
        let store = store_with(|kind, body| {
            if kind == "StatefulSet" {
                body["spec"]["template"]["spec"]["runtimeClassName"] = "gvisor".into();
            }
        });
        assert!(check(&buildkit_entry(), &store).is_ok());
    }

    #[test]
    fn the_service_port_must_be_a_port_of_the_service() {
        let mut entry = buildkit_entry();
        entry.service.port = 9999;
        assert_eq!(
            check(&entry, &store()).unwrap_err(),
            vec![EntryViolation::ServicePortMissing(9999)]
        );
        let mut entry = buildkit_entry();
        entry.service.name = "other".to_string();
        assert_eq!(
            check(&entry, &store()).unwrap_err(),
            vec![EntryViolation::ServiceNotAmongTemplates]
        );
    }

    #[test]
    fn a_named_target_port_is_what_the_policies_open() {
        let store = store_with(|kind, body| {
            if kind == "Service" {
                body["spec"]["ports"][0]["targetPort"] = "grpc".into();
            }
        });
        assert_eq!(check(&buildkit_entry(), &store).unwrap().port.port, "grpc");
    }

    #[test]
    fn the_client_duration_is_parsed() {
        assert_eq!(parse_duration("24h"), Some(Duration::from_secs(86_400)));
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5_400)));
        assert_eq!(
            parse_duration("3600000ms"),
            Some(Duration::from_secs(3_600))
        );
        for bad in [
            "",
            "24",
            "1.5h",
            "-1h",
            "1d",
            "h",
            "99999999999999999999h",
            "1H",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        for (raw, valid) in [
            ("24h", true),
            ("1h", true),
            ("59m", false),
            ("a week", false),
        ] {
            let mut entry = buildkit_entry();
            if let Some(tls) = entry.tls.as_mut() {
                tls.client_duration = raw.to_string();
            }
            assert_eq!(check(&entry, &store()).is_ok(), valid, "{raw}");
        }
    }

    #[test]
    fn team_keys_must_exist_and_default_stay_within_allowed() {
        let catalog = [buildkit_entry()];
        assert!(validate_team(&grant(&["buildkit"], &["buildkit"]), &catalog).is_empty());
        assert_eq!(
            validate_team(&grant(&["android"], &[]), &catalog),
            vec![TeamViolation::UnknownKey(ToolKey::new("android"))]
        );
        assert_eq!(
            validate_team(&grant(&[], &["buildkit"]), &catalog),
            vec![TeamViolation::DefaultNotAllowed(ToolKey::new("buildkit"))]
        );
        assert_eq!(keys(&["a"]).len(), 1);
    }

    #[test]
    fn an_allowed_tls_entry_requires_an_issuer() {
        let catalog = [buildkit_entry()];
        let mut team = grant(&["buildkit"], &[]);
        team.issuer_ref = None;
        assert_eq!(
            validate_team(&team, &catalog),
            vec![TeamViolation::IssuerRefRequired(ToolKey::new("buildkit"))]
        );
        let mut plain = buildkit_entry();
        plain.tls = None;
        assert!(validate_team(&team, &[plain]).is_empty());
        team.issuer_ref = Some(ToolIssuerRef {
            kind: "ClusterIssuer".to_string(),
            name: "ca".to_string(),
        });
        assert!(validate_team(&team, &catalog).is_empty());
    }

    #[test]
    fn every_violation_reads_as_a_sentence() {
        let message =
            EntryViolation::PodSpec(PodSpecViolation::HostPath("a\"b".to_string())).to_string();
        assert_eq!(
            message,
            "workload pod spec: volume \"a\\\"b\" is a hostPath"
        );
    }
}
