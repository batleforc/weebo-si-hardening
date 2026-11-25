//! `DevfileContract`, the `Feature<DevfileWorkspace>` (RFC 0019, *Behaviour rules*).
//!
//! **The invariant.** The only `Decision::deny` sits behind a denied-list match *and*
//! `subject.starting` *and* `onDenied: Deny`: an outdated, unknown or unpinned devfile is never
//! refused, and a non-start update (finalizers, a stop, a delete) never is. `evaluate` has no
//! fallible step past the config load: every parse failure is a verdict.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Mutation};
use weebo_si_crd::{
    DEVFILE_CONTRACT_ANNOTATION, DEVFILE_CONTRACT_REASON_ANNOTATION, DeniedParent,
    DevfileContractConfig, OnDenied, PLATFORM_CONTRACT_ATTRIBUTE,
};

use crate::parse::{
    Contract, UriPin, classify_parent_uri, excerpt, normalise_uri, parse_contract,
    parse_schema_version, scan_schema_version,
};
use crate::subject::{DevfileWorkspace, Parent};

/// The feature identifier.
pub const FEATURE_ID: &str = "devfile-contract";

/// The annotation verdict, worst first: `unknown` outranks `outdated` outranks `current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Nothing to say.
    Current,
    /// Written for older rules, or following a moving parent.
    Outdated,
    /// The contract is absent, invalid or from the future.
    Unknown,
}

impl Verdict {
    /// The annotation value, also the metric `result`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Outdated => "outdated",
            Self::Unknown => "unknown",
        }
    }
}

/// What one evaluation found, before the mode or the start rule is applied.
struct Findings {
    verdict: Verdict,
    reasons: Vec<&'static str>,
    warnings: Vec<String>,
}

impl Findings {
    fn add(&mut self, verdict: Verdict, reason: &'static str, warning: Option<String>) {
        self.verdict = self.verdict.max(verdict);
        self.reasons.push(reason);
        self.warnings.extend(warning);
    }
}

/// The `devfile-contract` feature, reading the config store's live handle.
pub struct DevfileContract {
    config: Arc<RwLock<Option<DevfileContractConfig>>>,
}

impl DevfileContract {
    /// Build it over the config store's live handle (`devfile_contract_config()`).
    pub fn new(config: Arc<RwLock<Option<DevfileContractConfig>>>) -> Self {
        Self { config }
    }
}

impl Feature<DevfileWorkspace> for DevfileContract {
    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn evaluate(
        &self,
        subject: &DevfileWorkspace,
        _ctx: &Context<'_>,
    ) -> Result<Decision<DevfileWorkspace>, DomainError> {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(config) = guard.as_ref() else {
            return Err(DomainError::InvalidConfiguration(
                "devfile-contract evaluated with no spec.features.devfileContract configured"
                    .to_string(),
            ));
        };
        Ok(decide(subject, config))
    }
}

fn decide(
    subject: &DevfileWorkspace,
    config: &DevfileContractConfig,
) -> Decision<DevfileWorkspace> {
    let mut findings = Findings {
        verdict: Verdict::Current,
        reasons: Vec::new(),
        warnings: Vec::new(),
    };
    let contract = parse_contract(subject.platform_contract.as_ref());
    check_contract(&mut findings, contract, config);
    check_parent(&mut findings, subject.parent.as_ref());
    check_schema(&mut findings, subject.che_devfile.as_deref(), config);

    // Absent and invalid count as 1, so `deniedContracts: [1]` makes the attribute mandatory.
    let effective = match contract {
        Contract::Number(n) => n,
        Contract::Absent | Contract::Invalid => 1,
    };
    let mut denials = Vec::new();
    if config.denied_contracts.contains(&effective) {
        findings.reasons.push("contract-denied");
        denials.push(Denied::Contract(effective));
    }
    if let Some((index, entry)) = subject
        .parent
        .as_ref()
        .and_then(|parent| denied_match(parent, &config.denied_parents))
    {
        findings.reasons.push("parent-denied");
        denials.push(Denied::Parent(index, entry));
    }

    let verdict = findings.verdict;
    let reasons = findings.reasons.join(",");
    let contract_field = match contract {
        Contract::Number(n) => n.to_string(),
        Contract::Absent | Contract::Invalid => "absent".to_string(),
    };
    let mut note = format!(
        "devfile={} reasons={reasons} contract={contract_field}",
        verdict.as_str()
    );
    if let Some(generator) = &subject.generator {
        note.push_str(&format!(" generator={}", excerpt(generator)));
    }

    let refuse = subject.starting && config.on_denied == OnDenied::Deny;
    if refuse && !denials.is_empty() {
        let reason = denials
            .iter()
            .map(|denied| render_denial(denied, config.current_contract))
            .collect::<Vec<_>>()
            .join(". ");
        return Decision::deny(reason, None, Some(note), "denied");
    }
    let mut warnings = findings.warnings;
    warnings.extend(
        denials
            .iter()
            .map(|denied| render_denied_warning(denied, config, subject.starting)),
    );

    let mut mutations = Vec::new();
    for (key, value, stored) in [
        (
            DEVFILE_CONTRACT_ANNOTATION,
            verdict.as_str().to_string(),
            &subject.stored_verdict,
        ),
        (
            DEVFILE_CONTRACT_REASON_ANNOTATION,
            reasons,
            &subject.stored_reasons,
        ),
    ] {
        if stored.as_deref() != Some(value.as_str()) {
            mutations.push(Mutation::Annotate {
                key: key.to_string(),
                value,
            });
        }
    }
    Decision::new(mutations, None, Some(note), verdict.as_str()).with_warnings(warnings)
}

fn check_contract(findings: &mut Findings, contract: Contract, config: &DevfileContractConfig) {
    let current = config.current_contract;
    match contract {
        Contract::Absent => findings.add(
            Verdict::Unknown,
            "contract-absent",
            Some(format!(
                "devfile has no {PLATFORM_CONTRACT_ATTRIBUTE} attribute; add \"{PLATFORM_CONTRACT_ATTRIBUTE}: {current}\" to its attributes"
            )),
        ),
        Contract::Invalid => findings.add(
            Verdict::Unknown,
            "contract-invalid",
            Some(format!(
                "{PLATFORM_CONTRACT_ATTRIBUTE} must be an integer, read as absent; current is {current}"
            )),
        ),
        Contract::Number(n) if n > current => findings.add(
            Verdict::Unknown,
            "contract-future",
            Some(format!(
                "{PLATFORM_CONTRACT_ATTRIBUTE} {n} is newer than this platform ({current}): check the value"
            )),
        ),
        Contract::Number(n) if n < config.minimum_contract => findings.add(
            Verdict::Outdated,
            "contract-below-minimum",
            Some(format!(
                "devfile written for platform contract {n}, minimum is {}: see the User Guide changes for contracts {} to {current}",
                config.minimum_contract,
                n.saturating_add(1),
            )),
        ),
        Contract::Number(_) => findings.add(Verdict::Current, "contract-ok", None),
    }
}

fn check_parent(findings: &mut Findings, parent: Option<&Parent>) {
    match parent {
        None => findings.add(Verdict::Current, "parent-none", None),
        Some(Parent::Uri(uri)) => match classify_parent_uri(uri) {
            UriPin::Pinned => findings.add(Verdict::Current, "parent-pinned", None),
            UriPin::Branch(branch) => findings.add(
                Verdict::Outdated,
                "parent-branch",
                Some(format!(
                    "devfile parent follows branch \"{branch}\": pin parent.uri to a tag or a commit"
                )),
            ),
            UriPin::Unpinned => findings.add(
                Verdict::Outdated,
                "parent-unpinned",
                Some(
                    "devfile parent is not pinned to a tag or a commit: pin parent.uri to one"
                        .to_string(),
                ),
            ),
        },
        Some(Parent::Id { id, version }) if version.as_deref().is_none_or(str::is_empty) => {
            findings.add(
                Verdict::Outdated,
                "parent-no-version",
                Some(format!(
                    "devfile parent \"{}\" has no version: set parent.version",
                    excerpt(id)
                )),
            );
        }
        Some(Parent::Id { .. }) => findings.add(Verdict::Current, "parent-pinned", None),
        Some(Parent::Kubernetes) => findings.add(
            Verdict::Outdated,
            "parent-mutable",
            Some(
                "devfile parent is a DevWorkspaceTemplate (parent.kubernetes): the workspace itself can change it"
                    .to_string(),
            ),
        ),
    }
}

fn check_schema(
    findings: &mut Findings,
    che_devfile: Option<&str>,
    config: &DevfileContractConfig,
) {
    let Some(found) = che_devfile.and_then(scan_schema_version) else {
        findings.add(Verdict::Current, "schema-unknown", None);
        return;
    };
    let minimum = config
        .minimum_schema_version
        .as_deref()
        .and_then(parse_schema_version);
    match minimum {
        Some(min) if found < min => findings.add(
            Verdict::Outdated,
            "schema-below-minimum",
            // Rendered from the parsed numbers: no user text reaches the warning.
            Some(format!(
                "devfile schemaVersion {}.{}.{} is below the platform minimum {}.{}.{}",
                found.0, found.1, found.2, min.0, min.1, min.2
            )),
        ),
        _ => findings.add(Verdict::Current, "schema-ok", None),
    }
}

/// A denied-list match, quoting the admin's entry only.
enum Denied<'a> {
    Contract(u32),
    /// The 1-based entry number and the entry.
    Parent(usize, &'a DeniedParent),
}

/// The first `deniedParents` entry the parent matches, numbered from 1. A `uriPrefix` matches a
/// `parent.uri` after both are normalised (T3: scheme and host lowercased, userinfo, query and
/// fragment dropped); an `id` matches `parent.id` with one of `versions`, or any version (an
/// absent one included) when `versions` is empty.
pub fn denied_match<'a>(
    parent: &Parent,
    denied: &'a [DeniedParent],
) -> Option<(usize, &'a DeniedParent)> {
    let uri = match parent {
        Parent::Uri(uri) => Some(normalise_uri(uri)),
        Parent::Id { .. } | Parent::Kubernetes => None,
    };
    denied.iter().enumerate().find_map(|(index, entry)| {
        let matched = match (parent, &entry.uri_prefix, &entry.id) {
            (Parent::Uri(_), Some(prefix), _) => uri
                .as_deref()
                .is_some_and(|uri| uri.starts_with(&normalise_uri(prefix))),
            (Parent::Id { id, version }, None, Some(denied_id)) => {
                id == denied_id
                    && (entry.versions.is_empty()
                        || version.as_ref().is_some_and(|v| entry.versions.contains(v)))
            }
            _ => false,
        };
        matched.then_some((index.saturating_add(1), entry))
    })
}

/// The refusal text: stands alone (the dashboard shows only this), quotes the admin's entry.
fn render_denial(denied: &Denied<'_>, current: u32) -> String {
    match denied {
        Denied::Contract(n) => {
            let absent = if *n == 1 {
                format!(" (devfiles without {PLATFORM_CONTRACT_ATTRIBUTE} count as 1)")
            } else {
                String::new()
            };
            format!(
                "platform contract {n} is denied{absent}: add \"{PLATFORM_CONTRACT_ATTRIBUTE}: {current}\" and follow the User Guide"
            )
        }
        Denied::Parent(index, entry) => {
            let (what, field) = match (&entry.uri_prefix, &entry.id) {
                // Normalised: an admin prefix carrying credentials never reaches the user.
                (Some(prefix), _) => (normalise_uri(prefix), "parent.uri"),
                (None, id) => (
                    format!("id {}", id.as_deref().unwrap_or_default()),
                    "parent.version",
                ),
            };
            format!(
                "devfile parent is denied by the platform (deniedParents entry {index}: {what}): move {field} to a newer version; contract {current} in the User Guide lists them"
            )
        }
    }
}

/// The warning a match becomes when it is not refused: on a non-start update under `Deny`, or
/// under `onDenied: Warn`. Short, so the 120-character bound keeps the action.
fn render_denied_warning(
    denied: &Denied<'_>,
    config: &DevfileContractConfig,
    starting: bool,
) -> String {
    let subject = match denied {
        Denied::Contract(n) => format!("platform contract {n} is denied"),
        Denied::Parent(index, _) => {
            format!("devfile parent is denied by the platform (deniedParents entry {index})")
        }
    };
    let action = match (config.on_denied, denied) {
        (OnDenied::Deny, _) if !starting => {
            "this workspace will be refused at its next start".to_string()
        }
        (_, Denied::Contract(_)) => format!(
            "add \"{PLATFORM_CONTRACT_ATTRIBUTE}: {}\" and follow the User Guide",
            config.current_contract
        ),
        (_, Denied::Parent(_, entry)) if entry.uri_prefix.is_some() => {
            "move parent.uri to a newer version".to_string()
        }
        (_, Denied::Parent(..)) => "move parent.version to a newer version".to_string(),
    };
    format!("{subject}: {action}")
}

#[cfg(test)]
#[path = "feature_tests.rs"]
mod tests;
