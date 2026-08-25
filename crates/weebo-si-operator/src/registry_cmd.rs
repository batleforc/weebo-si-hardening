//! `weebo-si-operator registry <resolve|check>` — RFC 0007's *CLI*.
//!
//! `resolve` is the "explain the decision" command every feature in this project has, and it
//! carries more weight here than elsewhere for one reason: this brick's metrics deliberately
//! carry no namespace label (see [`weebo_si_runtime::registry_metrics`]), so "which namespace is
//! degraded, and why" is answered here and in the controller log rather than by a time series.
//!
//! `check` is the pre-flight — validate every catalogue entry against its template *before* the
//! reconciler discovers the problem one namespace at a time. Exits non-zero on any violation, so
//! it works as a gate in a pipeline that edits the catalogue.
//!
//! Both read the cluster with **the invoking kubeconfig**, never the operator's service account,
//! matching `images audit`'s own rule: inspecting the configuration is the admin's permission.
//! That matters more here than there — this catalogue can name `Secret`s, and a CLI that read
//! them through the operator's identity would be a way to read a credential you were not granted.
//! **Neither subcommand ever prints a template's contents**, only its name, kind and verdict.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret};
use kube::{Api, Client, ResourceExt};
use weebo_si_crd::{
    RegistryConfig, RegistryEntry, SINGLETON_NAME, SourceKind, Team, TemplateRef, WeeboSiConfig,
    copy_name,
};
use weebo_si_registry_config::model::mount;
use weebo_si_registry_config::{ResolutionStep, resolve};

use crate::cli::flag;

/// Route the `registry` subcommand.
pub async fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("resolve") => resolve_cmd(&args[1..]).await,
        Some("check") => check(&args[1..]).await,
        Some(other) => Err(format!(
            "unrecognized registry subcommand '{other}' (expected resolve or check)"
        )),
        None => Err("registry needs a subcommand: resolve or check".to_string()),
    }
}

/// The `WeeboSiConfig` singleton's `registryConfig` block plus `spec.teams`, or a message naming
/// which of the two is missing.
async fn load(client: &Client) -> Result<(RegistryConfig, Vec<Team>), String> {
    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let config = api
        .get(SINGLETON_NAME)
        .await
        .map_err(|err| format!("could not read the WeeboSiConfig named {SINGLETON_NAME}: {err}"))?;
    let teams = config.spec.teams.clone();
    let registry = config
        .spec
        .features
        .registry_config
        .clone()
        .ok_or_else(|| {
            "this cluster's WeeboSiConfig has no spec.features.registryConfig block".to_string()
        })?;
    Ok((registry, teams))
}

/// `registry resolve --namespace <ns>` — the keys that namespace resolves to, the source objects
/// each expands into, and where each would mount.
async fn resolve_cmd(args: &[String]) -> Result<(), String> {
    let namespace = flag(args, "--namespace")
        .ok_or_else(|| "registry resolve needs --namespace <ns>".to_string())?;

    let client = Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let (config, teams) = load(&client).await?;

    let namespaces: Api<Namespace> = Api::all(client.clone());
    let object = namespaces
        .get(namespace)
        .await
        .map_err(|err| format!("could not read namespace {namespace}: {err}"))?;
    let labels: BTreeMap<String, String> = object.labels().clone();
    let annotation = (!config.namespace_selection.annotation.is_empty())
        .then(|| {
            object
                .annotations()
                .get(&config.namespace_selection.annotation)
        })
        .flatten()
        .cloned();

    println!("namespace:  {namespace}");
    println!("mode:       {:?}", config.mode);
    println!(
        "annotation: {} = {}",
        config.namespace_selection.annotation,
        annotation.as_deref().unwrap_or("<absent>")
    );

    let provenance = match resolve(&teams, &config, &labels, annotation.as_deref()) {
        Ok(provenance) => provenance,
        Err(not_granted) => {
            let keys: Vec<&str> = not_granted
                .requested
                .iter()
                .map(|key| key.as_str())
                .collect();
            println!(
                "team:       {}",
                not_granted
                    .team
                    .as_ref()
                    .map(|team| team.as_str())
                    .unwrap_or("<none>")
            );
            // A denial is printed and returned as an error, not just printed: `resolve` is used
            // in a pipeline that wants to know a namespace is misconfigured, and a zero exit for
            // "this namespace gets nothing because it asked for something it may not have" is
            // exactly the silence this command exists to break.
            return Err(format!(
                "onNotGranted: Deny — namespace {namespace} asks for [{}], which its team's \
                 grant does not allow; nothing would be written",
                keys.join(",")
            ));
        }
    };

    println!(
        "team:       {}",
        provenance
            .team
            .as_ref()
            .map(|team| team.as_str())
            .unwrap_or("<none>")
    );
    println!(
        "step:       {}",
        match provenance.step {
            ResolutionStep::NamespaceAnnotation => "namespace annotation",
            ResolutionStep::GrantDefault => "grant default",
        }
    );
    if !provenance.dropped_not_granted.is_empty() {
        let keys: Vec<&str> = provenance
            .dropped_not_granted
            .iter()
            .map(|key| key.as_str())
            .collect();
        println!("dropped:    [{}] (not granted)", keys.join(","));
    }

    if provenance.resolved.is_empty() {
        println!("\nthis namespace resolves no registry configuration");
        return Ok(());
    }

    println!(
        "\n{:<16} {:<10} {:<26} {:<40} MOUNT",
        "KEY", "KIND", "TEMPLATE", "COPY"
    );
    for key in &provenance.resolved {
        // Unreachable against a configuration `check` accepts; printed rather than returned so
        // one broken entry does not hide the rest of the answer.
        let Some(entry) = config.catalog.entry(key) else {
            println!("{key:<16} <not in catalog>");
            continue;
        };
        for source in &entry.sources {
            let mount = template_mount(&client, source.kind, &source.template_ref).await;
            println!(
                "{:<16} {:<10} {:<26} {:<40} {}",
                key.as_str(),
                source.kind.as_str(),
                source.template_ref.name,
                copy_name(key, &source.template_ref.name),
                mount
            );
        }
    }
    Ok(())
}

/// Where a template would mount, or why it would not — read from its own automount annotations.
///
/// Reads metadata only. A template that does not resolve is reported as such rather than as an
/// error: `resolve` answers "what would happen", and "the template is not there yet" is one of
/// the things that happens.
async fn template_mount(client: &Client, kind: SourceKind, reference: &TemplateRef) -> String {
    let Some((labels, annotations)) = template_metadata(client, kind, reference).await else {
        return "<template not found>".to_string();
    };
    match mount::admit(&labels, &annotations) {
        Err(refusal) => format!("REFUSED ({})", refusal.label()),
        Ok(()) => {
            let mount_as = mount::MountAs::parse(&annotations);
            let path = annotations
                .get(mount::MOUNT_PATH_ANNOTATION)
                .map(String::as_str)
                .unwrap_or("<devworkspace-operator default>");
            format!("{mount_as} {path}")
        }
    }
}

/// One template's labels and annotations — never its `data`.
///
/// The signature is the guarantee: this function cannot return a payload, so no caller in this
/// module can print one. That matters because half the objects this command inspects are
/// `Secret`s, and a CLI that dumped one would undo every argument RFC 0007 makes about keeping
/// credentials out of logs.
async fn template_metadata(
    client: &Client,
    kind: SourceKind,
    reference: &TemplateRef,
) -> Option<(BTreeMap<String, String>, BTreeMap<String, String>)> {
    match kind {
        SourceKind::ConfigMap => {
            let api: Api<ConfigMap> = Api::namespaced(client.clone(), reference.namespace.as_str());
            let object = api.get(&reference.name).await.ok()?;
            Some((object.labels().clone(), object.annotations().clone()))
        }
        SourceKind::Secret => {
            let api: Api<Secret> = Api::namespaced(client.clone(), reference.namespace.as_str());
            let object = api.get(&reference.name).await.ok()?;
            Some((object.labels().clone(), object.annotations().clone()))
        }
    }
}

/// One thing wrong with the catalogue, as `check` reports it.
struct Finding {
    key: String,
    kind: SourceKind,
    template: String,
    reason: String,
}

/// `registry check` — validate every catalogue entry against its template: the configuration's
/// own invariants first, then, for each source, that it exists, is automountable, and does not
/// shadow a home path.
async fn check(_args: &[String]) -> Result<(), String> {
    let client = Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let (config, teams) = load(&client).await?;

    // The configuration's own invariants first — a catalogue with two entries colliding on one
    // copy name is a supply-chain problem (one template's contents silently overwrite another's
    // in every granted namespace) and no amount of per-template checking would find it.
    let violations = config.validate(&teams);
    for violation in &violations {
        println!("CONFIG   {violation}");
    }

    let mut findings = Vec::new();
    for entry in config.catalog.entries() {
        findings.extend(check_entry(&client, entry).await);
    }

    if findings.is_empty() {
        println!("{:<16} {:<10} {:<26} STATUS", "KEY", "KIND", "TEMPLATE");
        for entry in config.catalog.entries() {
            for source in &entry.sources {
                println!(
                    "{:<16} {:<10} {:<26} ok",
                    entry.key.as_str(),
                    source.kind.as_str(),
                    source.template_ref.name
                );
            }
        }
    } else {
        println!("{:<16} {:<10} {:<26} REASON", "KEY", "KIND", "TEMPLATE");
        for finding in &findings {
            println!(
                "{:<16} {:<10} {:<26} {}",
                finding.key, finding.kind, finding.template, finding.reason
            );
        }
    }

    if violations.is_empty() && findings.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} configuration violation(s), {} unusable source(s)",
        violations.len(),
        findings.len()
    ))
}

async fn check_entry(client: &Client, entry: &RegistryEntry) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in &entry.sources {
        let reason = match template_metadata(client, source.kind, &source.template_ref).await {
            None => Some(format!(
                "not_found ({}/{})",
                source.template_ref.namespace, source.template_ref.name
            )),
            Some((labels, annotations)) => {
                mount::admit(&labels, &annotations).err().map(|refusal| {
                    // The refusal's `Display` says what to change, not only what is wrong — this
                    // is the command an admin runs when something is broken.
                    format!("{} — {refusal}", refusal.label())
                })
            }
        };
        if let Some(reason) = reason {
            findings.push(Finding {
                key: entry.key.to_string(),
                kind: source.kind,
                template: source.template_ref.name.clone(),
                reason,
            });
        }
    }
    findings
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    /// A textual tripwire, in the shape `weebo-si-webhook`'s router uses. Half the objects this
    /// command inspects are `Secret`s, and the whole of RFC 0007's argument about keeping
    /// credentials out of logs would be undone by one `println!` of a payload. The type system
    /// already prevents it — `template_metadata` cannot return one — but a future edit that
    /// fetches an object for some *other* reason would not be caught by it.
    ///
    /// Each needle is assembled at runtime, not written as a literal, so this test does not count
    /// its own source as an occurrence.
    #[test]
    fn this_command_never_reads_an_objects_payload_field() {
        let source = include_str!("registry_cmd.rs");
        for needle in [
            ["", "data"].join("."),
            ["string", "data"].join("_"),
            ["binary", "data"].join("_"),
        ] {
            assert_eq!(
                source.matches(&needle).count(),
                0,
                "registry_cmd must never touch a template's payload (found {needle})"
            );
        }
    }
}
