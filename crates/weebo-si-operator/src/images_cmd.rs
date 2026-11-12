//! `weebo-si-operator images <platform|check|audit>` — RFC 0005's *CLI*.
//!
//! `audit` is to this feature what `canary` is to RFC 0004: **the command that answers "is this
//! safe to switch on" before it is switched on.** It is step 0 of that RFC's rollout and the one
//! step no other feature in this repo has — a catalogue written from what is actually running
//! beats one guessed and then discovered a denial at a time.
//!
//! All three read the cluster with **the invoking kubeconfig**, never the operator's service
//! account: listing pods cluster-wide is the admin's own permission, which is why this feature
//! adds no RBAC at all (RFC 0005's *Security considerations*).

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::api::DynamicObject;
use kube::{Api, Client};
use weebo_si_crd::{
    IMAGE_REWRITE_ANNOTATION, NamespaceName, PlatformConfig, ResolvedImagePolicyConfig,
    SINGLETON_NAME, Team, TeamName, WeeboSiConfig, WeeboSiTeam, team_views,
};
use weebo_si_image_policy::port::{ImagePolicyObserver, Resource};
use weebo_si_image_policy::variable::resolve_declared;
use weebo_si_image_policy::{
    BUILTIN_PLATFORM_PATTERNS, ImageReference, ImageVerdict, PermittedBy, Rewrite, Rules,
    VariableName, VariableResult, VariableValues, Verdict, allowed_set, derived_platform_patterns,
    effective_patterns, judge, platform_patterns,
};

use crate::cli::flag;

/// Route the `images` subcommand.
pub async fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("platform") if args[1..].iter().any(|arg| arg == "--cluster") => {
            print_cluster_platform().await
        }
        Some("platform") => {
            print_platform();
            Ok(())
        }
        Some("check") => check(&args[1..]).await,
        Some("audit") => audit(&args[1..]).await,
        Some(other) => Err(format!(
            "unrecognized images subcommand '{other}' (expected platform, check or audit)"
        )),
        None => Err("images needs a subcommand: platform, check or audit".to_string()),
    }
}

/// `images platform` — the compiled-in set, printed rather than described in prose.
///
/// Reads no cluster and needs no kubeconfig: the list is in the binary, which is the whole point
/// of the subcommand. Nobody writes these down, so `kubectl` cannot show them to you.
fn print_platform() {
    for pattern in BUILTIN_PLATFORM_PATTERNS {
        println!("{pattern}");
    }
}

/// The effective platform set, one `(pattern, source)` row each: the compiled-in list, its form
/// derived through the `imageRewrite` rules (RFC 0017), then `platform.extra`. A derived pattern
/// is never hidden: it is listed next to the pattern it comes from and the rule that made it.
fn platform_rows(platform: &PlatformConfig, rewrite: Option<&Rules>) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    if platform.builtin {
        let derived = rewrite.map(derived_platform_patterns).unwrap_or_default();
        for builtin in BUILTIN_PLATFORM_PATTERNS {
            rows.push(((*builtin).to_string(), "builtin".to_string()));
            for pattern in derived.iter().filter(|d| d.builtin == *builtin) {
                rows.push((
                    pattern.text.clone(),
                    format!("builtin, rewritten by rule {}", pattern.rule),
                ));
            }
        }
    }
    rows.extend(
        platform
            .extra
            .iter()
            .map(|raw| (raw.clone(), "extra".to_string())),
    );
    rows
}

/// `images platform --cluster` — the platform set the live `WeeboSiConfig` actually yields.
async fn print_cluster_platform() -> Result<(), String> {
    let client = kube::Client::try_default().await.map_err(|err| {
        format!("cannot reach the cluster: {err}; run without --cluster for the compiled-in list")
    })?;
    let (config, _teams, rewrite) = load_config(&client).await?;
    let rows = platform_rows(&config.platform, rewrite.as_ref());
    let width = rows
        .iter()
        .map(|(pattern, _)| pattern.len())
        .max()
        .unwrap_or(0)
        .max("PATTERN".len());
    println!("{:width$}   SOURCE", "PATTERN");
    if rows.is_empty() {
        println!("(empty: no platform pattern — every image needs a grant)");
    }
    for (pattern, source) in rows {
        println!("{pattern:width$}   {source}");
    }
    Ok(())
}

/// Discard every observation — the CLI reports its own answers in full, and a counter with no
/// `/metrics` endpoint behind it has nowhere to go.
struct SilentObserver;

impl ImagePolicyObserver for SilentObserver {
    fn image_judged(
        &self,
        _resource: Resource,
        _team: Option<&TeamName>,
        _verdict: &ImageVerdict,
        _platform_only: bool,
    ) {
    }
    fn not_granted(&self, _resource: Resource, _team: Option<&TeamName>, _count: usize) {}
    fn variable_resolved(&self, _variable: &VariableName, _result: VariableResult) {}
    fn variable_value_seen(&self, _ns: &NamespaceName, _v: &VariableName, _value: &str) {}
}

/// A `NamespaceView` over a plain list of namespaces, for the CLI — the watch-backed adapter is
/// the webhook role's, and a one-shot command has no business starting a reflector.
struct ListedNamespaces(BTreeMap<String, Namespace>);

impl weebo_si_chassis::port::namespace_view::NamespaceView for ListedNamespaces {
    fn facts(&self, ns: &NamespaceName) -> Option<weebo_si_chassis::NamespaceFacts> {
        self.0
            .get(ns.as_str())
            .map(|namespace| weebo_si_chassis::NamespaceFacts {
                labels: namespace
                    .metadata
                    .labels
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
                selection_annotation: None,
            })
    }

    fn annotation(&self, ns: &NamespaceName, key: &str) -> Option<String> {
        if key.is_empty() {
            return None;
        }
        self.0.get(ns.as_str()).and_then(|namespace| {
            namespace
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(key))
                .filter(|value| !value.is_empty())
                .cloned()
        })
    }
}

/// The live `WeeboSiConfig`'s `imagePolicy` block resolved against every `WeeboSiTeam`, and
/// those teams as the features see them, or a clear refusal.
///
/// The resolution is not optional: RFC 0011 keeps each team's catalogue on its own object, so a
/// CLI reading only the singleton would report what the cluster would do if no team existed.
///
/// The third value is `imageRewrite`'s rules when the block is present and valid — what both
/// admission routes act on (RFC 0017); `None` otherwise, which derives and rewrites nothing.
async fn load_config(
    client: &Client,
) -> Result<(ResolvedImagePolicyConfig, Vec<Team>, Option<Rules>), String> {
    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let config = api
        .get(SINGLETON_NAME)
        .await
        .map_err(|err| format!("could not read WeeboSiConfig/{SINGLETON_NAME}: {err}"))?;
    let image_policy = config.spec.features.image_policy.as_ref().ok_or_else(|| {
        "WeeboSiConfig/cluster carries no spec.features.imagePolicy — there is nothing to judge \
         against yet. Write the catalogue first (mode: Off is fine), then re-run."
            .to_string()
    })?;
    let teams = load_teams(client).await?;
    let (image_policy, _conflicts) = image_policy.resolve(&teams);
    let rewrite = config
        .spec
        .features
        .image_rewrite
        .as_ref()
        .and_then(|rewrite| Rules::new(rewrite).ok());
    Ok((image_policy, team_views(&teams), rewrite))
}

/// Every `WeeboSiTeam` in the cluster, or a message naming why not.
async fn load_teams(client: &Client) -> Result<Vec<WeeboSiTeam>, String> {
    let api: Api<WeeboSiTeam> = Api::all(client.clone());
    api.list(&Default::default())
        .await
        .map(|list| list.items)
        .map_err(|err| format!("could not list WeeboSiTeam objects: {err}"))
}

/// Every namespace, keyed by name — one list call, reused by both `check` and `audit`.
async fn load_namespaces(client: &Client) -> Result<ListedNamespaces, String> {
    let api: Api<Namespace> = Api::all(client.clone());
    let list = api
        .list(&Default::default())
        .await
        .map_err(|err| format!("could not list namespaces: {err}"))?;
    Ok(ListedNamespaces(
        list.items
            .into_iter()
            .filter_map(|ns| ns.metadata.name.clone().map(|name| (name, ns)))
            .collect(),
    ))
}

/// Resolve one namespace's variables and its team's whole `allowed` set — the `Pod`-layer
/// answer, which is the one both `check` and `audit` report against.
///
/// Deliberately the team boundary rather than a workspace's selection: neither command has a
/// DevWorkspace in hand, and reporting a narrower answer than the floor actually enforces would
/// make `audit` say a running pod is denied when it is not.
fn judge_in_namespace(
    config: &ResolvedImagePolicyConfig,
    rewrite: Option<&Rules>,
    teams: &[Team],
    namespace: &NamespaceName,
    namespaces: &ListedNamespaces,
    reference: &str,
) -> (
    Option<TeamName>,
    Vec<weebo_si_crd::EntryKey>,
    Verdict,
    VariableValues,
) {
    use weebo_si_chassis::port::namespace_view::NamespaceView;

    let labels = namespaces
        .facts(namespace)
        .map(|facts| facts.labels)
        .unwrap_or_default();
    let provenance = allowed_set(teams, config, &labels);

    let mut variables = resolve_declared(config, namespace, namespaces, &SilentObserver);
    variables.bind_team(provenance.team.as_ref());
    variables.bind_namespace(namespace);

    let platform = platform_patterns(&config.platform, rewrite).unwrap_or_default();
    let union = effective_patterns(config, &provenance.resolved, &platform);
    let verdict = judge(reference, &union, &variables);
    (provenance.team, provenance.resolved, verdict, variables)
}

/// `images check REF [--team NAME] [--namespace NS]` — parse, normalize and judge one reference.
///
/// Exposes the parser so an admin can *see* the normalization rather than infer it, which is the
/// whole reason it exists: a reference that pulls differently from how it reads is the failure
/// this feature is shaped around.
async fn check(args: &[String]) -> Result<(), String> {
    let reference = args
        .iter()
        .find(|arg| !arg.starts_with("--"))
        .ok_or_else(|| "images check needs a reference".to_string())?
        .clone();
    let team = flag(args, "--team").map(str::to_string);
    let namespace = flag(args, "--namespace").unwrap_or("default").to_string();

    println!("reference  {reference}");
    let parsed = match ImageReference::parse(&reference) {
        Ok(parsed) => parsed,
        Err(err) => {
            // Parse failure denies, and `check` says so in the same words the API error uses.
            println!("normalized <unparseable>");
            println!("verdict    DENIED — {err}");
            return Err(
                "the reference does not parse, and an unparseable reference is always \
                        denied"
                    .to_string(),
            );
        }
    };
    println!("normalized {parsed}");
    println!(
        "           host={} path={} tag={} digest={}",
        parsed.host(),
        parsed.path(),
        parsed.tag().unwrap_or("<none>"),
        parsed.digest().unwrap_or("<none>")
    );

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let (config, teams, rewrite) = load_config(&client).await?;
    let namespaces = load_namespaces(&client).await?;
    let namespace = NamespaceName::new(namespace);

    // Admission rewrites before it judges (RFC 0017), so `check` does too and says so. Whether
    // `imageRewrite` runs in that namespace (mode, selector) is not checked here.
    let reference = match rewrite.as_ref().map(|rules| rules.rewrite(&reference)) {
        Some(Rewrite::Rewritten {
            reference: to,
            rule,
        }) => {
            println!("rewritten  {parsed} → {to} (rule {rule})");
            to.to_string()
        }
        _ => reference,
    };

    // `--team` overrides the namespace's own routing, so an admin can ask "what would team-2 see"
    // without needing a namespace that belongs to team-2.
    let (resolved_team, entries, verdict, variables) = match &team {
        Some(name) => {
            let synthetic = TeamName::new(name.clone());
            let grant = config.grant_for(&synthetic).cloned().unwrap_or_default();
            let mut variables = resolve_declared(&config, &namespace, &namespaces, &SilentObserver);
            variables.bind_team(Some(&synthetic));
            variables.bind_namespace(&namespace);
            let platform =
                platform_patterns(&config.platform, rewrite.as_ref()).unwrap_or_default();
            let union = effective_patterns(&config, &grant.allowed, &platform);
            let verdict = judge(&reference, &union, &variables);
            (Some(synthetic), grant.allowed, verdict, variables)
        }
        None => judge_in_namespace(
            &config,
            rewrite.as_ref(),
            &teams,
            &namespace,
            &namespaces,
            &reference,
        ),
    };

    // The interpolated line is not decoration: a pattern that interpolates is one an admin
    // cannot check by reading, so this prints what it became.
    for key in &entries {
        let Some(entry) = config.catalog.entry(key) else {
            continue;
        };
        for raw in &entry.patterns {
            let Ok(pattern) = weebo_si_image_policy::Pattern::parse(raw) else {
                println!("patterns   {raw}  ->  <unparseable, entry grants nothing>");
                continue;
            };
            if pattern.variables().is_empty() {
                continue;
            }
            match pattern.interpolated(&variables) {
                Some(rendered) => println!("patterns   {raw}  ->  {rendered}"),
                None => println!("patterns   {raw}  ->  <undefined variable, matches nothing>"),
            }
        }
    }

    let team_text = resolved_team
        .as_ref()
        .map(|team| format!("team {team}"))
        .unwrap_or_else(|| "no team".to_string());
    let entry_text: Vec<&str> = entries.iter().map(weebo_si_crd::EntryKey::as_str).collect();
    match verdict {
        Verdict::Permitted(PermittedBy::Entry(key)) => {
            println!("verdict    permitted by entry {key}");
            Ok(())
        }
        Verdict::Permitted(PermittedBy::Platform) => {
            println!("verdict    permitted by the platform set");
            Ok(())
        }
        Verdict::NoMatchingPattern => {
            println!(
                "verdict    DENIED — {team_text}, entries [{}], no matching pattern",
                entry_text.join(", ")
            );
            Err("not permitted".to_string())
        }
        Verdict::Unparseable(err) => {
            println!("verdict    DENIED — {err}");
            Err("not permitted".to_string())
        }
    }
}

/// RFC 0017's `stale-mirror`: the components of one `DevWorkspace` whose image is an earlier
/// rewrite of the original its `hardening.weebo.io/image-rewrite` annotation records, and is not
/// what today's rules would make of that original — a rule's `to` that changed or a rule that was
/// removed. The rewrite never revisits a stored name (it matches no `from`), so this is reported
/// for the admin or the user to edit, never fixed.
///
/// "An earlier rewrite" is checked, not assumed: another host, the original's whole path at the
/// end of its own, the same tag and digest. A component a user re-pointed elsewhere after its
/// rewrite keeps a stale record but fails that check, and is not reported.
///
/// Returns `(component, image, what today's rules give, if anything)`.
fn stale_mirror(
    rules: Option<&Rules>,
    recorded: &BTreeMap<String, String>,
    components: &[(String, String)],
) -> Vec<(String, String, Option<String>)> {
    let mut stale = Vec::new();
    for (name, image) in components {
        let Some(original) = recorded.get(name) else {
            continue;
        };
        let (Ok(was), Ok(now)) = (
            ImageReference::parse(original),
            ImageReference::parse(image),
        ) else {
            continue;
        };
        let an_earlier_rewrite = now.host() != was.host()
            && now.path().ends_with(&format!("/{}", was.path()))
            && now.tag() == was.tag()
            && now.digest() == was.digest();
        let expected = match rules.map(|rules| rules.rewrite(original)) {
            Some(Rewrite::Rewritten { reference, .. }) => Some(reference.to_string()),
            _ => None,
        };
        if an_earlier_rewrite && expected.as_deref() != Some(now.to_string().as_str()) {
            stale.push((name.clone(), image.clone(), expected));
        }
    }
    stale
}

/// One row of `images audit`.
struct AuditRow {
    pods: usize,
    /// `None` while every namespace agreed; `Some(ns)` once two disagreed, naming the first
    /// namespace whose verdict differs — the per-namespace answer a pattern that interpolates
    /// makes necessary.
    disagreement: Option<String>,
    verdict: Verdict,
    team: Option<TeamName>,
    entries: Vec<weebo_si_crd::EntryKey>,
}

/// `images audit [--namespace NS | --all-namespaces]` — every image running now, and its verdict.
///
/// Writes nothing and changes nothing. Because a pattern may interpolate, **a verdict is a
/// property of the namespace rather than of the image alone**: this aggregates the images whose
/// verdict is the same everywhere and names the namespace for the rest. Then, RFC 0017's
/// `stale-mirror` table: `DevWorkspace` components still naming a mirror no rule points at now.
async fn audit(args: &[String]) -> Result<(), String> {
    let all = args.iter().any(|arg| arg == "--all-namespaces");
    let one = flag(args, "--namespace").map(str::to_string);
    if !all && one.is_none() {
        return Err("images audit needs --namespace <ns> or --all-namespaces".to_string());
    }

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let (config, teams, rewrite) = load_config(&client).await?;
    let namespaces = load_namespaces(&client).await?;

    let pods: Api<Pod> = match &one {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = pods
        .list(&Default::default())
        .await
        .map_err(|err| format!("could not list pods: {err}"))?;

    let mut rows: BTreeMap<String, AuditRow> = BTreeMap::new();
    for pod in list.items {
        let Some(namespace) = pod.metadata.namespace.clone() else {
            continue;
        };
        let namespace = NamespaceName::new(namespace);
        let spec = pod.spec.unwrap_or_default();
        let references = spec
            .containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
            .filter_map(|container| container.image.clone());

        for reference in references {
            let (team, entries, verdict, _) = judge_in_namespace(
                &config,
                rewrite.as_ref(),
                &teams,
                &namespace,
                &namespaces,
                &reference,
            );
            rows.entry(reference)
                .and_modify(|row| {
                    row.pods += 1;
                    if row.verdict != verdict && row.disagreement.is_none() {
                        row.disagreement = Some(namespace.as_str().to_string());
                    }
                })
                .or_insert(AuditRow {
                    pods: 1,
                    disagreement: None,
                    verdict,
                    team,
                    entries,
                });
        }
    }

    println!("{:<56} {:>5}  VERDICT", "IMAGE", "PODS");
    let mut denied = 0usize;
    for (reference, row) in &rows {
        let verdict = match (&row.verdict, &row.disagreement) {
            (_, Some(namespace)) => {
                // The `{TEAM_NAME}` case: the same image is permitted in one namespace and not
                // in another, which is exactly what a per-team registry path is for.
                format!("VARIES   differs in {namespace}")
            }
            (Verdict::Permitted(PermittedBy::Entry(key)), None) => format!("allowed  {key}"),
            (Verdict::Permitted(PermittedBy::Platform), None) => "allowed  platform".to_string(),
            (Verdict::NoMatchingPattern, None) => {
                let team = row
                    .team
                    .as_ref()
                    .map(|team| format!("{team} grants "))
                    .unwrap_or_else(|| "no team, default ".to_string());
                let entries: Vec<&str> = row
                    .entries
                    .iter()
                    .map(weebo_si_crd::EntryKey::as_str)
                    .collect();
                format!("DENIED   {team}[{}]", entries.join(", "))
            }
            (Verdict::Unparseable(err), None) => format!("DENIED   {err}"),
        };
        if verdict.starts_with("DENIED") {
            denied += 1;
        }
        println!("{reference:<56} {:>5}  {verdict}", row.pods);
    }

    if denied > 0 {
        // Not an error: `audit` is a report, and a non-zero exit would make it awkward to run
        // from a pipeline that wants the table. The count is the summary an admin reads.
        println!();
        println!(
            "{denied} distinct image(s) would be denied by this configuration. Every one is a \
             workspace that stops starting at mode: Enforce — widen a grant, add a catalogue \
             entry, or accept the denial deliberately."
        );
    }

    let workspaces: Api<DynamicObject> = match &one {
        Some(ns) => Api::namespaced_with(
            client,
            ns,
            &weebo_si_controller::workspace::devworkspace_resource(),
        ),
        None => Api::all_with(
            client,
            &weebo_si_controller::workspace::devworkspace_resource(),
        ),
    };
    // A cluster without the DevWorkspace CRD has nothing to report here, not an error.
    let workspaces = workspaces
        .list(&Default::default())
        .await
        .map(|list| list.items)
        .unwrap_or_default();
    let mut stale_rows = Vec::new();
    for workspace in &workspaces {
        let Some(recorded) = workspace
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(IMAGE_REWRITE_ANNOTATION))
            .and_then(|value| serde_json::from_str::<BTreeMap<String, String>>(value).ok())
        else {
            continue;
        };
        let components: Vec<(String, String)> = workspace
            .data
            .pointer("/spec/template/components")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .filter_map(|component| {
                Some((
                    component.get("name")?.as_str()?.to_string(),
                    component.pointer("/container/image")?.as_str()?.to_string(),
                ))
            })
            .collect();
        let at = format!(
            "{}/{}",
            workspace.metadata.namespace.as_deref().unwrap_or_default(),
            workspace.metadata.name.as_deref().unwrap_or_default()
        );
        for (component, image, expected) in stale_mirror(rewrite.as_ref(), &recorded, &components) {
            stale_rows.push((at.clone(), component, image, expected));
        }
    }
    if !stale_rows.is_empty() {
        println!();
        println!(
            "{:<40} {:<16} {:<56} STALE-MIRROR",
            "DEVWORKSPACE", "COMPONENT", "IMAGE"
        );
        for (at, component, image, expected) in &stale_rows {
            let now = expected.as_deref().map_or_else(
                || "no rule rewrites it now".to_string(),
                |e| format!("now {e}"),
            );
            println!("{at:<40} {component:<16} {image:<56} {now}");
        }
        println!();
        println!(
            "{} component(s) still pull from a mirror an imageRewrite rule no longer points at. \
             The rewrite never revisits a stored name: edit each DevWorkspace's image.",
            stale_rows.len()
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_listing_is_what_the_domain_compiled_in() {
        // `images platform` exists because nobody writes these down, so the printed list has to
        // be the same one the matcher uses — not a second copy that can drift.
        assert!(!BUILTIN_PLATFORM_PATTERNS.is_empty());
        assert!(
            BUILTIN_PLATFORM_PATTERNS
                .iter()
                .any(|p| p.contains("project-clone"))
        );
    }

    #[test]
    fn a_component_rewritten_under_a_changed_or_removed_rule_is_a_stale_mirror() {
        let rules = |to: &str| {
            Rules::new(&weebo_si_crd::ImageRewriteConfig {
                mode: weebo_si_crd::FeatureMode::Enforce,
                namespace_selector: None,
                rules: vec![weebo_si_crd::RewriteRule {
                    from: "quay.io".to_string(),
                    to: to.to_string(),
                }],
            })
            .unwrap()
        };
        let recorded = BTreeMap::from([
            (
                "clone".to_string(),
                "quay.io/devfile/project-clone:v1".to_string(),
            ),
            ("tools".to_string(), "quay.io/a/tools:1".to_string()),
        ]);
        let components = |clone: &str, tools: &str| {
            vec![
                ("clone".to_string(), clone.to_string()),
                ("tools".to_string(), tools.to_string()),
                ("db".to_string(), "postgres:18".to_string()),
            ]
        };
        let current = rules("registry.pkg.weebo.poc/quay");

        // Rewritten under today's rule: nothing to report.
        let fresh = components(
            "registry.pkg.weebo.poc/quay/devfile/project-clone:v1",
            "registry.pkg.weebo.poc/quay/a/tools:1",
        );
        assert!(stale_mirror(Some(&current), &recorded, &fresh).is_empty());

        // Rewritten under an old `to`; `tools` was re-pointed by its user since.
        let moved = components(
            "old-mirror.example.io/quay/devfile/project-clone:v1",
            "ghcr.io/me/tools:2",
        );
        assert_eq!(
            stale_mirror(Some(&current), &recorded, &moved),
            vec![(
                "clone".to_string(),
                "old-mirror.example.io/quay/devfile/project-clone:v1".to_string(),
                Some("registry.pkg.weebo.poc/quay/devfile/project-clone:v1".to_string()),
            )]
        );

        // The rule removed altogether.
        assert_eq!(stale_mirror(None, &recorded, &fresh).len(), 2);
    }

    #[test]
    fn the_cluster_platform_listing_names_each_derived_pattern_and_its_rule() {
        let rules = Rules::new(&weebo_si_crd::ImageRewriteConfig {
            mode: weebo_si_crd::FeatureMode::DryRun,
            namespace_selector: None,
            rules: vec![weebo_si_crd::RewriteRule {
                from: "quay.io".to_string(),
                to: "registry.pkg.weebo.poc/quay".to_string(),
            }],
        })
        .unwrap();
        let platform = PlatformConfig {
            builtin: true,
            extra: vec!["registry.pkg.weebo.poc/ghcr/x/y:*".to_string()],
        };
        let rows = platform_rows(&platform, Some(&rules));
        assert_eq!(rows.len(), 2 * BUILTIN_PLATFORM_PATTERNS.len() + 1);
        assert_eq!(
            rows[1],
            (
                "registry.pkg.weebo.poc/quay/devfile/project-clone:*@*".to_string(),
                "builtin, rewritten by rule quay.io".to_string()
            )
        );
        assert_eq!(rows.last().unwrap().1, "extra");

        let off = PlatformConfig {
            builtin: false,
            extra: Vec::new(),
        };
        assert!(platform_rows(&off, Some(&rules)).is_empty());
    }

    #[test]
    fn a_listed_namespace_view_answers_labels_and_annotations() {
        use weebo_si_chassis::port::namespace_view::NamespaceView;

        let mut namespace = Namespace::default();
        namespace.metadata.name = Some("user-alice".to_string());
        namespace.metadata.labels = Some(
            [("weebo.io/team".to_string(), "team-1".to_string())]
                .into_iter()
                .collect(),
        );
        namespace.metadata.annotations = Some(
            [("weebo.io/project".to_string(), "apollo".to_string())]
                .into_iter()
                .collect(),
        );
        let view = ListedNamespaces(
            [("user-alice".to_string(), namespace)]
                .into_iter()
                .collect(),
        );

        let ns = NamespaceName::new("user-alice");
        assert_eq!(
            view.facts(&ns).unwrap().labels.get("weebo.io/team"),
            Some(&"team-1".to_string())
        );
        assert_eq!(
            view.annotation(&ns, "weebo.io/project"),
            Some("apollo".to_string())
        );
        assert_eq!(view.annotation(&ns, ""), None);
        assert_eq!(view.annotation(&NamespaceName::new("nope"), "x"), None);
    }
}
