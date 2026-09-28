//! The Argo CD `Application` template a team carries, and the object one person renders it to —
//! RFC 0011's *What gets created*.
//!
//! The template is deliberately shaped like an `ApplicationSet` template rather than like a
//! wrapper of our own: `source`, `destination`, `project` and `syncPolicy` are upstream's fields
//! under upstream's names. RFC 0011's *Alternatives considered* keeps the plugin generator open
//! as a back end, and a template that already speaks Argo's vocabulary is what makes that a
//! swap rather than a redesign.
//!
//! Only the fields this operator writes are modelled. An `Application` has many more; carrying
//! them would mean tracking upstream's schema in this crate forever, and every one left out is a
//! field a team cannot set — which is the trade RFC 0011's *Drawbacks* names.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::identity::ProvisioningMode;
use crate::template::{self, Bindings, TEMPLATE_VARIABLES, TemplateError, USER_NAMESPACE};

/// The default `metadata.name` template: the `WeeboSiUser`'s own object name.
const DEFAULT_NAME_TEMPLATE: &str = "{OBJECT_NAME}";

/// `spec.workspace.che` on a `WeeboSiTeam` — one `Application` per member, rendered per person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationTemplate {
    /// Required when the block is present, per the chassis rule that a behaviour nobody wrote
    /// down does not run: `Off` keeps the template without acting on it, which is how a team
    /// stops provisioning for everybody without losing what it configured.
    pub mode: ProvisioningMode,
    /// The `Application`'s own name, templated. Defaults to `{OBJECT_NAME}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The Argo CD project, which is the outer fence this operator relies on rather than
    /// reimplements. Checked against `spec.features.identity.che.allowedProjects`.
    pub project: String,
    /// Where the chart comes from.
    pub source: ApplicationSource,
    /// Where it is deployed.
    pub destination: ApplicationDestination,
    /// Passed through verbatim — this operator has no opinion on how Argo syncs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_policy: Option<SyncPolicy>,
}

/// `spec.source` of the rendered `Application`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSource {
    /// The chart repository or the git repository. Prefix-checked against
    /// `spec.features.identity.che.allowedRepoUrls`.
    pub repo_url: String,
    /// A Helm chart name. Exactly one of `chart` and `path` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chart: Option<String>,
    /// A path inside a git repository. Exactly one of `chart` and `path` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Chart version, git revision, or branch.
    pub target_revision: String,
    /// The base Helm values every member of this team gets, templated. A person's own
    /// `spec.che.values` is deep-merged over this.
    ///
    /// Free-form, and the only free-form field in this crate — see [`crate::free_form`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::free_form::object_schema")]
    pub values: Option<Value>,
}

/// `spec.destination` of the rendered `Application`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationDestination {
    /// The cluster API URL. Exactly one of `server` and `name` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The cluster's registered name in Argo CD. Exactly one of `server` and `name` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The namespace, templated. Its rendered value is what `{USER_NAMESPACE}` binds to
    /// everywhere else, so it is resolved first and cannot name that variable itself.
    pub namespace: String,
}

/// `spec.syncPolicy`, carried through unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncPolicy {
    /// Automated sync, absent for manual.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automated: Option<SyncAutomated>,
    /// Sync options, e.g. `CreateNamespace=true`.
    #[serde(default)]
    pub options: Vec<String>,
}

/// `spec.syncPolicy.automated`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncAutomated {
    /// Delete resources no longer in the chart.
    #[serde(default)]
    pub prune: bool,
    /// Revert drift written by hand.
    #[serde(default)]
    pub self_heal: bool,
}

/// One way a template is malformed on its own terms, before any allow-list or any person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationTemplateViolation {
    /// Neither `chart` nor `path` is set, or both are.
    SourceNotExactlyOne,
    /// Neither `server` nor `name` is set, or both are.
    DestinationNotExactlyOne,
    /// A required string is empty. An empty `project` or `repoUrl` renders an `Application` the
    /// API server accepts and Argo never syncs, which is worse than a refusal.
    EmptyField(&'static str),
    /// A template names a variable the operator cannot resolve, or does not parse.
    Template(TemplateError),
    /// The destination namespace names `{USER_NAMESPACE}`, which is itself.
    NamespaceNamesItself,
}

impl fmt::Display for ApplicationTemplateViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceNotExactlyOne => {
                write!(f, "source must set exactly one of 'chart' and 'path'")
            }
            Self::DestinationNotExactlyOne => {
                write!(f, "destination must set exactly one of 'server' and 'name'")
            }
            Self::EmptyField(field) => write!(f, "{field} is empty"),
            Self::Template(err) => write!(f, "{err}"),
            Self::NamespaceNamesItself => write!(
                f,
                "destination.namespace names {{{USER_NAMESPACE}}}, which is the namespace it defines"
            ),
        }
    }
}

impl ApplicationTemplate {
    /// Every way this template is malformed, independently of the cluster's allow-lists and of
    /// any person — so a team gets told at apply time rather than at somebody's first day.
    pub fn validate_shape(&self) -> Vec<ApplicationTemplateViolation> {
        let mut violations = Vec::new();

        if self.source.chart.is_some() == self.source.path.is_some() {
            violations.push(ApplicationTemplateViolation::SourceNotExactlyOne);
        }
        if self.destination.server.is_some() == self.destination.name.is_some() {
            violations.push(ApplicationTemplateViolation::DestinationNotExactlyOne);
        }
        if self.project.trim().is_empty() {
            violations.push(ApplicationTemplateViolation::EmptyField("project"));
        }
        if self.source.repo_url.trim().is_empty() {
            violations.push(ApplicationTemplateViolation::EmptyField("source.repoUrl"));
        }
        if self.source.target_revision.trim().is_empty() {
            violations.push(ApplicationTemplateViolation::EmptyField(
                "source.targetRevision",
            ));
        }

        for (field, template) in self.templates() {
            match template::variables(template) {
                Ok(names) => {
                    for name in names {
                        if !TEMPLATE_VARIABLES.contains(&name.as_str()) {
                            violations.push(ApplicationTemplateViolation::Template(
                                TemplateError::UnknownVariable {
                                    template: template.to_owned(),
                                    variable: name,
                                },
                            ));
                        } else if field == "destination.namespace" && name == USER_NAMESPACE {
                            violations.push(ApplicationTemplateViolation::NamespaceNamesItself);
                        }
                    }
                }
                Err(err) => violations.push(ApplicationTemplateViolation::Template(err)),
            }
        }

        if let Some(values) = &self.source.values {
            collect_value_violations(values, &mut violations);
        }

        violations
    }

    /// Every templated string on this object, with the field name a violation reports.
    fn templates(&self) -> Vec<(&'static str, &str)> {
        let mut templates = vec![
            (
                "name",
                self.name.as_deref().unwrap_or(DEFAULT_NAME_TEMPLATE),
            ),
            ("source.repoUrl", self.source.repo_url.as_str()),
            (
                "source.targetRevision",
                self.source.target_revision.as_str(),
            ),
            ("destination.namespace", self.destination.namespace.as_str()),
        ];
        if let Some(chart) = &self.source.chart {
            templates.push(("source.chart", chart));
        }
        if let Some(path) = &self.source.path {
            templates.push(("source.path", path));
        }
        templates
    }

    /// Render this template for one person.
    ///
    /// `base` carries the five variables a `WeeboSiUser` resolves directly; `{USER_NAMESPACE}` is
    /// bound here, from `namespace_override` or from the rendered `destination.namespace`, and is
    /// available to every other field — the two passes RFC 0011's *Template variables* specifies.
    pub fn render(
        &self,
        application_namespace: &str,
        base: &Bindings,
        namespace_override: Option<&str>,
        overlay_values: Option<&Value>,
    ) -> Result<RenderedApplication, TemplateError> {
        let namespace = match namespace_override {
            Some(namespace) => template::render_namespace(namespace, base)?,
            None => template::render_namespace(&self.destination.namespace, base)?,
        };
        let bindings = base.clone().bind(USER_NAMESPACE, namespace.clone());

        let values = match (&self.source.values, overlay_values) {
            (Some(base_values), Some(overlay)) => Some(template::merge_values(
                &template::render_value(base_values, &bindings)?,
                &template::render_value(overlay, &bindings)?,
            )),
            (Some(base_values), None) => Some(template::render_value(base_values, &bindings)?),
            (None, Some(overlay)) => Some(template::render_value(overlay, &bindings)?),
            (None, None) => None,
        };

        Ok(RenderedApplication {
            name: template::render(
                self.name.as_deref().unwrap_or(DEFAULT_NAME_TEMPLATE),
                &bindings,
            )?,
            namespace: application_namespace.to_owned(),
            project: self.project.clone(),
            source: ApplicationSource {
                repo_url: template::render(&self.source.repo_url, &bindings)?,
                chart: self
                    .source
                    .chart
                    .as_deref()
                    .map(|chart| template::render(chart, &bindings))
                    .transpose()?,
                path: self
                    .source
                    .path
                    .as_deref()
                    .map(|path| template::render(path, &bindings))
                    .transpose()?,
                target_revision: template::render(&self.source.target_revision, &bindings)?,
                values,
            },
            destination: ApplicationDestination {
                server: self.destination.server.clone(),
                name: self.destination.name.clone(),
                namespace,
            },
            sync_policy: self.sync_policy.clone(),
        })
    }
}

/// One `Application` this operator would write, with every template resolved.
///
/// A value, not an API call: the reconcile loop compares it against what the cluster has, and the
/// tests compare it against what the RFC says. Turning it into an object is
/// [`RenderedApplication::spec`] plus the metadata the adapter owns.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedApplication {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.namespace` — always `spec.features.identity.che.applicationNamespace`, never a
    /// value a team chose. One namespace is what keeps this operator's RBAC to one namespace.
    pub namespace: String,
    /// `spec.project`.
    pub project: String,
    /// `spec.source`.
    pub source: ApplicationSource,
    /// `spec.destination`.
    pub destination: ApplicationDestination,
    /// `spec.syncPolicy`.
    pub sync_policy: Option<SyncPolicy>,
}

impl RenderedApplication {
    /// The `spec` of the `argoproj.io/v1alpha1` `Application` this renders to.
    ///
    /// Built as JSON rather than through an upstream type: depending on Argo CD's Rust bindings
    /// for five fields would be a dependency on their whole schema, and the mapping is short
    /// enough to read against RFC 0011's table.
    pub fn spec(&self) -> Value {
        let mut source = serde_json::Map::new();
        source.insert(
            "repoURL".to_owned(),
            Value::String(self.source.repo_url.clone()),
        );
        source.insert(
            "targetRevision".to_owned(),
            Value::String(self.source.target_revision.clone()),
        );
        if let Some(chart) = &self.source.chart {
            source.insert("chart".to_owned(), Value::String(chart.clone()));
        }
        if let Some(path) = &self.source.path {
            source.insert("path".to_owned(), Value::String(path.clone()));
        }
        if let Some(values) = &self.source.values {
            let mut helm = serde_json::Map::new();
            helm.insert("valuesObject".to_owned(), values.clone());
            source.insert("helm".to_owned(), Value::Object(helm));
        }

        let mut destination = serde_json::Map::new();
        destination.insert(
            "namespace".to_owned(),
            Value::String(self.destination.namespace.clone()),
        );
        if let Some(server) = &self.destination.server {
            destination.insert("server".to_owned(), Value::String(server.clone()));
        }
        if let Some(name) = &self.destination.name {
            destination.insert("name".to_owned(), Value::String(name.clone()));
        }

        let mut spec = serde_json::Map::new();
        spec.insert("project".to_owned(), Value::String(self.project.clone()));
        spec.insert("source".to_owned(), Value::Object(source));
        spec.insert("destination".to_owned(), Value::Object(destination));
        if let Some(policy) = &self.sync_policy {
            let mut sync = serde_json::Map::new();
            if let Some(automated) = &policy.automated {
                let mut auto = serde_json::Map::new();
                auto.insert("prune".to_owned(), Value::Bool(automated.prune));
                auto.insert("selfHeal".to_owned(), Value::Bool(automated.self_heal));
                sync.insert("automated".to_owned(), Value::Object(auto));
            }
            if !policy.options.is_empty() {
                sync.insert(
                    "syncOptions".to_owned(),
                    Value::Array(
                        policy
                            .options
                            .iter()
                            .map(|option| Value::String(option.clone()))
                            .collect(),
                    ),
                );
            }
            spec.insert("syncPolicy".to_owned(), Value::Object(sync));
        }

        Value::Object(spec)
    }
}

/// Walk a free-form value tree and report every template inside it that cannot render.
fn collect_value_violations(value: &Value, violations: &mut Vec<ApplicationTemplateViolation>) {
    match value {
        Value::String(text) => match template::variables(text) {
            Ok(names) => {
                for name in names {
                    if !TEMPLATE_VARIABLES.contains(&name.as_str()) {
                        violations.push(ApplicationTemplateViolation::Template(
                            TemplateError::UnknownVariable {
                                template: text.clone(),
                                variable: name,
                            },
                        ));
                    }
                }
            }
            Err(err) => violations.push(ApplicationTemplateViolation::Template(err)),
        },
        Value::Array(items) => {
            for item in items {
                collect_value_violations(item, violations);
            }
        }
        Value::Object(fields) => {
            for field in fields.values() {
                collect_value_violations(field, violations);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::template::{DISPLAY_NAME, EMAIL, OBJECT_NAME, TEAM_NAME, USERNAME};

    fn template() -> ApplicationTemplate {
        ApplicationTemplate {
            mode: ProvisioningMode::Ensure,
            name: Some("che-{USERNAME}".to_string()),
            project: "weebo-dev".to_string(),
            source: ApplicationSource {
                repo_url: "https://charts.weebo.io".to_string(),
                chart: Some("che-user".to_string()),
                path: None,
                target_revision: "1.4.2".to_string(),
                values: Some(serde_json::json!({
                    "username": "{USERNAME}",
                    "namespace": "{USER_NAMESPACE}",
                    "storage": {"size": "10Gi", "class": "fast"},
                })),
            },
            destination: ApplicationDestination {
                server: Some("https://kubernetes.default.svc".to_string()),
                name: None,
                namespace: "{USERNAME}-che".to_string(),
            },
            sync_policy: Some(SyncPolicy {
                automated: Some(SyncAutomated {
                    prune: true,
                    self_heal: true,
                }),
                options: vec!["CreateNamespace=true".to_string()],
            }),
        }
    }

    fn bindings() -> Bindings {
        Bindings::new()
            .bind(USERNAME, "max")
            .bind(OBJECT_NAME, "max")
            .bind(TEAM_NAME, "platform")
            .bind(EMAIL, "max@weebo.io")
            .bind(DISPLAY_NAME, "Max")
    }

    #[test]
    fn a_clean_template_has_no_violation() {
        assert_eq!(template().validate_shape(), Vec::new());
    }

    #[test]
    fn a_source_naming_both_chart_and_path_is_refused() {
        let mut template = template();
        template.source.path = Some("charts/che".to_string());
        assert!(
            template
                .validate_shape()
                .contains(&ApplicationTemplateViolation::SourceNotExactlyOne)
        );
    }

    #[test]
    fn a_namespace_naming_itself_is_refused() {
        let mut template = template();
        template.destination.namespace = "{USER_NAMESPACE}".to_string();
        assert!(
            template
                .validate_shape()
                .contains(&ApplicationTemplateViolation::NamespaceNamesItself)
        );
    }

    #[test]
    fn an_unknown_variable_inside_values_is_found() {
        let mut template = template();
        template.source.values = Some(serde_json::json!({"who": "{WHOEVER}"}));
        assert!(matches!(
            template.validate_shape().as_slice(),
            [ApplicationTemplateViolation::Template(
                TemplateError::UnknownVariable { .. }
            )]
        ));
    }

    #[test]
    fn rendering_binds_the_namespace_it_just_resolved() {
        let rendered = template()
            .render("argocd", &bindings(), None, None)
            .unwrap();
        assert_eq!(rendered.name, "che-max".to_string());
        assert_eq!(rendered.namespace, "argocd".to_string());
        assert_eq!(rendered.destination.namespace, "max-che".to_string());
        assert_eq!(
            rendered.source.values,
            Some(serde_json::json!({
                "username": "max",
                "namespace": "max-che",
                "storage": {"size": "10Gi", "class": "fast"},
            }))
        );
    }

    #[test]
    fn a_person_overrides_one_value_and_keeps_its_siblings() {
        let overlay = serde_json::json!({"storage": {"size": "30Gi"}});
        let rendered = template()
            .render("argocd", &bindings(), None, Some(&overlay))
            .unwrap();
        assert_eq!(
            rendered.source.values,
            Some(serde_json::json!({
                "username": "max",
                "namespace": "max-che",
                "storage": {"size": "30Gi", "class": "fast"},
            }))
        );
    }

    #[test]
    fn a_namespace_override_wins_and_rebinds_the_variable() {
        let rendered = template()
            .render("argocd", &bindings(), Some("max-sandbox"), None)
            .unwrap();
        assert_eq!(rendered.destination.namespace, "max-sandbox".to_string());
        assert_eq!(
            rendered.source.values.unwrap()["namespace"],
            serde_json::json!("max-sandbox")
        );
    }

    #[test]
    fn the_rendered_spec_uses_upstream_field_names() {
        let spec = template()
            .render("argocd", &bindings(), None, None)
            .unwrap()
            .spec();
        assert_eq!(spec["project"], serde_json::json!("weebo-dev"));
        assert_eq!(
            spec["source"]["repoURL"],
            serde_json::json!("https://charts.weebo.io")
        );
        assert_eq!(spec["source"]["chart"], serde_json::json!("che-user"));
        assert_eq!(
            spec["source"]["helm"]["valuesObject"]["username"],
            serde_json::json!("max")
        );
        assert_eq!(
            spec["destination"]["namespace"],
            serde_json::json!("max-che")
        );
        assert_eq!(
            spec["syncPolicy"]["syncOptions"],
            serde_json::json!(["CreateNamespace=true"])
        );
        assert_eq!(
            spec["syncPolicy"]["automated"]["selfHeal"],
            serde_json::json!(true)
        );
    }
}
