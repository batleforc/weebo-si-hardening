//! `{VARIABLE}` rendering for the per-user workspace template — RFC 0011's *Template variables*.
//!
//! The syntax, the legality rule and the fail-closed treatment of an unknown name are RFC 0005's,
//! deliberately: an admin reading `{USERNAME}-che` here and `registry.internal/{TEAM_NAME}/**` in
//! `spec.features.imagePolicy` is reading one notation, not two.
//!
//! What is **not** shared is the substitution model, and the difference is worth stating where
//! somebody will read it. `image-policy` refuses to interpolate into its patterns at all — a
//! substituted value there would change what an allow-list matches, so it resolves into a parsed
//! slot instead ([`crate::image_policy`], and `weebo-si-image-policy`'s `variable` module says it
//! at length). Here the rendered string *is* the product: a Helm value, a namespace name, an
//! object name. Two properties keep that honest — substitution only ever produces a string scalar
//! inside an already-parsed [`serde_json::Value`], so no value can grow structure around itself,
//! and a rendered namespace is validated against DNS-1123 before it leaves this module.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;

use crate::image_policy::is_legal_variable_name;

/// The person's Kubernetes identity — `WeeboSiUser.spec.username`.
pub const USERNAME: &str = "USERNAME";
/// The `WeeboSiUser`'s own `metadata.name`.
pub const OBJECT_NAME: &str = "OBJECT_NAME";
/// The team the person belongs to, empty when they have none.
pub const TEAM_NAME: &str = "TEAM_NAME";
/// The person's email, empty when unset.
pub const EMAIL: &str = "EMAIL";
/// The person's display name, defaulted to their username.
pub const DISPLAY_NAME: &str = "DISPLAY_NAME";
/// The rendered destination namespace. Bound only in the second pass — see [`Bindings`].
pub const USER_NAMESPACE: &str = "USER_NAMESPACE";

/// Every variable a workspace template may name. A closed set: there is no way to declare one,
/// because every value here is resolved by the operator from an object it already has.
pub const TEMPLATE_VARIABLES: [&str; 6] = [
    USERNAME,
    OBJECT_NAME,
    TEAM_NAME,
    EMAIL,
    DISPLAY_NAME,
    USER_NAMESPACE,
];

/// The values [`render`] substitutes, by variable name.
///
/// Built in two passes, because `{USER_NAMESPACE}` is itself rendered: the first pass resolves
/// `destination.namespace` from the five variables a `WeeboSiUser` carries directly, and the
/// second renders everything else with the result bound as well. A template naming
/// `{USER_NAMESPACE}` inside the namespace template is therefore an unknown variable rather than
/// a loop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bindings {
    values: BTreeMap<String, String>,
}

impl Bindings {
    /// An empty binding set. Rendering anything with a variable in it fails until something is
    /// bound — the fail-closed direction.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind one variable, builder-style.
    pub fn bind(mut self, name: &str, value: impl Into<String>) -> Self {
        self.values.insert(name.to_owned(), value.into());
        self
    }

    /// The value bound to `name`, if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
}

/// One way a template can refuse to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// A name inside `{...}` is not bound, or is not a legal variable name. The two are one
    /// error on purpose: `{TEMA_NAME}` and `{team_name}` are both typos, and treating either as
    /// a literal would produce an object nobody asked for.
    UnknownVariable {
        /// The template, as written.
        template: String,
        /// The offending name.
        variable: String,
    },
    /// A `{` with no matching `}`, or a `{{` with no matching `}}`.
    UnterminatedVariable {
        /// The template, as written.
        template: String,
    },
    /// A rendered namespace is not a DNS-1123 label, so no namespace could carry the name.
    IllegalNamespace {
        /// The template, as written.
        template: String,
        /// What it rendered to.
        rendered: String,
    },
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVariable { template, variable } => write!(
                f,
                "template {template} names unknown variable {{{variable}}}"
            ),
            Self::UnterminatedVariable { template } => {
                write!(f, "template {template} has a '{{' with no matching '}}'")
            }
            Self::IllegalNamespace { template, rendered } => write!(
                f,
                "template {template} rendered to {rendered}, which is not a legal namespace name"
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Render one template string. `{{ ... }}` is copied through verbatim; every other `{` opens a
/// variable and has to close.
pub fn render(template: &str, bindings: &Bindings) -> Result<String, TemplateError> {
    render_with(template, &mut |name| bindings.get(name).map(str::to_owned))
}

/// Every variable a template names, in order, with duplicates kept.
///
/// The half of rendering a validator can run with no person in hand: it answers "does this
/// template name anything the operator cannot resolve" at reconcile, rather than at the first
/// onboarding.
pub fn variables(template: &str) -> Result<Vec<String>, TemplateError> {
    let mut found = Vec::new();
    render_with(template, &mut |name| {
        found.push(name.to_owned());
        Some(String::new())
    })?;
    Ok(found)
}

/// The one parser. `render` binds through it, `variables` records through it — so the two can
/// never disagree about where a variable starts.
fn render_with(
    template: &str,
    lookup: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<String, TemplateError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];

        // `{{ ... }}` is somebody else's template — Helm's, usually — and is copied through
        // verbatim, braces included. Rendering it would hand Helm a string it can no longer read,
        // and refusing it would ban every chart value that contains one.
        if after.starts_with('{') {
            let Some(close) = after.find("}}") else {
                return Err(TemplateError::UnterminatedVariable {
                    template: template.to_owned(),
                });
            };
            out.push('{');
            out.push_str(&after[..close + 2]);
            rest = &after[close + 2..];
            continue;
        }

        let Some(close) = after.find('}') else {
            return Err(TemplateError::UnterminatedVariable {
                template: template.to_owned(),
            });
        };

        let name = &after[..close];
        if !is_legal_variable_name(name) {
            return Err(TemplateError::UnknownVariable {
                template: template.to_owned(),
                variable: name.to_owned(),
            });
        }
        let Some(value) = lookup(name) else {
            return Err(TemplateError::UnknownVariable {
                template: template.to_owned(),
                variable: name.to_owned(),
            });
        };
        out.push_str(&value);
        rest = &after[close + 1..];
    }

    out.push_str(rest);
    Ok(out)
}

/// Render a template that has to name a namespace, and check that it does.
///
/// The check is here rather than at the call site because every caller wants it and one that
/// forgot would hand the API server a name it refuses — a reconcile error where a `Degraded`
/// condition naming the template belongs.
pub fn render_namespace(template: &str, bindings: &Bindings) -> Result<String, TemplateError> {
    let rendered = render(template, bindings)?;
    if is_dns_label(&rendered) {
        Ok(rendered)
    } else {
        Err(TemplateError::IllegalNamespace {
            template: template.to_owned(),
            rendered,
        })
    }
}

/// Render every string inside a free-form value tree, recursively.
///
/// Strings only: object keys are left exactly as written, so a rendered value can never become a
/// key, and a number or a boolean is never reinterpreted as text.
pub fn render_value(value: &Value, bindings: &Bindings) -> Result<Value, TemplateError> {
    match value {
        Value::String(text) => Ok(Value::String(render(text, bindings)?)),
        Value::Array(items) => items
            .iter()
            .map(|item| render_value(item, bindings))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(fields) => {
            let mut rendered = serde_json::Map::with_capacity(fields.len());
            for (key, field) in fields {
                rendered.insert(key.clone(), render_value(field, bindings)?);
            }
            Ok(Value::Object(rendered))
        }
        other => Ok(other.clone()),
    }
}

/// Deep-merge `overlay` over `base`: objects merge key by key, everything else is replaced.
///
/// Helm's own merge semantics, and the reason a person overriding `storage.size` does not lose
/// the rest of their team's `storage` block. An array is replaced rather than concatenated, which
/// is also Helm's rule and the one people expect after being surprised by it once.
pub fn merge_values(base: &Value, overlay: &Value) -> Value {
    match (base, overlay) {
        (Value::Object(base_fields), Value::Object(overlay_fields)) => {
            let mut merged = base_fields.clone();
            for (key, value) in overlay_fields {
                let next = match merged.get(key) {
                    Some(existing) => merge_values(existing, value),
                    None => value.clone(),
                };
                merged.insert(key.clone(), next);
            }
            Value::Object(merged)
        }
        _ => overlay.clone(),
    }
}

/// Whether `name` is a DNS-1123 label: lowercase alphanumerics and `-`, no leading or trailing
/// `-`, at most 63 characters, never empty.
fn is_dns_label(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn bindings() -> Bindings {
        Bindings::new()
            .bind(USERNAME, "max")
            .bind(OBJECT_NAME, "max")
            .bind(TEAM_NAME, "platform")
            .bind(EMAIL, "max@weebo.io")
            .bind(DISPLAY_NAME, "Max")
    }

    #[test]
    fn renders_every_bound_variable() {
        assert_eq!(
            render("{USERNAME}-che", &bindings()).unwrap(),
            "max-che".to_string()
        );
        assert_eq!(
            render("{DISPLAY_NAME} <{EMAIL}>", &bindings()).unwrap(),
            "Max <max@weebo.io>".to_string()
        );
    }

    #[test]
    fn somebody_elses_template_is_copied_through_verbatim() {
        assert_eq!(
            render("{{ .Values.x }}", &bindings()).unwrap(),
            "{{ .Values.x }}".to_string()
        );
        assert_eq!(
            render("{USERNAME}: {{ .Release.Name }}", &bindings()).unwrap(),
            "max: {{ .Release.Name }}".to_string()
        );
    }

    #[test]
    fn an_unterminated_passthrough_is_refused() {
        assert!(matches!(
            render("{{ .Values.x }", &bindings()),
            Err(TemplateError::UnterminatedVariable { .. })
        ));
    }

    #[test]
    fn an_unbound_variable_is_an_error_not_a_literal() {
        let err = render("{USER_NAMESPACE}/x", &bindings()).unwrap_err();
        assert_eq!(
            err,
            TemplateError::UnknownVariable {
                template: "{USER_NAMESPACE}/x".to_string(),
                variable: USER_NAMESPACE.to_string(),
            }
        );
    }

    #[test]
    fn a_misspelled_variable_is_never_a_literal() {
        assert!(matches!(
            render("{team_name}", &bindings()),
            Err(TemplateError::UnknownVariable { .. })
        ));
    }

    #[test]
    fn an_unterminated_variable_is_refused() {
        assert!(matches!(
            render("{USERNAME", &bindings()),
            Err(TemplateError::UnterminatedVariable { .. })
        ));
    }

    #[test]
    fn a_rendered_namespace_has_to_be_one() {
        let illegal = bindings().bind(USERNAME, "Max.Leriche");
        assert!(matches!(
            render_namespace("{USERNAME}-che", &illegal),
            Err(TemplateError::IllegalNamespace { .. })
        ));
        assert_eq!(
            render_namespace("{USERNAME}-che", &bindings().bind(USERNAME, "max")).unwrap(),
            "max-che".to_string()
        );
    }

    #[test]
    fn values_render_in_place_and_keys_do_not() {
        let value = serde_json::json!({
            "{USERNAME}": "{USERNAME}",
            "list": ["{TEAM_NAME}", 3, true],
        });
        let rendered = render_value(&value, &bindings()).unwrap();
        assert_eq!(
            rendered,
            serde_json::json!({
                "{USERNAME}": "max",
                "list": ["platform", 3, true],
            })
        );
    }

    #[test]
    fn merging_keeps_the_sibling_keys_of_an_overridden_one() {
        let base = serde_json::json!({"storage": {"size": "10Gi", "class": "fast"}});
        let overlay = serde_json::json!({"storage": {"size": "30Gi"}});
        assert_eq!(
            merge_values(&base, &overlay),
            serde_json::json!({"storage": {"size": "30Gi", "class": "fast"}})
        );
    }

    #[test]
    fn merging_replaces_an_array_rather_than_appending() {
        let base = serde_json::json!({"args": ["a", "b"]});
        let overlay = serde_json::json!({"args": ["c"]});
        assert_eq!(
            merge_values(&base, &overlay),
            serde_json::json!({"args": ["c"]})
        );
    }
}
