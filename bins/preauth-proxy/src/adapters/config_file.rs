//! Loading the YAML config file and turning it into the validated domain model.
//!
//! Everything about YAML lives here. The domain never sees a `serde` type, and nothing beyond
//! this module can construct a [`Config`] that skipped validation.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;

use crate::domain::config::{
    Acquisition, Config, ConfigError, Inject, InjectMode, Origin, Passthrough, Renew, Take,
    header_name, status_code, substitute,
};

/// Replays permitted after a renewal when `renew.max_replays` is omitted.
const DEFAULT_MAX_REPLAYS: u32 = 1;

/// Why a config file could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The document is not valid YAML, or does not match the schema.
    Malformed(String),
    /// The document parsed but broke a rule.
    Invalid(ConfigError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "config is not valid: {why}"),
            Self::Invalid(err) => write!(f, "config is invalid: {err}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<ConfigError> for LoadError {
    fn from(err: ConfigError) -> Self {
        Self::Invalid(err)
    }
}

/// The file's shape, one-to-one with the documented schema.
///
/// `deny_unknown_fields` throughout: a misspelled key is a startup failure, not a silently
/// ignored line. For a file whose whole job is to describe security-relevant behaviour, "the key
/// you thought you set" is the failure worth catching loudest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    upstream: String,
    passthrough: RawPassthrough,
    credential: RawCredential,
    inject: RawInject,
    #[serde(default)]
    renew: RawRenew,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPassthrough {
    header: String,
    contains: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential {
    origin: String,
    request: RawRequest,
    accept_status: Vec<u16>,
    extract: RawExtract,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    method: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExtract {
    from_header: String,
    take: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInject {
    header: String,
    mode: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRenew {
    #[serde(default)]
    on_status: Vec<u16>,
    max_replays: Option<u32>,
}

fn non_empty(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::Empty(field));
    }
    Ok(())
}

impl RawConfig {
    /// Validate, substitute `${ENV}`, and produce the domain model.
    fn into_domain(self, lookup: &impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
        let listen = self.listen.parse().map_err(|_| ConfigError::Invalid {
            field: "listen".to_owned(),
            value: self.listen.clone(),
            expected: "a socket address such as [::]:8080",
        })?;

        non_empty("passthrough.contains", &self.passthrough.contains)?;

        let method = self
            .credential
            .request
            .method
            .parse()
            .map_err(|_| ConfigError::Invalid {
                field: "credential.request.method".to_owned(),
                value: self.credential.request.method.clone(),
                expected: "an HTTP method",
            })?;

        let path = self.credential.request.path;
        if !path.starts_with('/') {
            return Err(ConfigError::Invalid {
                field: "credential.request.path".to_owned(),
                value: path,
                expected: "a path starting with /",
            });
        }

        if self.credential.accept_status.is_empty() {
            return Err(ConfigError::Empty("credential.accept_status"));
        }

        // `${ENV}` is substituted in header values and in the body, and nowhere else — the
        // secret material belongs in exactly those two places.
        let mut headers = Vec::with_capacity(self.credential.request.headers.len());
        for (name, value) in self.credential.request.headers {
            let parsed = header_name(&format!("credential.request.headers.{name}"), &name)?;
            headers.push((parsed, substitute(&value, lookup)?));
        }

        let accept_status = self
            .credential
            .accept_status
            .into_iter()
            .map(|raw| status_code("credential.accept_status", raw))
            .collect::<Result<Vec<_>, _>>()?;

        let on_status = self
            .renew
            .on_status
            .into_iter()
            .map(|raw| status_code("renew.on_status", raw))
            .collect::<Result<Vec<_>, _>>()?;

        let mode = match self.inject.mode.as_str() {
            "append" => InjectMode::Append,
            "set" => InjectMode::Set,
            other => {
                return Err(ConfigError::Invalid {
                    field: "inject.mode".to_owned(),
                    value: other.to_owned(),
                    expected: "either append or set",
                });
            }
        };

        Ok(Config {
            listen,
            upstream: Origin::parse("upstream", &self.upstream)?,
            passthrough: Passthrough {
                header: header_name("passthrough.header", &self.passthrough.header)?,
                contains: self.passthrough.contains,
            },
            credential: Acquisition {
                origin: Origin::parse("credential.origin", &self.credential.origin)?,
                method,
                path,
                headers,
                body: substitute(&self.credential.request.body, lookup)?,
                accept_status,
                from_header: header_name(
                    "credential.extract.from_header",
                    &self.credential.extract.from_header,
                )?,
                take: Take::parse(&self.credential.extract.take)?,
            },
            inject: Inject {
                header: header_name("inject.header", &self.inject.header)?,
                mode,
            },
            renew: Renew {
                on_status,
                max_replays: self.renew.max_replays.unwrap_or(DEFAULT_MAX_REPLAYS),
            },
        })
    }
}

/// Parse a config document.
///
/// # Errors
///
/// [`LoadError::Malformed`] for a document that is not the documented schema, and
/// [`LoadError::Invalid`] for one that parses but breaks a rule — including an unset `${ENV}`.
pub fn parse(
    document: &str,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Config, LoadError> {
    let raw: RawConfig =
        serde_yaml_bw::from_str(document).map_err(|err| LoadError::Malformed(err.to_string()))?;
    Ok(raw.into_domain(lookup)?)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use http::{Method, StatusCode};
    use std::collections::HashMap;

    /// The documented example, verbatim from the RFC's *Guide-level explanation*.
    const EXAMPLE: &str = r#"
listen: "[::]:8080"
upstream: "http://app:3000"

passthrough:
  header: Cookie
  contains: "session="

credential:
  origin: "http://app-auth:8000"
  request:
    method: POST
    path: "/login"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
      X-Forwarded-Proto: "https"
    body: "email=${CRED_USER}&password=${CRED_SECRET}"
  accept_status: [200, 302, 303]
  extract:
    from_header: "Set-Cookie"
    take: cookie-pair

inject:
  header: Cookie
  mode: append

renew:
  on_status: [401]
  max_replays: 1
"#;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    fn creds() -> impl Fn(&str) -> Option<String> {
        env(&[
            ("CRED_USER", "svc@example.test"),
            ("CRED_SECRET", "hunter2"),
        ])
    }

    #[test]
    fn the_documented_example_parses() {
        let config = parse(EXAMPLE, &creds()).unwrap();

        assert_eq!(config.listen.to_string(), "[::]:8080");
        assert_eq!(config.upstream.authority(), "app:3000");
        assert_eq!(config.passthrough.header, http::header::COOKIE);
        assert_eq!(config.passthrough.contains, "session=");

        assert_eq!(config.credential.origin.authority(), "app-auth:8000");
        assert_eq!(config.credential.method, Method::POST);
        assert_eq!(config.credential.path, "/login");
        assert_eq!(
            config.credential.body,
            "email=svc@example.test&password=hunter2"
        );
        assert_eq!(
            config.credential.accept_status,
            vec![StatusCode::OK, StatusCode::FOUND, StatusCode::SEE_OTHER]
        );
        assert_eq!(config.credential.take, Take::CookiePair);

        assert_eq!(config.inject.mode, InjectMode::Append);
        assert_eq!(config.renew.on_status, vec![StatusCode::UNAUTHORIZED]);
        assert_eq!(config.renew.max_replays, 1);
    }

    #[test]
    fn header_values_are_substituted_and_names_validated() {
        let config = parse(EXAMPLE, &creds()).unwrap();
        let names: Vec<_> = config
            .credential
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.clone()))
            .collect();
        assert!(names.contains(&(
            "content-type".to_owned(),
            "application/x-www-form-urlencoded".to_owned()
        )));
    }

    #[test]
    fn an_unset_env_reference_fails_the_load() {
        let err = parse(EXAMPLE, &env(&[("CRED_USER", "svc")])).unwrap_err();
        assert!(
            matches!(err, LoadError::Invalid(ConfigError::UnsetEnv(ref name)) if name == "CRED_SECRET"),
            "{err}"
        );
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let doc = EXAMPLE.replace("max_replays: 1", "max_replays: 1\n  max_retries: 4");
        let err = parse(&doc, &creds()).unwrap_err();
        assert!(matches!(err, LoadError::Malformed(_)), "{err}");
    }

    #[test]
    fn a_missing_required_key_is_refused() {
        let doc = EXAMPLE.replace("upstream: \"http://app:3000\"", "");
        let err = parse(&doc, &creds()).unwrap_err();
        assert!(matches!(err, LoadError::Malformed(_)), "{err}");
    }

    #[test]
    fn malformed_yaml_is_an_error_not_a_panic() {
        for bad in ["listen: [", "\t- nope", "{{{", ""] {
            assert!(parse(bad, &creds()).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn renew_is_optional_and_defaults_to_one_replay() {
        let doc = EXAMPLE.replace("renew:\n  on_status: [401]\n  max_replays: 1\n", "");
        let config = parse(&doc, &creds()).unwrap();
        assert!(config.renew.on_status.is_empty(), "renewal stays disabled");
        assert_eq!(config.renew.max_replays, DEFAULT_MAX_REPLAYS);
    }

    #[test]
    fn every_field_level_rule_is_enforced() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "listen",
                "listen: \"[::]:8080\"",
                "listen: \"not-an-address\"",
            ),
            (
                "upstream scheme",
                "upstream: \"http://app:3000\"",
                "upstream: \"https://app:3000\"",
            ),
            (
                "origin scheme",
                "origin: \"http://app-auth:8000\"",
                "origin: \"ftp://app-auth:8000\"",
            ),
            ("method", "method: POST", "method: \"NOT A METHOD\""),
            ("path", "path: \"/login\"", "path: \"login\""),
            (
                "accept_status empty",
                "accept_status: [200, 302, 303]",
                "accept_status: []",
            ),
            (
                "accept_status range",
                "accept_status: [200, 302, 303]",
                "accept_status: [99]",
            ),
            ("take", "take: cookie-pair", "take: \"regex:.*\""),
            ("inject mode", "mode: append", "mode: replace"),
            (
                "passthrough contains",
                "contains: \"session=\"",
                "contains: \"\"",
            ),
            (
                "header name",
                "header: Cookie\n  contains",
                "header: \"not a header\"\n  contains",
            ),
        ];

        for (label, from, to) in cases {
            let doc = EXAMPLE.replace(from, to);
            assert_ne!(
                doc, EXAMPLE,
                "{label}: the fixture substitution did not apply"
            );
            assert!(parse(&doc, &creds()).is_err(), "{label}: should be refused");
        }
    }
}
