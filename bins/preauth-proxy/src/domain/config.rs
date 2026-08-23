//! The validated configuration model, and the `${ENV}` substitution that fills it.
//!
//! Pure. Parsing a YAML document is an adapter concern
//! ([`crate::adapters::config_file`]); what lives here is the shape the rest of the binary is
//! allowed to see, and the rules that shape has to satisfy before anything else runs.
//!
//! The vocabulary is deliberately generic — *marker*, *credential*, *exchange*, *injection*.
//! Nothing here names a cookie type, a session, an auth protocol or an application. Those are
//! values an operator writes, and they are the only place a deployment's actual purpose is
//! legible.

use std::fmt;
use std::net::SocketAddr;

use http::{HeaderName, Method, StatusCode};

/// Why a configuration was refused.
///
/// Every variant is a startup failure (exit `2`): a config the binary cannot fully understand is
/// never partially applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A `${NAME}` reference whose variable is not set. Never treated as an empty string.
    UnsetEnv(String),
    /// A `${` with no closing brace.
    MalformedReference(String),
    /// A required value was empty.
    Empty(&'static str),
    /// A field did not parse as the type it must be.
    Invalid {
        /// Dotted path of the offending key, as written in the file.
        field: String,
        /// The value that failed.
        value: String,
        /// What was expected instead.
        expected: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsetEnv(name) => {
                write!(f, "${{{name}}} is referenced but the variable is not set")
            }
            Self::MalformedReference(raw) => write!(f, "malformed ${{...}} reference in {raw:?}"),
            Self::Empty(field) => write!(f, "{field} must not be empty"),
            Self::Invalid {
                field,
                value,
                expected,
            } => write!(f, "{field}: {value:?} is not {expected}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Replace every `${NAME}` in `template` using `lookup`.
///
/// An unset variable is a [`ConfigError::UnsetEnv`], not an empty string — a credential silently
/// becoming `password=` is the failure mode this rule exists to prevent. A bare `$` not followed
/// by `{` is a literal.
///
/// # Errors
///
/// Returns on the first unset or malformed reference.
pub fn substitute(
    template: &str,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let Some(close) = after.find('}') else {
            return Err(ConfigError::MalformedReference(template.to_owned()));
        };
        let name = &after[..close];
        if name.is_empty() {
            return Err(ConfigError::MalformedReference(template.to_owned()));
        }
        let value = lookup(name).ok_or_else(|| ConfigError::UnsetEnv(name.to_owned()))?;
        out.push_str(&value);
        rest = &after[close + 1..];
    }

    out.push_str(rest);
    Ok(out)
}

/// A plain-HTTP origin the proxy talks to.
///
/// Only `http://` is accepted. Both origins this brick speaks to are in-cluster services reached
/// over the pod network; a `https://` origin would need a TLS stack and a trust decision that is
/// not in this RFC, so it is refused loudly rather than silently downgraded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// `host:port`, ready to use as an HTTP/1.1 `Host` header and a connection target.
    authority: String,
}

impl Origin {
    /// Parse an `http://host[:port]` origin.
    ///
    /// # Errors
    ///
    /// Rejects any scheme other than `http`, an empty host, and anything carrying a path.
    pub fn parse(field: &str, raw: &str) -> Result<Self, ConfigError> {
        let invalid = |expected| ConfigError::Invalid {
            field: field.to_owned(),
            value: raw.to_owned(),
            expected,
        };

        let rest = raw
            .strip_prefix("http://")
            .ok_or_else(|| invalid("an http:// origin (https is not supported)"))?;
        let authority = rest.trim_end_matches('/');
        if authority.is_empty() || authority.contains('/') {
            return Err(invalid("an origin with no path"));
        }
        // Round-trip through http's own parser so a malformed authority is caught here rather
        // than on the first request.
        let uri = format!("http://{authority}/")
            .parse::<http::Uri>()
            .map_err(|_| invalid("a parseable origin"))?;
        if uri.host().is_none_or(str::is_empty) {
            return Err(invalid("an origin with a host"));
        }

        Ok(Self {
            authority: authority.to_owned(),
        })
    }

    /// The `host:port` authority, for the connection and the `Host` header.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Build an absolute URI for `path_and_query` against this origin.
    ///
    /// # Errors
    ///
    /// Fails when the caller-supplied path cannot form a URI.
    pub fn uri(&self, path_and_query: &str) -> Result<http::Uri, http::uri::InvalidUri> {
        format!("http://{}{path_and_query}", self.authority).parse()
    }
}

/// The rule that decides a request already carries its own credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passthrough {
    /// Request header inspected.
    pub header: HeaderName,
    /// Substring whose presence means "this caller brought its own".
    pub contains: String,
}

/// How the minted credential is read out of the acquisition response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Take {
    /// The first `name=value` pair, attributes dropped. The `Set-Cookie` case.
    CookiePair,
    /// The header value verbatim.
    Whole,
    /// Everything after the given prefix.
    After(String),
}

impl Take {
    /// Parse the `credential.extract.take` value.
    ///
    /// # Errors
    ///
    /// Rejects anything other than `cookie-pair`, `whole`, or `after:<prefix>`.
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw {
            "cookie-pair" => Ok(Self::CookiePair),
            "whole" => Ok(Self::Whole),
            other => other
                .strip_prefix("after:")
                .map(|p| Self::After(p.to_owned()))
                .ok_or(ConfigError::Invalid {
                    field: "credential.extract.take".to_owned(),
                    value: raw.to_owned(),
                    expected: "one of cookie-pair, whole, after:<prefix>",
                }),
        }
    }

    /// Apply the rule to a response header value.
    ///
    /// Returns `None` when the rule finds nothing, which the caller treats as a failed
    /// acquisition rather than as an empty credential.
    pub fn apply<'a>(&self, value: &'a str) -> Option<&'a str> {
        let taken = match self {
            // `sid=abc; Path=/; HttpOnly` -> `sid=abc`
            Self::CookiePair => value.split(';').next().unwrap_or(value).trim(),
            Self::Whole => value.trim(),
            Self::After(prefix) => value
                .split_once(prefix.as_str())
                .map(|(_, tail)| tail)?
                .trim(),
        };
        (!taken.is_empty()).then_some(taken)
    }
}

/// The single request/response exchange that mints a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acquisition {
    /// Origin the exchange is sent to.
    pub origin: Origin,
    /// Method of the acquisition request.
    pub method: Method,
    /// Path (and query) of the acquisition request.
    pub path: String,
    /// Headers, with `${ENV}` already substituted.
    pub headers: Vec<(HeaderName, String)>,
    /// Body, with `${ENV}` already substituted.
    pub body: String,
    /// Response statuses that count as a successful acquisition.
    pub accept_status: Vec<StatusCode>,
    /// Response header the credential is read from.
    pub from_header: HeaderName,
    /// How to read it.
    pub take: Take,
}

/// Whether the credential replaces or joins whatever the caller sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectMode {
    /// Add to an existing header value, comma/semicolon-joined as the header requires.
    Append,
    /// Replace the header outright.
    Set,
}

/// How the minted credential rides on forwarded requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inject {
    /// Request header written before forwarding.
    pub header: HeaderName,
    /// Replace or join.
    pub mode: InjectMode,
}

/// When the upstream is telling us the held credential is stale.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Renew {
    /// Statuses that mean "stale". Empty disables renewal entirely.
    pub on_status: Vec<StatusCode>,
    /// Replays permitted per request after a renewal.
    pub max_replays: u32,
}

impl Renew {
    /// Whether this status means the held credential should be discarded and re-acquired.
    pub fn triggers(&self, status: StatusCode) -> bool {
        self.on_status.contains(&status)
    }
}

/// The whole validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Address the proxy binds.
    pub listen: SocketAddr,
    /// Origin every non-acquisition request is forwarded to.
    pub upstream: Origin,
    /// The "caller brought its own" rule.
    pub passthrough: Passthrough,
    /// The exchange that mints a credential.
    pub credential: Acquisition,
    /// How the credential is attached.
    pub inject: Inject,
    /// Reactive renewal.
    pub renew: Renew,
}

/// Parse a header name, naming the field in the error.
///
/// # Errors
///
/// Rejects anything that is not a valid HTTP field name.
pub fn header_name(field: &str, raw: &str) -> Result<HeaderName, ConfigError> {
    raw.parse().map_err(|_| ConfigError::Invalid {
        field: field.to_owned(),
        value: raw.to_owned(),
        expected: "a valid HTTP header name",
    })
}

/// Parse a status code, naming the field in the error.
///
/// # Errors
///
/// Rejects anything the HTTP spec's status range excludes.
pub fn status_code(field: &str, raw: u16) -> Result<StatusCode, ConfigError> {
    StatusCode::from_u16(raw).map_err(|_| ConfigError::Invalid {
        field: field.to_owned(),
        value: raw.to_string(),
        expected: "a status code between 100 and 599",
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn substitution_fills_every_reference() {
        let lookup = env(&[("CRED_USER", "svc"), ("CRED_SECRET", "hunter2")]);
        assert_eq!(
            substitute("email=${CRED_USER}&password=${CRED_SECRET}", &lookup).unwrap(),
            "email=svc&password=hunter2"
        );
    }

    #[test]
    fn an_unset_reference_is_an_error_not_an_empty_string() {
        let lookup = env(&[]);
        assert_eq!(
            substitute("password=${CRED_SECRET}", &lookup),
            Err(ConfigError::UnsetEnv("CRED_SECRET".to_owned()))
        );
    }

    #[test]
    fn a_bare_dollar_is_literal() {
        let lookup = env(&[]);
        assert_eq!(substitute("cost is $5", &lookup).unwrap(), "cost is $5");
    }

    #[test]
    fn an_unclosed_reference_is_malformed() {
        let lookup = env(&[("A", "1")]);
        assert!(matches!(
            substitute("x=${A", &lookup),
            Err(ConfigError::MalformedReference(_))
        ));
        assert!(matches!(
            substitute("x=${}", &lookup),
            Err(ConfigError::MalformedReference(_))
        ));
    }

    #[test]
    fn substitution_leaves_text_with_no_reference_untouched() {
        assert_eq!(substitute("plain", &env(&[])).unwrap(), "plain");
        assert_eq!(substitute("", &env(&[])).unwrap(), "");
    }

    #[test]
    fn origins_accept_http_and_reject_everything_else() {
        assert_eq!(
            Origin::parse("upstream", "http://app:3000")
                .unwrap()
                .authority(),
            "app:3000"
        );
        assert_eq!(
            Origin::parse("upstream", "http://app").unwrap().authority(),
            "app"
        );
        // A trailing slash is tolerated; a path is not.
        assert_eq!(
            Origin::parse("upstream", "http://app:3000/")
                .unwrap()
                .authority(),
            "app:3000"
        );
        for bad in [
            "https://app:3000",
            "app:3000",
            "http://",
            "http://app/login",
            "",
        ] {
            assert!(
                Origin::parse("upstream", bad).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn an_origin_builds_absolute_uris() {
        let origin = Origin::parse("upstream", "http://app:3000").unwrap();
        assert_eq!(
            origin.uri("/a/b?c=d").unwrap().to_string(),
            "http://app:3000/a/b?c=d"
        );
    }

    #[test]
    fn extraction_rules_do_what_they_say() {
        let cookie = Take::parse("cookie-pair").unwrap();
        assert_eq!(
            cookie.apply("sid=abc123; Path=/; HttpOnly; SameSite=Lax"),
            Some("sid=abc123")
        );
        assert_eq!(cookie.apply("sid=abc123"), Some("sid=abc123"));

        let whole = Take::parse("whole").unwrap();
        assert_eq!(whole.apply("  Bearer xyz  "), Some("Bearer xyz"));

        let after = Take::parse("after:Bearer ").unwrap();
        assert_eq!(after.apply("Bearer xyz"), Some("xyz"));
        assert_eq!(after.apply("Basic xyz"), None, "prefix absent");
    }

    #[test]
    fn an_extraction_that_finds_nothing_is_none_not_an_empty_credential() {
        assert_eq!(Take::CookiePair.apply(""), None);
        assert_eq!(Take::CookiePair.apply("   ; Path=/"), None);
        assert_eq!(Take::Whole.apply("   "), None);
        assert_eq!(Take::After("x=".to_owned()).apply("x="), None);
    }

    #[test]
    fn unknown_extraction_rules_are_refused() {
        assert!(Take::parse("regex:.*").is_err());
        assert!(Take::parse("").is_err());
    }

    #[test]
    fn renewal_is_disabled_by_an_empty_status_list() {
        let never = Renew::default();
        assert!(!never.triggers(StatusCode::UNAUTHORIZED));

        let on_401 = Renew {
            on_status: vec![StatusCode::UNAUTHORIZED],
            max_replays: 1,
        };
        assert!(on_401.triggers(StatusCode::UNAUTHORIZED));
        assert!(!on_401.triggers(StatusCode::FORBIDDEN));
    }
}
