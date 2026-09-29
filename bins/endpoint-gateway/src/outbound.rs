//! The one HTTP client every outbound HTTPS call uses: issuer discovery, JWKS, the token and
//! introspection endpoints, and the self-origin probe.
//!
//! One client rather than a `reqwest::Client::new()` per call site, because trust is a property
//! of the process, not of the call: an identity provider behind a private CA — most corporate
//! ones, and every test rig — has to be reachable from discovery through to revalidation, and a
//! site that kept building its own client would be the one that fails an hour after startup,
//! at the first token refresh.
//!
//! `extra_ca_file` **adds** roots; it never replaces the built-in Mozilla set. Replacing would
//! let one misconfigured bundle turn every public issuer into an untrusted one, which is the kind
//! of failure that looks like an outage of the identity provider rather than a line of config.

use std::sync::OnceLock;

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Build the process-wide client, trusting `extra_ca_file` on top of the built-in roots.
///
/// Called once at startup, before anything talks to the issuer. An unreadable file or a bundle
/// with no certificate in it is a refusal to start: a gateway that silently fell back to the
/// built-in roots would fail every sign-in while reporting itself healthy.
pub fn init(extra_ca_file: &str) -> Result<(), String> {
    let client = build(extra_ca_file)?;
    // A second `init` keeps the first client: the configuration is read once per process.
    let _ = CLIENT.set(client);
    Ok(())
}

/// The process-wide client, or a default one where [`init`] never ran — which is every unit
/// test, and nothing else.
pub fn client() -> reqwest::Client {
    CLIENT.get().cloned().unwrap_or_default()
}

fn build(extra_ca_file: &str) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();
    if !extra_ca_file.is_empty() {
        let pem = std::fs::read(extra_ca_file)
            .map_err(|err| format!("extra_ca_file {extra_ca_file}: {err}"))?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|err| format!("extra_ca_file {extra_ca_file}: {err}"))?;
        if certificates.is_empty() {
            return Err(format!(
                "extra_ca_file {extra_ca_file} holds no PEM certificate"
            ));
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder
        .build()
        .map_err(|err| format!("building the outbound HTTP client: {err}"))
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
    fn no_extra_bundle_builds_the_default_client() {
        assert!(build("").is_ok());
    }

    #[test]
    fn a_missing_bundle_is_a_refusal_to_start() {
        let err = build("/nonexistent/ca.crt").unwrap_err();
        assert!(err.contains("/nonexistent/ca.crt"), "{err}");
    }

    #[test]
    fn a_bundle_with_no_certificate_is_a_refusal_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.crt");
        std::fs::write(&path, "not a certificate\n").unwrap();
        let err = build(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("no PEM certificate"), "{err}");
    }

    #[test]
    fn a_real_bundle_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.crt");
        std::fs::write(&path, include_str!("fixtures/test-ca.crt")).unwrap();
        assert!(build(path.to_str().unwrap()).is_ok());
    }
}
