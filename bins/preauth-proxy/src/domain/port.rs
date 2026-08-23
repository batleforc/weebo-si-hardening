//! The traits the domain owns and the outside implements.
//!
//! Named for what the application needs, not for what happens to implement them today. Both
//! fakes are far smaller than the real adapters, which is the honesty test
//! [`hexagonal.md`](../../../../docs/architecture/hexagonal.md) applies before a port earns its
//! place.

use std::fmt;
use std::future::Future;

use bytes::Bytes;

/// An opaque credential: whatever the acquisition exchange extracted.
///
/// Deliberately not `Display` and not `Debug`-transparent — it is the one secret this process
/// mints, and the type is what stops it reaching a log line by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
    /// Wrap an extracted value.
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The bytes to write into the injection header.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The length, which is the only thing about a credential that may be logged.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential({} bytes)", self.0.len())
    }
}

/// Why an acquisition failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireError {
    /// The origin could not be reached, or the exchange did not complete.
    Unreachable(String),
    /// The origin answered with a status outside `accept_status`.
    Rejected(u16),
    /// The response did not carry the extraction header.
    NoHeader(String),
    /// The extraction rule found nothing in the header it was pointed at.
    NothingExtracted(String),
}

impl fmt::Display for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(why) => write!(f, "origin unreachable: {why}"),
            Self::Rejected(status) => write!(f, "origin returned {status}"),
            Self::NoHeader(name) => write!(f, "response carried no {name} header"),
            Self::NothingExtracted(name) => {
                write!(f, "the extraction rule found nothing in {name}")
            }
        }
    }
}

impl std::error::Error for AcquireError {}

/// Obtain a credential.
///
/// The real adapter performs the configured HTTP exchange and runs the extraction rules; the fake
/// returns a fixed value, or a queued sequence to exercise renewal.
pub trait CredentialSource {
    /// Run the acquisition exchange once.
    fn acquire(&self) -> impl Future<Output = Result<Credential, AcquireError>> + Send;
}

/// Why a forward failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayError(pub String);

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GatewayError {}

/// Forward a request and return its response.
///
/// The request body is [`Bytes`] rather than a stream: a request may have to be **replayed** after
/// a renewal, and a stream cannot be replayed. Response bodies stay opaque ([`Upstream::Body`])
/// precisely so the adapter can stream them without the domain ever holding one whole.
pub trait Upstream {
    /// The response body, opaque here and streamed by the adapter.
    type Body;

    /// Send one request upstream.
    fn forward(
        &self,
        request: http::Request<Bytes>,
    ) -> impl Future<Output = Result<http::Response<Self::Body>, GatewayError>> + Send;
}
