//! Who a caller is, once something has proved it.
//!
//! Four things can prove an identity to this gate — a host session cookie, a bearer token this
//! cluster's issuer minted, a workspace's service-account token, and the client address of a pod
//! — and RFC 0009 is emphatic that all four are *identities, not exemptions*: each one produces a
//! caller who is then authorised by the same owner check, the same delegation and the same path
//! rules. [`Credential`] is that shape, and it is what keeps the difference between "how you
//! proved it" and "what it gets you" from collapsing into a special case.

use std::collections::BTreeSet;
use std::fmt;

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Wrap a name read from a claim, an annotation or a Kubernetes object.
            pub fn new(raw: impl Into<String>) -> Self {
                Self(raw.into())
            }

            /// The name as written.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name_type! {
    /// A username, as the identity provider's `claims.username` spells it — which RFC 0009
    /// requires to be the same string Che wrote in the namespace annotation. The startup check
    /// that verifies this is what turns a claim-mapping mistake into a refused start instead of
    /// a cluster where nobody is the owner of their own endpoint.
    Username
}
name_type! {
    /// A group name from the identity provider's groups claim.
    GroupName
}
name_type! {
    /// A team name, chassis-level (RFC 0002). Never written by a developer, and derived here
    /// rather than claimed: a team's members are the owners of its namespaces.
    TeamName
}
name_type! {
    /// A Kubernetes namespace name.
    NamespaceName
}
name_type! {
    /// The identity provider's session id (`sid`), the handle back-channel logout revokes a
    /// session by.
    SessionId
}

/// What a session or a verified token said about the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// The caller.
    pub username: Username,
    /// The groups that were sealed into the session — *some* of the caller's groups, not all of
    /// them, per RFC 0009's *Group claims*: only those an endpoint somewhere names.
    pub groups: BTreeSet<GroupName>,
    /// The caller's team, derived from the namespaces they own rather than read from a claim.
    /// `None` for somebody who owns no namespace — "a person who has never opened a workspace is
    /// not a colleague the cluster knows about".
    pub team: Option<TeamName>,
    /// The identity provider's session id, when it issued one. `None` for a bearer token, which
    /// is revoked by expiry rather than by logout.
    pub session: Option<SessionId>,
}

impl Claims {
    /// A caller with no groups and no team — the shape most tests want.
    pub fn user(username: &str) -> Self {
        Self {
            username: Username::new(username),
            groups: BTreeSet::new(),
            team: None,
            session: None,
        }
    }

    /// The same, in a team.
    pub fn in_team(username: &str, team: &str) -> Self {
        Self {
            team: Some(TeamName::new(team)),
            ..Self::user(username)
        }
    }

    /// The same, in some groups.
    pub fn with_groups<'a>(mut self, groups: impl IntoIterator<Item = &'a str>) -> Self {
        self.groups = groups.into_iter().map(GroupName::new).collect();
        self
    }
}

/// A caller, once proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointIdentity {
    /// A person: a browser session, or a bearer token this issuer minted.
    User(Claims),
    /// A workspace: a pod of this namespace, or that workspace's service-account token. Whoever
    /// runs code in alice's workspace pod *is* alice, so this resolves to the namespace's owner
    /// and to nothing wider — see RFC 0009's *Calling your own endpoint from your own workspace*.
    Workspace(NamespaceName),
}

/// What the request presented, after the ports have had their say — the input `decide()` reads
/// instead of reading headers.
///
/// The order these are resolved in is the flowchart's, and it is deliberate: an explicit
/// credential beats an implicit one, so a developer testing what a colleague will see can do it
/// from their own workspace terminal by presenting that colleague's session, and gets the answer
/// the colleague would get.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// Nothing usable was presented.
    None,
    /// A valid host session cookie for this host.
    Session(Claims),
    /// A bearer token this cluster's issuer minted, verified against its keys.
    Bearer(Claims),
    /// An `Authorization` header carrying something this cluster did not mint. Not an identity —
    /// the only thing it can reach is a path rule that opted into `bearer: Passthrough`.
    ForeignBearer,
    /// A Kubernetes service-account token, resolved to the namespace it belongs to.
    ServiceAccount(NamespaceName),
    /// No credential, but the client address is a pod of this namespace.
    PodOrigin(NamespaceName),
    /// A session cookie that opened, for a session the identity provider has since ended.
    /// Distinct from [`Credential::None`] so that the log line and the metric can say `revoked`
    /// rather than `no_identity` — the difference between "sign in" and "you were signed out",
    /// and the one a developer will otherwise report as a bug.
    RevokedSession,
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
    fn claims_helpers_build_what_the_tables_need() {
        let claims = Claims::in_team("alice", "team-1").with_groups(["payments"]);
        assert_eq!(claims.username, Username::new("alice"));
        assert_eq!(claims.team, Some(TeamName::new("team-1")));
        assert!(claims.groups.contains(&GroupName::new("payments")));
        assert_eq!(claims.session, None);
    }

    #[test]
    fn a_name_renders_as_itself() {
        assert_eq!(Username::new("alice").to_string(), "alice");
        assert_eq!(NamespaceName::new("user-alice").as_str(), "user-alice");
    }
}
