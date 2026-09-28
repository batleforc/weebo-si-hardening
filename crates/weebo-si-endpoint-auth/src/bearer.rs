//! Which tokens are ours — RFC 0009's *Which tokens are ours, and what the IDE actually has*.
//!
//! `verify_own_issuer: true` is not a specification. On a realm with more than one client it
//! means *every token that realm has ever minted, for any client*: a workspace application that
//! registered its own OIDC client could turn anyone who signs in to it into a caller at every
//! endpoint in the cluster. That is not a bypass of the authorisation half — the verdict is still
//! that user's — it is a confused deputy, which is the failure mode audience restriction exists to
//! prevent.
//!
//! So "minted by our issuer" is written out here as five checks, and a token is an identity only
//! if it passes all of them. The module is deliberately in the *domain*: it does no cryptography,
//! reaches no network and reads no clock, so the whole table can be exercised without an identity
//! provider — and the signature check that feeds it stays in the adapter, where a JWKS cache and
//! an introspection endpoint are two different answers to the same question.
//!
//! The one check that is *not* here is the signature. An adapter proves a token is authentic and
//! then hands what it read to [`BearerRules::check`]; what makes a token *ours* is everything
//! after that.

use std::collections::BTreeSet;
use std::fmt;

use crate::identity::SessionId;
use crate::port::RevocationStore;
use crate::time::Timestamp;

/// What shape of credential the `Authorization` header turned out to hold — the `shape` label of
/// `weebo_si_endpoint_auth_bearer_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenShape {
    /// A JWT, verified against the issuer's published keys.
    Jwt,
    /// An opaque string, resolved by asking the issuer (RFC 7662). Every Che on OpenShift.
    Opaque,
    /// A Kubernetes service-account token, resolved by a `TokenReview`.
    ServiceAccount,
}

impl TokenShape {
    /// The metric label. A `&'static str` from a closed enum, never a formatted value.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::Opaque => "opaque",
            Self::ServiceAccount => "service_account",
        }
    }
}

/// What the checks concluded — the `result` label of `weebo_si_endpoint_auth_bearer_total`, and
/// the line `--explain-token` prints.
///
/// **The decision's own `reason` enum does not grow for any of this.** A refused bearer is
/// `no_identity`, as it was: every one of these is a deny, they are already indistinguishable to
/// the caller, and the detail an admin wants is "which check, how often" rather than a wider
/// verdict vocabulary. The precedent cuts the other way from `preflight`, which *did* join the
/// enum — there an allow was becoming indistinguishable from another allow in the one metric an
/// admin uses to find unauthenticated traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerResult {
    /// An identity: the token named an audience in `bearer.audiences`.
    Accepted,
    /// An identity, reached through the compatibility mode: no audience we know, but the party
    /// that asked for the token is in `bearer.authorized_parties`.
    ///
    /// Its own label rather than a second `accepted`, because the whole point of the mode is that
    /// an admin can see how much of their traffic depends on it — "we meant to add the mapper
    /// next sprint" is how a compatibility mode becomes the configuration.
    AcceptedAuthorizedParty,
    /// Our issuer, somebody else's audience.
    WrongAudience,
    /// An ID token. A statement to a client about a login, and the one an SPA holds in JS.
    IdToken,
    /// Past its `exp`, or before its `nbf`.
    Expired,
    /// Minted from a session the identity provider has since ended.
    Revoked,
    /// Introspection answered `active: false`.
    Inactive,
    /// Well-formed and unverifiable: no key, no signature, or nothing to ask.
    Unverifiable,
    /// Somebody else's issuer. Not ours to refuse — `profile.bearer` decides what happens to it.
    Foreign,
}

impl BearerResult {
    /// The metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AcceptedAuthorizedParty => "accepted_authorized_party",
            Self::WrongAudience => "wrong_audience",
            Self::IdToken => "id_token",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Inactive => "inactive",
            Self::Unverifiable => "unverifiable",
            Self::Foreign => "foreign",
        }
    }

    /// Whether this token is an identity here.
    pub const fn is_identity(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedAuthorizedParty)
    }

    /// One sentence a developer can act on, for the `401` body and for `--explain-token`.
    ///
    /// The failure this removes is a developer reading their own `fetch` wrapper for an afternoon
    /// because a gate nobody told them about answered `401` to a token that looked, from where
    /// they were standing, entirely valid.
    pub const fn advice(self) -> &'static str {
        match self {
            Self::Accepted | Self::AcceptedAuthorizedParty => "accepted",
            Self::WrongAudience => {
                "the token names no audience this gateway accepts: add an audience mapper to the \
                 client that minted it, or list that client in bearer.authorized_parties"
            }
            Self::IdToken => {
                "that is the ID token, not the access token — present the access token from the \
                 same exchange"
            }
            Self::Expired => {
                "the token is outside its own validity window; fetch one per use rather than one \
                 per run — a realm access token is short, five minutes by default"
            }
            Self::Revoked => {
                "the session this token was minted from has been signed out; sign in again and \
                 fetch a new one"
            }
            Self::Inactive => "the issuer says this token is not active",
            Self::Unverifiable => {
                "nothing here can verify this token: no published key matches it, and \
                 introspection is off"
            }
            Self::Foreign => {
                "another issuer minted this token; only a rule with `bearer: Passthrough` reaches \
                 the application with it"
            }
        }
    }
}

impl fmt::Display for BearerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What a verifier read off a token, before anything has been decided about it.
///
/// One shape for both verifiers: a JWT's claims and an RFC 7662 introspection response carry the
/// same five facts under the same names, so the checks below are written once rather than twice
/// with a chance to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedToken {
    /// `iss`.
    pub issuer: Option<String>,
    /// `aud`, as a set — a token may name several.
    pub audiences: BTreeSet<String>,
    /// `azp`, or introspection's `client_id`: the party that asked for the token.
    pub authorized_party: Option<String>,
    /// `typ`, where the issuer writes one. Keycloak writes `ID` and `Bearer`.
    pub token_type: Option<String>,
    /// Whether `at_hash` is present.
    pub at_hash: bool,
    /// Whether `nonce` is present.
    pub nonce: bool,
    /// `exp`.
    pub expires_at: Option<Timestamp>,
    /// `nbf`.
    pub not_before: Option<Timestamp>,
    /// `sid`, the handle back-channel logout revokes a session by.
    pub session: Option<SessionId>,
    /// Whether the issuer considers this token live. Always true for a signature-verified JWT,
    /// which carries the assertion itself; introspection's `active` otherwise.
    pub active: bool,
}

impl PresentedToken {
    /// A token an adapter has proved authentic — a verified signature, or an introspection answer
    /// of `active: true`.
    ///
    /// Everything else is absent until a builder adds it, so a claim this gateway never read
    /// cannot be one it silently treated as satisfied.
    pub fn proved(issuer: impl Into<String>) -> Self {
        Self {
            issuer: Some(issuer.into()),
            audiences: BTreeSet::new(),
            authorized_party: None,
            token_type: None,
            at_hash: false,
            nonce: false,
            expires_at: None,
            not_before: None,
            session: None,
            active: true,
        }
    }

    /// An introspection answer of `active: false`. Nothing else is known about it, and nothing
    /// else needs to be.
    pub fn inactive() -> Self {
        Self {
            active: false,
            ..Self::proved(String::new())
        }
    }

    /// With these audiences.
    pub fn for_audiences<'a>(mut self, audiences: impl IntoIterator<Item = &'a str>) -> Self {
        self.audiences = audiences.into_iter().map(str::to_owned).collect();
        self
    }

    /// Asked for by this party (`azp`, or introspection's `client_id`).
    pub fn asked_for_by(mut self, party: &str) -> Self {
        self.authorized_party = Some(party.to_owned());
        self
    }

    /// Labelled `typ` by the issuer.
    pub fn typed(mut self, token_type: &str) -> Self {
        self.token_type = Some(token_type.to_owned());
        self
    }

    /// Carrying an `at_hash` — the structural mark of an ID token.
    pub fn with_at_hash(mut self) -> Self {
        self.at_hash = true;
        self
    }

    /// Carrying a `nonce`.
    pub fn with_nonce(mut self) -> Self {
        self.nonce = true;
        self
    }

    /// Valid until.
    pub fn expiring_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Not valid before.
    pub fn not_before(mut self, not_before: Timestamp) -> Self {
        self.not_before = Some(not_before);
        self
    }

    /// Minted from this session.
    pub fn in_session(mut self, session: &str) -> Self {
        self.session = Some(SessionId::new(session));
        self
    }

    /// Whether this is an ID token, tested structurally rather than by vendor.
    ///
    /// An ID token's audience *is* the client id, so under `authorized_parties` it would sail
    /// through the audience check — which would mean handing a cluster credential to every
    /// browser-side thing that has ever seen one, the population OIDC is explicit about not
    /// treating as a resource-server credential.
    pub fn is_id_token(&self) -> bool {
        // `at_hash` binds an ID token to an access token. An access token has nothing to bind,
        // and no issuer has a reason to put one there — so this is the discriminator that holds
        // in every direction, and it is checked first.
        if self.at_hash {
            return true;
        }
        // The issuer's own label, where it writes one (Keycloak's `ID` against `Bearer`).
        // Checked, never depended on: the specification does not require it, and a refusal that
        // *rested* on it would reopen the hole silently for an issuer that omits it.
        if self
            .token_type
            .as_deref()
            .is_some_and(|typ| typ.eq_ignore_ascii_case("id"))
        {
            return true;
        }
        // `nonce` is the third signal and the one to be careful with: it belongs to the ID token,
        // and some Keycloak versions have put it in the *access* token as well. RFC 0009 has it
        // refuse only alongside one of the other two — both of which have already answered — so
        // today it is corroboration rather than a discriminator, and which way it should count is
        // a line in the ground-truth spike rather than a guess made here.
        false
    }
}

/// Why a set of bearer rules could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesError {
    /// `verify_own_issuer` is on and neither list names anything.
    ///
    /// A refusal to start rather than a warning, and for the same reason a suffix this gateway
    /// cannot govern is: a gateway that accepts every token in the realm while looking healthy is
    /// worse than one that will not come up.
    NoAudience,
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAudience => f.write_str(
                "bearer.verify_own_issuer is on with no bearer.audiences and no \
                 bearer.authorized_parties, which would accept every token this realm has ever \
                 minted, for every client — add an audience mapper for this gateway to the realm \
                 client and name it in bearer.audiences",
            ),
        }
    }
}

/// What makes a token ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerRules {
    issuer: String,
    audiences: BTreeSet<String>,
    authorized_parties: BTreeSet<String>,
}

impl BearerRules {
    /// Build the rules, or refuse.
    pub fn new<A, P>(
        issuer: impl Into<String>,
        audiences: A,
        parties: P,
    ) -> Result<Self, RulesError>
    where
        A: IntoIterator,
        A::Item: Into<String>,
        P: IntoIterator,
        P::Item: Into<String>,
    {
        let rules = Self {
            issuer: issuer.into(),
            audiences: audiences.into_iter().map(Into::into).collect(),
            authorized_parties: parties.into_iter().map(Into::into).collect(),
        };
        if rules.audiences.is_empty() && rules.authorized_parties.is_empty() {
            return Err(RulesError::NoAudience);
        }
        Ok(rules)
    }

    /// The issuer these rules are for.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The audiences that make a token ours.
    pub fn audiences(&self) -> impl Iterator<Item = &str> {
        self.audiences.iter().map(String::as_str)
    }

    /// The parties accepted in place of an audience — empty on a correctly configured realm.
    pub fn authorized_parties(&self) -> impl Iterator<Item = &str> {
        self.authorized_parties.iter().map(String::as_str)
    }

    /// Whether the compatibility mode is on at all: what raises the startup `WARN`, the
    /// `Degraded` condition and the metric label.
    pub fn in_compatibility_mode(&self) -> bool {
        !self.authorized_parties.is_empty()
    }

    /// The five checks, in the order whose refusal a caller can act on soonest.
    ///
    /// The ordering differs from RFC 0009's table in one place, deliberately: the ID-token
    /// refusal runs *before* the audience check, because "you sent the wrong one of your two" is a
    /// five-second fix and `wrong_audience` for the same token is an afternoon of guessing. The
    /// set of tokens each order accepts is identical.
    pub fn check(
        &self,
        token: &PresentedToken,
        now: Timestamp,
        revocations: &dyn RevocationStore,
    ) -> BearerResult {
        if !token.active {
            return BearerResult::Inactive;
        }
        if token.issuer.as_deref() != Some(self.issuer.as_str()) {
            return BearerResult::Foreign;
        }
        if token.is_id_token() {
            return BearerResult::IdToken;
        }
        let accepted = if token
            .audiences
            .iter()
            .any(|audience| self.audiences.contains(audience))
        {
            BearerResult::Accepted
        } else if token
            .authorized_party
            .as_deref()
            .is_some_and(|party| self.authorized_parties.contains(party))
        {
            BearerResult::AcceptedAuthorizedParty
        } else {
            return BearerResult::WrongAudience;
        };
        // A bearer lives by its own clock and this gate extends nobody's. An absent `exp` is not
        // a token that never expires: it is one this gateway cannot bound, which is the same
        // answer.
        match token.expires_at {
            Some(exp) if !now.is_at_or_after(exp) => {}
            _ => return BearerResult::Expired,
        }
        if token.not_before.is_some_and(|nbf| !now.is_at_or_after(nbf)) {
            return BearerResult::Expired;
        }
        // The revocation set is already in memory for the cookie, and a token a developer fetches
        // is minted from exactly the session a back-channel logout ends — so checking it here
        // closes the gap *Revocation* owed this feature, at the cost of one set lookup.
        if let Some(session) = token.session.as_ref()
            && revocations.is_revoked(session)
        {
            return BearerResult::Revoked;
        }
        accepted
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
    use crate::testing::FakeRevocations;

    const ISSUER: &str = "https://sso.weebo.si/realms/weebo";
    const NOW: Timestamp = Timestamp::from_secs(1_000);

    fn rules() -> BearerRules {
        BearerRules::new(ISSUER, ["endpoint-gateway"], Vec::<String>::new()).unwrap()
    }

    fn ours() -> PresentedToken {
        PresentedToken::proved(ISSUER)
            .for_audiences(["endpoint-gateway"])
            .expiring_at(Timestamp::from_secs(2_000))
    }

    /// One row per check, which is the whole point of writing this in the domain: the table runs
    /// with no identity provider, no keys and no network.
    #[test]
    fn one_row_per_check() {
        let revocations = FakeRevocations::revoked(["ended"]);
        let rules = rules();
        let cases: &[(&str, PresentedToken, BearerResult)] = &[
            (
                "our issuer, our audience, live",
                ours(),
                BearerResult::Accepted,
            ),
            (
                "another issuer entirely",
                PresentedToken::proved("https://sso.example.test/realms/other")
                    .for_audiences(["endpoint-gateway"])
                    .expiring_at(Timestamp::from_secs(2_000)),
                BearerResult::Foreign,
            ),
            (
                "our realm, minted for another client",
                ours().for_audiences(["account"]).asked_for_by("che-client"),
                BearerResult::WrongAudience,
            ),
            (
                "an ID token, by at_hash",
                ours().with_at_hash(),
                BearerResult::IdToken,
            ),
            (
                "an ID token, by the issuer's own label",
                ours().typed("ID"),
                BearerResult::IdToken,
            ),
            (
                "past its exp",
                ours().expiring_at(Timestamp::from_secs(999)),
                BearerResult::Expired,
            ),
            (
                "before its nbf",
                ours().not_before(Timestamp::from_secs(1_001)),
                BearerResult::Expired,
            ),
            (
                "no exp at all — unbounded is not the same as valid",
                PresentedToken::proved(ISSUER).for_audiences(["endpoint-gateway"]),
                BearerResult::Expired,
            ),
            (
                "minted from a session that has since been signed out",
                ours().in_session("ended"),
                BearerResult::Revoked,
            ),
            (
                "minted from a session that is still open",
                ours().in_session("open"),
                BearerResult::Accepted,
            ),
            (
                "introspection said it is not active",
                PresentedToken::inactive(),
                BearerResult::Inactive,
            ),
        ];
        for (why, token, expected) in cases {
            assert_eq!(rules.check(token, NOW, &revocations), *expected, "{why}");
        }
    }

    /// The row this whole section exists for. A realm issues tokens to more than one party, and a
    /// user who signs in to any of them hands that party a credential — which, without this
    /// check, would open every endpoint in the cluster as them.
    #[test]
    fn a_token_minted_for_another_client_of_the_same_realm_is_not_an_identity() {
        let revocations = FakeRevocations::default();
        let theirs = ours()
            .for_audiences(["their-app"])
            .asked_for_by("their-app");
        assert_eq!(
            rules().check(&theirs, NOW, &revocations),
            BearerResult::WrongAudience
        );
        assert!(!BearerResult::WrongAudience.is_identity());
    }

    #[test]
    fn the_compatibility_mode_accepts_on_azp_and_says_so_in_its_own_label() {
        let revocations = FakeRevocations::default();
        let rules = BearerRules::new(ISSUER, Vec::<String>::new(), ["che-client"]).unwrap();
        let theirs = ours().for_audiences(["account"]).asked_for_by("che-client");
        let result = rules.check(&theirs, NOW, &revocations);
        assert_eq!(result, BearerResult::AcceptedAuthorizedParty);
        assert!(result.is_identity());
        // Distinguishable from an ordinary accept in the one metric an admin would alert on.
        assert_ne!(result.label(), BearerResult::Accepted.label());
        assert!(rules.in_compatibility_mode());
        // And a party nobody listed is still refused.
        let other = ours().for_audiences(["account"]).asked_for_by("their-app");
        assert_eq!(
            rules.check(&other, NOW, &revocations),
            BearerResult::WrongAudience
        );
    }

    /// The reason the compatibility mode needs the structural refusal: an ID token's audience
    /// *is* the client id, so `authorized_parties` alone would hand a cluster credential to
    /// everything browser-side that has ever seen one.
    #[test]
    fn an_id_token_is_refused_even_where_its_party_is_listed() {
        let revocations = FakeRevocations::default();
        let rules = BearerRules::new(ISSUER, Vec::<String>::new(), ["che-client"]).unwrap();
        let id_token = ours()
            .for_audiences(["che-client"])
            .asked_for_by("che-client")
            .with_at_hash();
        assert_eq!(
            rules.check(&id_token, NOW, &revocations),
            BearerResult::IdToken
        );
    }

    /// `nonce` alone does not refuse: some Keycloak versions put one in the access token, and a
    /// gate that refused on it would deny every caller on those realms.
    #[test]
    fn a_nonce_on_its_own_is_not_an_id_token() {
        let revocations = FakeRevocations::default();
        assert_eq!(
            rules().check(&ours().with_nonce(), NOW, &revocations),
            BearerResult::Accepted
        );
        assert!(ours().with_nonce().with_at_hash().is_id_token());
    }

    #[test]
    fn no_audience_and_no_party_refuses_to_build_at_all() {
        assert_eq!(
            BearerRules::new(ISSUER, Vec::<String>::new(), Vec::<String>::new()),
            Err(RulesError::NoAudience)
        );
        // And the message names the fix rather than the field.
        assert!(
            RulesError::NoAudience
                .to_string()
                .contains("audience mapper")
        );
    }

    #[test]
    fn every_label_is_a_distinct_closed_value() {
        let all = [
            BearerResult::Accepted,
            BearerResult::AcceptedAuthorizedParty,
            BearerResult::WrongAudience,
            BearerResult::IdToken,
            BearerResult::Expired,
            BearerResult::Revoked,
            BearerResult::Inactive,
            BearerResult::Unverifiable,
            BearerResult::Foreign,
        ];
        let labels: BTreeSet<&str> = all.iter().map(|result| result.label()).collect();
        assert_eq!(labels.len(), all.len());
        for shape in [
            TokenShape::Jwt,
            TokenShape::Opaque,
            TokenShape::ServiceAccount,
        ] {
            assert!(!shape.label().is_empty());
        }
    }
}
