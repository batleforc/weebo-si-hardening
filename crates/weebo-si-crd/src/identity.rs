//! `spec.features.identity` — the switch that lets this operator create objects in other
//! people's systems, and the allow-lists that bound what it may create. See RFC 0011.
//!
//! Every other feature in this repo rewrites or refuses somebody's workload. This one writes an
//! `AuthentikUser` into an identity provider and an `Application` into Argo CD, which is a
//! different kind of blast radius and deserves a different kind of gate. Hence three properties,
//! all deliberate:
//!
//! - It is a feature with a [`FeatureMode`], so it is `Off` unless somebody wrote it down, and
//!   `DryRun` renders everything while writing nothing.
//! - Its allow-lists are **empty by default and empty means none**. A team may name a chart
//!   repository only if an admin listed it; a person may ask for an Authentik group only if an
//!   admin listed it.
//! - A violation refuses the whole object rather than trimming the offending entry. A partially
//!   honoured provisioning request is the failure nobody notices.

use std::collections::BTreeSet;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::argo::{ApplicationTemplateViolation, RenderedApplication};
use crate::feature_mode::FeatureMode;
use crate::team::{TeamName, WeeboSiTeam};
use crate::template::TemplateError;
use crate::user::{Username, WeeboSiUser};

/// Whether one provisioning switch acts.
///
/// Two values, not three: "create it if it is missing, reference it if it is already there" is
/// one behaviour, and splitting it would ask an admin to predict which case they are in. What
/// **is** split is what happens to an object somebody else owns — see
/// [`crate::user::TargetState::Adopted`]: it is referenced, never written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ProvisioningMode {
    /// Nothing is looked for and nothing is created.
    Off,
    /// The object is created when missing, kept in step when this operator owns it, and
    /// referenced when it does not.
    Ensure,
}

/// `spec.features.identity.authentik`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthentikProvisioning {
    /// Authentik group names a team or a person may request. `team-*` matches by prefix. Empty
    /// allows none, which is why a cluster that turns this feature on with no list provisions
    /// users with no group rather than users with every group.
    #[serde(default)]
    pub allowed_group_refs: Vec<String>,
}

/// `spec.features.identity.che`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CheProvisioning {
    /// The one namespace `Application` objects are created in. One namespace is what keeps this
    /// operator's RBAC to one namespace, so it is a cluster-level field and never a team's.
    #[serde(default = "default_application_namespace")]
    pub application_namespace: String,
    /// Argo CD projects a team template may name. Empty allows none.
    #[serde(default)]
    pub allowed_projects: Vec<String>,
    /// Chart or git repositories a team template may name. `https://charts.weebo.io/*` matches by
    /// prefix. Empty allows none.
    #[serde(default)]
    pub allowed_repo_urls: Vec<String>,
}

/// The namespace Argo CD installs itself into by convention, and the only default worth having.
pub const DEFAULT_APPLICATION_NAMESPACE: &str = "argocd";

fn default_application_namespace() -> String {
    DEFAULT_APPLICATION_NAMESPACE.to_owned()
}

impl Default for CheProvisioning {
    fn default() -> Self {
        Self {
            application_namespace: default_application_namespace(),
            allowed_projects: Vec::new(),
            allowed_repo_urls: Vec::new(),
        }
    }
}

/// `spec.features.identity` — provisioning, and its fences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`. `DryRun` plans everything and
    /// writes nothing, which is the same computation with the write withheld.
    pub mode: FeatureMode,
    /// The identity provider half.
    #[serde(default)]
    pub authentik: AuthentikProvisioning,
    /// The workspace half.
    #[serde(default)]
    pub che: CheProvisioning,
}

/// The `AuthentikUser` one person maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthentikUserPlan {
    /// `metadata.name`.
    pub name: String,
    /// `spec.username`.
    pub username: Username,
    /// `spec.name`.
    pub display_name: String,
    /// `spec.email`.
    pub email: String,
    /// `spec.isActive`.
    pub is_active: bool,
    /// `spec.groupRefs`, the team's and the person's merged, deduplicated and sorted.
    pub group_refs: Vec<String>,
}

impl AuthentikUserPlan {
    /// The `spec` of the `authentik.weebo.io/v1alpha1` `AuthentikUser` this renders to.
    ///
    /// JSON rather than the upstream type, for the reason
    /// [`crate::argo::RenderedApplication::spec`] gives: six fields is not a dependency on
    /// another project's whole schema.
    pub fn spec(&self) -> Value {
        let mut spec = serde_json::Map::new();
        spec.insert(
            "username".to_owned(),
            Value::String(self.username.to_string()),
        );
        spec.insert("name".to_owned(), Value::String(self.display_name.clone()));
        spec.insert("email".to_owned(), Value::String(self.email.clone()));
        spec.insert("isActive".to_owned(), Value::Bool(self.is_active));
        spec.insert(
            "groupRefs".to_owned(),
            Value::Array(
                self.group_refs
                    .iter()
                    .map(|group| Value::String(group.clone()))
                    .collect(),
            ),
        );
        Value::Object(spec)
    }
}

/// Everything one person's objects would be, with nothing written yet.
///
/// The pure half of provisioning: the reconcile loop compares this against the cluster, and
/// `DryRun` computes it and stops here.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UserPlan {
    /// The identity provider object, absent when the person did not ask for one.
    pub authentik: Option<AuthentikUserPlan>,
    /// The workspace application, absent when the person did not ask for one.
    pub application: Option<RenderedApplication>,
}

/// One way provisioning refuses to act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityConfigViolation {
    /// Two `WeeboSiUser` objects claim one username.
    DuplicateUsername(Username),
    /// A person names a team no `WeeboSiTeam` declares.
    UnknownTeam {
        /// The person.
        user: Username,
        /// The team they name.
        team: TeamName,
    },
    /// A group is outside `authentik.allowedGroupRefs`.
    GroupRefNotAllowed {
        /// Whoever asked: a team name or a username.
        subject: String,
        /// The group asked for.
        group: String,
    },
    /// An Authentik account was asked for without the email it requires.
    EmailRequired(Username),
    /// A person asked for a workspace and belongs to no team.
    WorkspaceWithoutTeam(Username),
    /// A person asked for a workspace and their team describes none.
    WorkspaceWithoutTemplate {
        /// The person.
        user: Username,
        /// Their team.
        team: TeamName,
    },
    /// A person asked for a workspace their team has switched `Off`. Reported rather than
    /// silently skipped: the two say opposite things and somebody should know which won.
    WorkspaceDisabledByTeam {
        /// The person.
        user: Username,
        /// Their team.
        team: TeamName,
    },
    /// A team's template is malformed on its own terms.
    TemplateInvalid {
        /// The team carrying it.
        team: TeamName,
        /// What is wrong with it.
        violation: ApplicationTemplateViolation,
    },
    /// A team names an Argo CD project outside `che.allowedProjects`.
    ProjectNotAllowed {
        /// The team.
        team: TeamName,
        /// The project it names.
        project: String,
    },
    /// A team names a repository outside `che.allowedRepoUrls`.
    RepoUrlNotAllowed {
        /// The team.
        team: TeamName,
        /// The repository it names.
        repo_url: String,
    },
    /// A template did not render for one person.
    RenderFailed {
        /// The person.
        user: Username,
        /// Why.
        error: TemplateError,
    },
}

impl fmt::Display for IdentityConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateUsername(user) => {
                write!(f, "two WeeboSiUser objects claim username {user}")
            }
            Self::UnknownTeam { user, team } => {
                write!(f, "user {user} names team {team}, which does not exist")
            }
            Self::GroupRefNotAllowed { subject, group } => write!(
                f,
                "{subject} asks for group {group}, which is outside allowedGroupRefs"
            ),
            Self::EmailRequired(user) => {
                write!(f, "user {user} asks for an Authentik account with no email")
            }
            Self::WorkspaceWithoutTeam(user) => {
                write!(f, "user {user} asks for a workspace and has no team")
            }
            Self::WorkspaceWithoutTemplate { user, team } => write!(
                f,
                "user {user} asks for a workspace and team {team} describes none"
            ),
            Self::WorkspaceDisabledByTeam { user, team } => write!(
                f,
                "user {user} asks for a workspace and team {team} has it switched off"
            ),
            Self::TemplateInvalid { team, violation } => {
                write!(f, "team {team}'s workspace template: {violation}")
            }
            Self::ProjectNotAllowed { team, project } => write!(
                f,
                "team {team} names project {project}, which is outside allowedProjects"
            ),
            Self::RepoUrlNotAllowed { team, repo_url } => write!(
                f,
                "team {team} names repository {repo_url}, which is outside allowedRepoUrls"
            ),
            Self::RenderFailed { user, error } => {
                write!(f, "rendering the workspace of user {user}: {error}")
            }
        }
    }
}

impl IdentityConfig {
    /// What this person's objects would be, or every reason they cannot be.
    ///
    /// Mode-blind on purpose: `DryRun` and `Enforce` plan identically, and withholding the write
    /// is the caller's job — so a dry run cannot measure something enforcement would not do.
    pub fn plan_for(
        &self,
        user: &WeeboSiUser,
        team: Option<&WeeboSiTeam>,
    ) -> Result<UserPlan, Vec<IdentityConfigViolation>> {
        let mut violations = Vec::new();
        let mut plan = UserPlan::default();

        if user.wants_authentik() {
            match self.authentik_plan(user, team) {
                Ok(authentik) => plan.authentik = Some(authentik),
                Err(mut found) => violations.append(&mut found),
            }
        }

        if user.wants_che() {
            match self.application_plan(user, team) {
                Ok(application) => plan.application = Some(application),
                Err(mut found) => violations.append(&mut found),
            }
        }

        if violations.is_empty() {
            Ok(plan)
        } else {
            Err(violations)
        }
    }

    /// The `AuthentikUser` half of a plan.
    fn authentik_plan(
        &self,
        user: &WeeboSiUser,
        team: Option<&WeeboSiTeam>,
    ) -> Result<AuthentikUserPlan, Vec<IdentityConfigViolation>> {
        let mut violations = Vec::new();

        let Some(email) = user.spec.email.clone().filter(|mail| !mail.is_empty()) else {
            return Err(vec![IdentityConfigViolation::EmailRequired(
                user.spec.username.clone(),
            )]);
        };

        let mut groups: BTreeSet<String> = BTreeSet::new();
        if let Some(team) = team {
            groups.extend(team.spec.identity.authentik.group_refs.iter().cloned());
        }
        if let Some(block) = &user.spec.authentik {
            groups.extend(block.group_refs.iter().cloned());
        }
        for group in &groups {
            if !allow_listed(&self.authentik.allowed_group_refs, group) {
                violations.push(IdentityConfigViolation::GroupRefNotAllowed {
                    subject: user.spec.username.to_string(),
                    group: group.clone(),
                });
            }
        }

        if !violations.is_empty() {
            return Err(violations);
        }

        Ok(AuthentikUserPlan {
            name: user.authentik_name(),
            username: user.spec.username.clone(),
            display_name: user.display_name(),
            email,
            is_active: user.spec.active,
            group_refs: groups.into_iter().collect(),
        })
    }

    /// The `Application` half of a plan.
    fn application_plan(
        &self,
        user: &WeeboSiUser,
        team: Option<&WeeboSiTeam>,
    ) -> Result<RenderedApplication, Vec<IdentityConfigViolation>> {
        let Some(team) = team else {
            return Err(vec![IdentityConfigViolation::WorkspaceWithoutTeam(
                user.spec.username.clone(),
            )]);
        };
        let team_name = team.team_name();

        let Some(template) = &team.spec.workspace.che else {
            return Err(vec![IdentityConfigViolation::WorkspaceWithoutTemplate {
                user: user.spec.username.clone(),
                team: team_name,
            }]);
        };

        if template.mode == ProvisioningMode::Off {
            return Err(vec![IdentityConfigViolation::WorkspaceDisabledByTeam {
                user: user.spec.username.clone(),
                team: team_name,
            }]);
        }

        let mut violations = self.template_violations(team);
        if !violations.is_empty() {
            return Err(violations);
        }

        let (namespace, values) = match &user.spec.che {
            Some(block) => (block.namespace.as_deref(), block.values.as_ref()),
            None => (None, None),
        };

        match template.render(
            &self.che.application_namespace,
            &user.bindings(),
            namespace,
            values,
        ) {
            Ok(application) => {
                // The allow-list was checked on the *template* above, where `{USERNAME}` is still
                // a placeholder; a prefix match there says nothing about what a username renders
                // to. Checked again on the value Argo will actually be given, and a `..` segment
                // is refused outright: it is how `https://git/org/{USERNAME}` becomes
                // `https://git/org/x/../../other` and still passes a prefix check.
                let rendered = &application.source.repo_url;
                if climbs_out(rendered) || !allow_listed(&self.che.allowed_repo_urls, rendered) {
                    violations.push(IdentityConfigViolation::RepoUrlNotAllowed {
                        team: team.team_name(),
                        repo_url: rendered.clone(),
                    });
                    return Err(violations);
                }
                Ok(application)
            }
            Err(error) => {
                violations.push(IdentityConfigViolation::RenderFailed {
                    user: user.spec.username.clone(),
                    error,
                });
                Err(violations)
            }
        }
    }

    /// Everything wrong with one team's workspace template, person-independent: its own shape,
    /// its project, its repository, and the groups it hands every member.
    pub fn team_violations(&self, team: &WeeboSiTeam) -> Vec<IdentityConfigViolation> {
        let mut violations = self.template_violations(team);
        for group in &team.spec.identity.authentik.group_refs {
            if !allow_listed(&self.authentik.allowed_group_refs, group) {
                violations.push(IdentityConfigViolation::GroupRefNotAllowed {
                    subject: team.team_name().to_string(),
                    group: group.clone(),
                });
            }
        }
        violations
    }

    /// The template half of [`IdentityConfig::team_violations`].
    fn template_violations(&self, team: &WeeboSiTeam) -> Vec<IdentityConfigViolation> {
        let Some(template) = &team.spec.workspace.che else {
            return Vec::new();
        };
        let team_name = team.team_name();
        let mut violations: Vec<IdentityConfigViolation> = template
            .validate_shape()
            .into_iter()
            .map(|violation| IdentityConfigViolation::TemplateInvalid {
                team: team_name.clone(),
                violation,
            })
            .collect();

        if !allow_listed(&self.che.allowed_projects, &template.project) {
            violations.push(IdentityConfigViolation::ProjectNotAllowed {
                team: team_name.clone(),
                project: template.project.clone(),
            });
        }
        if !allow_listed(&self.che.allowed_repo_urls, &template.source.repo_url) {
            violations.push(IdentityConfigViolation::RepoUrlNotAllowed {
                team: team_name,
                repo_url: template.source.repo_url.clone(),
            });
        }

        violations
    }

    /// Every violation over the whole set of teams and people, for the reconcile loop's
    /// `Degraded` conditions. One pass, every problem — never just the first.
    pub fn validate(
        &self,
        teams: &[WeeboSiTeam],
        users: &[WeeboSiUser],
    ) -> Vec<IdentityConfigViolation> {
        let mut violations = Vec::new();

        for team in teams {
            violations.extend(self.team_violations(team));
        }

        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut reported: BTreeSet<&str> = BTreeSet::new();
        for user in users {
            let username = user.spec.username.as_str();
            if !seen.insert(username) && reported.insert(username) {
                violations.push(IdentityConfigViolation::DuplicateUsername(
                    user.spec.username.clone(),
                ));
            }

            if let Some(team) = &user.spec.team
                && !teams.iter().any(|candidate| &candidate.team_name() == team)
            {
                violations.push(IdentityConfigViolation::UnknownTeam {
                    user: user.spec.username.clone(),
                    team: team.clone(),
                });
            }

            let team = user
                .spec
                .team
                .as_ref()
                .and_then(|name| teams.iter().find(|team| &team.team_name() == name));
            if let Err(mut found) = self.plan_for(user, team) {
                violations.append(&mut found);
            }
        }

        violations
    }
}

/// Whether `value` is on an allow-list. An entry ending in `*` matches by prefix; every other
/// entry matches exactly. An empty list matches nothing — the whole point of the list.
///
/// The prefix form is [`crate::endpoint_auth::OverrideMatch::matches_user`]'s, deliberately: two
/// allow-list dialects in one CRD would be one too many.
pub fn allow_listed(patterns: &[String], value: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => value.starts_with(prefix),
            None => pattern == value,
        })
}

/// How many times [`climbs_out`] percent-decodes before giving up and refusing. A git server
/// decodes once; anything still encoded after this many passes has no honest reason to be.
const MAX_DECODE_PASSES: usize = 4;

/// Whether a rendered repository URL contains a `..` segment in any spelling a server might
/// resolve: literal, percent-encoded (`%2e%2e`, `.%2E`), encoded again (`%252e`), or split by an
/// encoded or backslash separator (`x%2f..`, `x\..`). The prefix allow-list compares spellings,
/// so every spelling of "up one level" has to be refused before it runs.
fn climbs_out(url: &str) -> bool {
    let mut current = url.as_bytes().to_vec();
    for _ in 0..MAX_DECODE_PASSES {
        if has_dot_dot_segment(&current) {
            return true;
        }
        let decoded = percent_decode(&current);
        if decoded == current {
            return false;
        }
        current = decoded;
    }
    // Still decoding after every pass: refused rather than interpreted.
    true
}

fn has_dot_dot_segment(bytes: &[u8]) -> bool {
    bytes
        .split(|byte| matches!(byte, b'/' | b'\\' | b'?' | b'#'))
        .any(|segment| segment == b"..")
}

/// One pass of percent-decoding. A `%` not followed by two hex digits is kept as it is.
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
        {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "two hex digits are at most 0xff"
            )]
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::argo::{ApplicationDestination, ApplicationSource, ApplicationTemplate, SyncPolicy};
    use crate::selector::Selector;
    use crate::team::{TeamAuthentik, TeamFeatures, TeamIdentity, TeamWorkspace, WeeboSiTeamSpec};
    use crate::user::{UserAuthentik, UserChe, WeeboSiUserSpec};

    fn config() -> IdentityConfig {
        IdentityConfig {
            mode: FeatureMode::Enforce,
            authentik: AuthentikProvisioning {
                allowed_group_refs: vec!["platform".to_string(), "oncall-*".to_string()],
            },
            che: CheProvisioning {
                application_namespace: "argocd".to_string(),
                allowed_projects: vec!["weebo-dev".to_string()],
                allowed_repo_urls: vec!["https://charts.weebo.io*".to_string()],
            },
        }
    }

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
                values: Some(serde_json::json!({"username": "{USERNAME}"})),
            },
            destination: ApplicationDestination {
                server: Some("https://kubernetes.default.svc".to_string()),
                name: None,
                namespace: "{USERNAME}-che".to_string(),
            },
            sync_policy: Some(SyncPolicy::default()),
        }
    }

    fn team(che: Option<ApplicationTemplate>, groups: Vec<String>) -> WeeboSiTeam {
        let mut team = WeeboSiTeam::new(
            "platform",
            WeeboSiTeamSpec {
                display_name: None,
                priority: 100,
                namespace_selector: Selector::default(),
                features: TeamFeatures::default(),
                identity: TeamIdentity {
                    authentik: TeamAuthentik { group_refs: groups },
                },
                workspace: TeamWorkspace { che },
            },
        );
        team.status = None;
        team
    }

    fn user(authentik: Option<UserAuthentik>, che: Option<UserChe>) -> WeeboSiUser {
        let mut user = WeeboSiUser::new(
            "max",
            WeeboSiUserSpec {
                username: Username::new("max"),
                display_name: Some("Max".to_string()),
                email: Some("max@weebo.io".to_string()),
                team: Some(TeamName::new("platform")),
                active: true,
                authentik,
                che,
            },
        );
        user.status = None;
        user
    }

    fn ensure_authentik(groups: Vec<String>) -> Option<UserAuthentik> {
        Some(UserAuthentik {
            mode: ProvisioningMode::Ensure,
            name: None,
            group_refs: groups,
        })
    }

    fn ensure_che() -> Option<UserChe> {
        Some(UserChe {
            mode: ProvisioningMode::Ensure,
            namespace: None,
            values: None,
        })
    }

    #[test]
    fn a_plan_merges_the_teams_groups_with_the_persons() {
        let team = team(None, vec!["platform".to_string()]);
        let user = user(ensure_authentik(vec!["oncall-eu".to_string()]), None);
        let plan = config().plan_for(&user, Some(&team)).unwrap();
        let authentik = plan.authentik.unwrap();
        assert_eq!(
            authentik.group_refs,
            vec!["oncall-eu".to_string(), "platform".to_string()]
        );
        assert_eq!(authentik.email, "max@weebo.io".to_string());
        assert_eq!(authentik.spec()["isActive"], serde_json::json!(true));
    }

    #[test]
    fn a_group_outside_the_allow_list_refuses_the_whole_object() {
        let team = team(None, vec![]);
        let user = user(ensure_authentik(vec!["authentik-admins".to_string()]), None);
        let violations = config().plan_for(&user, Some(&team)).unwrap_err();
        assert_eq!(
            violations,
            vec![IdentityConfigViolation::GroupRefNotAllowed {
                subject: "max".to_string(),
                group: "authentik-admins".to_string(),
            }]
        );
    }

    #[test]
    fn an_empty_allow_list_allows_nothing() {
        let mut config = config();
        config.authentik.allowed_group_refs.clear();
        let team = team(None, vec!["platform".to_string()]);
        let user = user(ensure_authentik(vec![]), None);
        assert!(config.plan_for(&user, Some(&team)).is_err());
    }

    #[test]
    fn an_account_with_no_email_is_refused() {
        let team = team(None, vec![]);
        let mut user = user(ensure_authentik(vec![]), None);
        user.spec.email = None;
        assert_eq!(
            config().plan_for(&user, Some(&team)).unwrap_err(),
            vec![IdentityConfigViolation::EmailRequired(Username::new("max"))]
        );
    }

    #[test]
    fn a_workspace_plan_renders_the_teams_template() {
        let team = team(Some(template()), vec!["platform".to_string()]);
        let user = user(None, ensure_che());
        let plan = config().plan_for(&user, Some(&team)).unwrap();
        let application = plan.application.unwrap();
        assert_eq!(application.name, "che-max".to_string());
        assert_eq!(application.namespace, "argocd".to_string());
        assert_eq!(application.destination.namespace, "max-che".to_string());
    }

    #[test]
    fn a_repository_outside_the_allow_list_is_refused() {
        let mut template = template();
        template.source.repo_url = "https://charts.example.test".to_string();
        let team = team(Some(template), vec![]);
        let user = user(None, ensure_che());
        assert!(config().plan_for(&user, Some(&team)).unwrap_err().contains(
            &IdentityConfigViolation::RepoUrlNotAllowed {
                team: TeamName::new("platform"),
                repo_url: "https://charts.example.test".to_string(),
            }
        ));
    }

    #[test]
    fn a_username_cannot_render_the_repository_out_of_its_allowed_prefix() {
        let mut template = template();
        template.source.repo_url = "https://git.example.test/org/{USERNAME}".to_string();
        // A fixed namespace, so the hostile username is judged by the repository check and not
        // refused earlier by namespace rendering.
        template.destination.namespace = "che-users".to_string();
        let mut config = config();
        config.che.allowed_repo_urls = vec!["https://git.example.test/org/*".to_string()];
        let team = team(Some(template), vec![]);

        let mut honest = user(None, ensure_che());
        honest.spec.username = Username::new("max");
        assert!(config.plan_for(&honest, Some(&team)).is_ok());

        for name in [
            "x/../../other",
            "x/%2e%2e/%2e%2e/other",
            "x/%2E%2E/%2E%2E/other",
            "x/.%2e/.%2e/other",
            "x/%252e%252e/%252e%252e/other",
            "x%2f..%2f..%2fother",
            "x\\..\\..\\other",
            "x/%25252525252e%25252525252e/other",
        ] {
            let mut hostile = user(None, ensure_che());
            hostile.spec.username = Username::new(name);
            assert!(
                matches!(
                    config
                        .plan_for(&hostile, Some(&team))
                        .unwrap_err()
                        .as_slice(),
                    [IdentityConfigViolation::RepoUrlNotAllowed { .. }]
                ),
                "{name} should be refused"
            );
        }
    }

    #[test]
    fn dots_that_do_not_climb_are_not_refused() {
        for url in [
            "https://git.example.test/org/max.leriche",
            "https://git.example.test/org/..max",
            "https://git.example.test/org/max%20x",
            "https://git.example.test/org/100%",
        ] {
            assert!(!climbs_out(url), "{url} should not climb");
        }
    }

    #[test]
    fn a_person_with_no_team_cannot_have_a_workspace() {
        let mut user = user(None, ensure_che());
        user.spec.team = None;
        assert_eq!(
            config().plan_for(&user, None).unwrap_err(),
            vec![IdentityConfigViolation::WorkspaceWithoutTeam(
                Username::new("max")
            )]
        );
    }

    #[test]
    fn a_team_switching_its_workspace_off_is_reported_not_skipped() {
        let mut template = template();
        template.mode = ProvisioningMode::Off;
        let team = team(Some(template), vec![]);
        let user = user(None, ensure_che());
        assert_eq!(
            config().plan_for(&user, Some(&team)).unwrap_err(),
            vec![IdentityConfigViolation::WorkspaceDisabledByTeam {
                user: Username::new("max"),
                team: TeamName::new("platform"),
            }]
        );
    }

    #[test]
    fn two_people_claiming_one_username_is_reported_once() {
        let team = team(None, vec![]);
        let first = user(None, None);
        let mut second = user(None, None);
        second.metadata.name = Some("max-2".to_string());
        let violations = config().validate(&[team], &[first, second]);
        assert_eq!(
            violations,
            vec![IdentityConfigViolation::DuplicateUsername(Username::new(
                "max"
            ))]
        );
    }

    #[test]
    fn a_person_naming_a_team_that_does_not_exist_is_reported() {
        let user = user(None, None);
        assert_eq!(
            config().validate(&[], &[user]),
            vec![IdentityConfigViolation::UnknownTeam {
                user: Username::new("max"),
                team: TeamName::new("platform"),
            }]
        );
    }

    #[test]
    fn the_allow_list_prefix_form_matches_by_prefix_only() {
        let patterns = vec!["oncall-*".to_string(), "platform".to_string()];
        assert!(allow_listed(&patterns, "oncall-eu"));
        assert!(allow_listed(&patterns, "platform"));
        assert!(!allow_listed(&patterns, "platform-admins"));
        assert!(!allow_listed(&[], "platform"));
    }
}
