//! The decisions: what one pass does to one provisioned object, and what a team's status says.
//!
//! Everything here is a function of values the caller already has. The only `await` is the port
//! call [`reconcile_target`] makes on the caller's behalf, and the branch it takes was decided
//! by [`decide`] before it.

use std::collections::BTreeMap;

use weebo_si_chassis::DomainError;
use weebo_si_crd::{
    IdentityConfig, ResolveConflict, TargetState, TargetStatus, Team, WeeboSiTeam, WeeboSiUser,
    team_views,
};

use crate::port::{DesiredObject, Observation, ProvisionObserver, Provisioner};

/// What this pass does to one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing exists; write it.
    Create,
    /// This operator owns it and it has drifted; write it again.
    Update,
    /// This operator owns it and it already says what we would say.
    Unchanged,
    /// It exists and somebody else owns it. **Referenced, never written** — an object an admin
    /// made is not this loop's to take over, and the alternative (patch it into shape) is how a
    /// hardening operator silently rewrites an identity somebody was relying on.
    Adopt,
    /// It exists and another `WeeboSiUser` owns it. Two people claiming one target is a
    /// configuration mistake with no correct resolution, so neither wins.
    Conflict,
    /// The kind is not served by this cluster.
    Absent,
}

impl Action {
    /// The state this action reports on the person's own object.
    pub fn state(self) -> TargetState {
        match self {
            Self::Create | Self::Update | Self::Unchanged => TargetState::Created,
            Self::Adopt => TargetState::Adopted,
            Self::Conflict => TargetState::Conflict,
            Self::Absent => TargetState::Absent,
        }
    }

    /// Whether this action writes anything. `DryRun` is this same decision with the write
    /// withheld, which is why the caller and not this type decides.
    pub fn writes(self) -> bool {
        matches!(self, Self::Create | Self::Update)
    }
}

/// What to do about one object, given what the cluster currently holds.
///
/// `owner_uid` is the `WeeboSiUser`'s own `metadata.uid`: ownership is compared by uid and never
/// by name, so a person deleted and recreated under the same name does not silently inherit the
/// objects of the first one.
pub fn decide(desired: &DesiredObject, observation: &Observation, owner_uid: &str) -> Action {
    match observation {
        Observation::KindAbsent => Action::Absent,
        Observation::Missing => Action::Create,
        Observation::Present {
            owner_uid: Some(uid),
            spec,
        } if uid == owner_uid => {
            if spec == &desired.spec {
                Action::Unchanged
            } else {
                Action::Update
            }
        }
        Observation::Present {
            owner_uid: Some(_), ..
        } => Action::Conflict,
        Observation::Present {
            owner_uid: None, ..
        } => Action::Adopt,
    }
}

/// Observe, decide, write when asked to, and report — one object, one pass.
///
/// `enforce` is the feature's mode with `Off` already handled by the caller: `false` is
/// `DryRun`, which takes every decision and writes nothing, so a dry run cannot measure
/// something enforcement would not do.
pub async fn reconcile_target(
    provisioner: &dyn Provisioner,
    desired: &DesiredObject,
    owner_uid: &str,
    enforce: bool,
    observer: &dyn ProvisionObserver,
) -> Result<TargetStatus, DomainError> {
    let kind = provisioner.kind();
    let observation = match provisioner
        .observe(&desired.name, desired.namespace.as_deref())
        .await
    {
        Ok(observation) => observation,
        Err(err) => {
            observer.provision_failed(kind);
            return Err(err);
        }
    };

    let action = decide(desired, &observation, owner_uid);
    if action.writes()
        && enforce
        && let Err(err) = provisioner.apply(desired).await
    {
        observer.provision_failed(kind);
        return Err(err);
    }

    let state = action.state();
    observer.user_reconciled(kind, state);
    Ok(TargetStatus {
        name: desired.name.clone(),
        namespace: desired.namespace.clone(),
        state,
        message: message_for(kind, &desired.name, action, enforce),
    })
}

/// The human-readable half of a [`TargetStatus`].
fn message_for(kind: &str, name: &str, action: Action, enforce: bool) -> String {
    match (action, enforce) {
        (Action::Create, true) => format!("created {kind}/{name}"),
        (Action::Create, false) => format!("would create {kind}/{name}"),
        (Action::Update, true) => format!("updated {kind}/{name}"),
        (Action::Update, false) => format!("would update {kind}/{name}"),
        (Action::Unchanged, _) => format!("{kind}/{name} is up to date"),
        (Action::Adopt, _) => {
            format!("{kind}/{name} exists and is owned by somebody else: referenced, never written")
        }
        (Action::Conflict, _) => {
            format!("another WeeboSiUser already owns {kind}/{name}")
        }
        (Action::Absent, _) => {
            format!("this cluster does not serve the {kind} kind, so {name} cannot exist")
        }
    }
}

/// One namespace, as a team's selector sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedNamespace {
    /// Its name, for the contested-namespace message.
    pub name: String,
    /// Its labels — the only thing a team selector reads.
    pub labels: BTreeMap<String, String>,
}

/// What one team's `status` says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeamReport {
    /// Namespaces this team actually owns — matched by its selector **and** won against every
    /// other team's priority. Not "matched by the selector": a count that includes namespaces
    /// another team owns is a count that hides the overlap.
    pub namespaces: i64,
    /// `WeeboSiUser` objects naming this team.
    pub members: i64,
    /// Everything wrong with this team, one message per problem.
    pub violations: Vec<String>,
}

/// How many contested namespaces one message names before it stops listing them. A condition is
/// read in a terminal; an admin who has mislabelled two hundred namespaces needs the count and a
/// sample, not two hundred names.
const CONTESTED_SAMPLE: usize = 3;

/// Everything `WeeboSiTeam.status` reports, computed from what the cluster holds.
///
/// `conflicts` is the resolution's own output — the catalogue keys somebody redefined — filtered
/// here to the ones this team is responsible for, so each team's condition names its own
/// mistakes and no team is blamed for another's.
pub fn report_team(
    team: &WeeboSiTeam,
    teams: &[WeeboSiTeam],
    users: &[WeeboSiUser],
    namespaces: &[ObservedNamespace],
    conflicts: &[ResolveConflict],
    identity: Option<&IdentityConfig>,
) -> TeamReport {
    let name = team.team_name();
    let ordered = team_views(teams);

    let mut owned = 0_i64;
    let mut contested: Vec<String> = Vec::new();
    for namespace in namespaces {
        if !team.spec.namespace_selector.matches(&namespace.labels) {
            continue;
        }
        match owner_of(&ordered, &namespace.labels) {
            Some(owner) if owner == name => owned += 1,
            Some(owner) => contested.push(format!("{} (owned by {owner})", namespace.name)),
            None => {}
        }
    }

    let members = users
        .iter()
        .filter(|user| user.spec.team.as_ref() == Some(&name))
        .count() as i64;

    let mut violations: Vec<String> = conflicts
        .iter()
        .filter(|conflict| conflict.team.as_ref() == Some(&name))
        .map(|conflict| conflict.message.clone())
        .collect();

    if let Some(identity) = identity {
        violations.extend(
            identity
                .team_violations(team)
                .iter()
                .map(ToString::to_string),
        );
    }

    if !contested.is_empty() {
        let sample = contested
            .iter()
            .take(CONTESTED_SAMPLE)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if contested.len() > CONTESTED_SAMPLE {
            format!(", and {} more", contested.len() - CONTESTED_SAMPLE)
        } else {
            String::new()
        };
        violations.push(format!(
            "{} namespace(s) match this team's selector and belong to a team with a lower \
             priority: {sample}{suffix}",
            contested.len()
        ));
    }

    TeamReport {
        namespaces: owned,
        members,
        violations,
    }
}

/// Which team owns a namespace: first match in resolution order, per RFC 0011.
fn owner_of(ordered: &[Team], labels: &BTreeMap<String, String>) -> Option<weebo_si_crd::TeamName> {
    ordered
        .iter()
        .find(|team| team.namespace_selector.matches(labels))
        .map(|team| team.name.clone())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::testing::{FakeObserver, FakeProvisioner};
    use weebo_si_crd::{
        Selector, TeamName, Username, WeeboSiTeamSpec, WeeboSiUserSpec, team::TeamFeatures,
    };

    fn desired() -> DesiredObject {
        DesiredObject {
            name: "max".to_string(),
            namespace: None,
            labels: BTreeMap::new(),
            spec: serde_json::json!({"username": "max"}),
            owner: crate::port::ObjectOwner {
                api_version: "hardening.weebo.io/v1alpha1".to_string(),
                kind: "WeeboSiUser".to_string(),
                name: "max".to_string(),
                uid: "uid-1".to_string(),
            },
        }
    }

    #[test]
    fn nothing_there_is_a_create() {
        assert_eq!(
            decide(&desired(), &Observation::Missing, "uid-1"),
            Action::Create
        );
    }

    #[test]
    fn our_own_object_in_shape_is_left_alone() {
        let observation = Observation::Present {
            owner_uid: Some("uid-1".to_string()),
            spec: serde_json::json!({"username": "max"}),
        };
        assert_eq!(decide(&desired(), &observation, "uid-1"), Action::Unchanged);
    }

    #[test]
    fn our_own_object_that_drifted_is_written_again() {
        let observation = Observation::Present {
            owner_uid: Some("uid-1".to_string()),
            spec: serde_json::json!({"username": "somebody-else"}),
        };
        assert_eq!(decide(&desired(), &observation, "uid-1"), Action::Update);
    }

    #[test]
    fn somebody_elses_object_is_adopted_never_written() {
        let observation = Observation::Present {
            owner_uid: None,
            spec: serde_json::json!({"username": "max"}),
        };
        assert_eq!(decide(&desired(), &observation, "uid-1"), Action::Adopt);
        assert!(!Action::Adopt.writes());
    }

    #[test]
    fn another_person_owning_the_target_is_a_conflict() {
        let observation = Observation::Present {
            owner_uid: Some("uid-2".to_string()),
            spec: serde_json::json!({"username": "max"}),
        };
        assert_eq!(decide(&desired(), &observation, "uid-1"), Action::Conflict);
    }

    #[test]
    fn an_uninstalled_kind_is_absent_not_missing() {
        assert_eq!(
            decide(&desired(), &Observation::KindAbsent, "uid-1"),
            Action::Absent
        );
    }

    #[tokio::test]
    async fn enforce_writes_and_dry_run_does_not() {
        let observer = FakeObserver::default();

        let enforcing = FakeProvisioner::new("AuthentikUser");
        let status = reconcile_target(&enforcing, &desired(), "uid-1", true, &observer)
            .await
            .unwrap();
        assert_eq!(status.state, TargetState::Created);
        assert_eq!(enforcing.applied().len(), 1);

        let dry = FakeProvisioner::new("AuthentikUser");
        let status = reconcile_target(&dry, &desired(), "uid-1", false, &observer)
            .await
            .unwrap();
        assert_eq!(status.state, TargetState::Created);
        assert_eq!(status.message, "would create AuthentikUser/max".to_string());
        assert!(dry.applied().is_empty(), "a dry run writes nothing");
    }

    #[tokio::test]
    async fn an_adopted_object_is_never_written() {
        let observer = FakeObserver::default();
        let provisioner = FakeProvisioner::new("AuthentikUser").with(
            "max",
            Observation::Present {
                owner_uid: None,
                spec: serde_json::json!({"username": "somebody-else"}),
            },
        );
        let status = reconcile_target(&provisioner, &desired(), "uid-1", true, &observer)
            .await
            .unwrap();
        assert_eq!(status.state, TargetState::Adopted);
        assert!(provisioner.applied().is_empty());
    }

    fn team(name: &str, priority: i32, label: &str) -> WeeboSiTeam {
        let mut selector = Selector::default();
        selector
            .match_labels
            .insert("weebo.io/team".to_string(), label.to_string());
        let mut team = WeeboSiTeam::new(
            name,
            WeeboSiTeamSpec {
                display_name: None,
                priority,
                namespace_selector: selector,
                features: TeamFeatures::default(),
                identity: Default::default(),
                workspace: Default::default(),
            },
        );
        team.status = None;
        team
    }

    fn namespace(name: &str, label: &str) -> ObservedNamespace {
        ObservedNamespace {
            name: name.to_string(),
            labels: BTreeMap::from([("weebo.io/team".to_string(), label.to_string())]),
        }
    }

    fn user(name: &str, team: Option<&str>) -> WeeboSiUser {
        let mut user = WeeboSiUser::new(
            name,
            WeeboSiUserSpec {
                username: Username::new(name),
                display_name: None,
                email: None,
                team: team.map(TeamName::new),
                active: true,
                authentik: None,
                che: None,
            },
        );
        user.status = None;
        user
    }

    #[test]
    fn a_report_counts_the_namespaces_it_owns_and_the_people_naming_it() {
        let teams = vec![team("platform", 100, "platform")];
        let users = vec![user("max", Some("platform")), user("sam", None)];
        let namespaces = vec![
            namespace("a", "platform"),
            namespace("b", "platform"),
            namespace("c", "research"),
        ];
        let report = report_team(&teams[0], &teams, &users, &namespaces, &[], None);
        assert_eq!(report.namespaces, 2);
        assert_eq!(report.members, 1);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn a_namespace_another_team_won_is_reported_and_not_counted() {
        let teams = vec![
            team("platform", 200, "shared"),
            team("research", 100, "shared"),
        ];
        let namespaces = vec![namespace("a", "shared")];
        let report = report_team(&teams[0], &teams, &[], &namespaces, &[], None);
        assert_eq!(report.namespaces, 0);
        assert_eq!(report.violations.len(), 1);
        assert!(
            report.violations[0].contains("owned by research"),
            "{}",
            report.violations[0]
        );
    }

    #[test]
    fn only_this_teams_conflicts_reach_its_own_status() {
        let teams = vec![team("platform", 100, "platform")];
        let conflicts = vec![
            ResolveConflict {
                team: Some(TeamName::new("platform")),
                message: "platform redefines gpu".to_string(),
            },
            ResolveConflict {
                team: Some(TeamName::new("research")),
                message: "research redefines gpu".to_string(),
            },
        ];
        let report = report_team(&teams[0], &teams, &[], &[], &conflicts, None);
        assert_eq!(
            report.violations,
            vec!["platform redefines gpu".to_string()]
        );
    }
}
