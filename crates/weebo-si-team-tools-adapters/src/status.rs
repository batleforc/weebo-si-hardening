//! `WeeboSiTeam.status.teamTools` and its `TeamToolsReady` condition.
//!
//! The identity loop writes the same status with a JSON merge patch of the whole struct, which
//! replaces `conditions`. This writer therefore touches only `status.teamTools` and its own
//! condition: it reads the live team, keeps every other condition as is, and patches with the
//! `resourceVersion` it read, so a write racing identity's is refused (and redone next pass)
//! rather than dropping identity's `Ready`. Identity, in turn, carries `TeamToolsReady` over.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Patch, PatchParams};
use kube::{Api, ResourceExt};
use serde_json::json;
use weebo_si_crd::{TeamToolStatus, WeeboSiTeam};
use weebo_si_team_tools::FIELD_MANAGER;

/// The condition type this feature owns on a `WeeboSiTeam`.
pub const CONDITION: &str = "TeamToolsReady";

/// What one team's status should say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamReport {
    /// One entry per tool.
    pub tools: Vec<TeamToolStatus>,
    /// `TeamToolsReady`: `(status, reason, message)`; `None` removes the condition (the team has
    /// no `teamTools` block any more).
    pub ready: Option<(bool, String, String)>,
}

/// `conditions` with this feature's condition replaced by `ready`, every other one untouched.
/// The transition time is kept while the status does not change.
pub fn merge_conditions(
    current: &[Condition],
    ready: Option<&(bool, String, String)>,
    generation: i64,
    now: Time,
) -> Vec<Condition> {
    let previous = current
        .iter()
        .find(|condition| condition.type_ == CONDITION);
    let mut conditions: Vec<Condition> = current
        .iter()
        .filter(|condition| condition.type_ != CONDITION)
        .cloned()
        .collect();
    if let Some((ok, reason, message)) = ready {
        let status = if *ok { "True" } else { "False" }.to_string();
        let last_transition_time = previous
            .filter(|previous| previous.status == status)
            .map_or(now, |previous| previous.last_transition_time.clone());
        conditions.push(Condition {
            type_: CONDITION.to_string(),
            status,
            reason: reason.clone(),
            message: message.clone(),
            observed_generation: Some(generation),
            last_transition_time,
        });
    }
    conditions
}

/// Write `report` on team `name`, unless the live status already says it or the team is gone.
/// `Ok(false)` when the write lost a race with another writer (409): retried next pass.
pub async fn write(
    api: &Api<WeeboSiTeam>,
    name: &str,
    report: &TeamReport,
) -> Result<bool, kube::Error> {
    match api.get_opt(name).await? {
        Some(team) => write_over(api, &team, report).await,
        None => Ok(true),
    }
}

/// [`write`] against `team` as read, its `resourceVersion` pinning the patch.
pub async fn write_over(
    api: &Api<WeeboSiTeam>,
    team: &WeeboSiTeam,
    report: &TeamReport,
) -> Result<bool, kube::Error> {
    let status = team.status.clone().unwrap_or_default();
    let conditions = merge_conditions(
        &status.conditions,
        report.ready.as_ref(),
        team.metadata.generation.unwrap_or(0),
        Time(k8s_openapi::jiff::Timestamp::now()),
    );
    if status.team_tools == report.tools && status.conditions == conditions {
        return Ok(true);
    }
    let patch = json!({
        "metadata": {"resourceVersion": team.metadata.resource_version},
        // An explicit list, `[]` included: merge patch replaces it, and an omitted field would
        // leave the last value behind.
        "status": {"teamTools": report.tools, "conditions": conditions},
    });
    match api
        .patch_status(
            &team.name_any(),
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Merge(&patch),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(status)) if status.code == 409 => Ok(false),
        Err(err) => Err(err),
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

    fn condition(type_: &str, status: &str, at: i64) -> Condition {
        Condition {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: "AsExpected".to_string(),
            message: String::new(),
            observed_generation: Some(1),
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::from_second(at).unwrap()),
        }
    }

    fn now() -> Time {
        Time(k8s_openapi::jiff::Timestamp::from_second(1_000).unwrap())
    }

    #[test]
    fn identitys_condition_is_kept_and_ours_replaced() {
        let current = vec![
            condition("Ready", "True", 1),
            condition(CONDITION, "True", 2),
        ];
        let ready = (
            false,
            "NamespaceNotBound".to_string(),
            "not bound".to_string(),
        );
        let merged = merge_conditions(&current, Some(&ready), 3, now());
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0], current[0]);
        assert_eq!(merged[1].status, "False");
        assert_eq!(merged[1].reason, "NamespaceNotBound");
        assert_eq!(merged[1].last_transition_time, now());
    }

    #[test]
    fn an_unchanged_status_keeps_its_transition_time() {
        let current = vec![condition(CONDITION, "True", 2)];
        let ready = (true, "Bound".to_string(), String::new());
        let merged = merge_conditions(&current, Some(&ready), 3, now());
        assert_eq!(
            merged[0].last_transition_time,
            current[0].last_transition_time
        );
    }

    #[test]
    fn no_block_removes_only_our_condition() {
        let current = vec![
            condition("Ready", "True", 1),
            condition(CONDITION, "True", 2),
        ];
        let merged = merge_conditions(&current, None, 3, now());
        assert_eq!(merged, vec![current[0].clone()]);
    }
}
