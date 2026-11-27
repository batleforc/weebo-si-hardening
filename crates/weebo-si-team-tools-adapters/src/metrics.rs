//! RFC 0020's *Observability* table. Labels are a `WeeboSiTeam` name and a catalogue key, both
//! admin-written and bounded; no metric carries a namespace or a user.

use std::collections::BTreeSet;
use std::sync::Mutex;

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};

/// Every `result` of `weebo_si_team_tools_reconcile_total`.
pub const RESULTS: [&str; 8] = [
    "applied",
    "unchanged",
    "deleted",
    "not_granted",
    "invalid",
    "unbound",
    "forbidden",
    "error",
];

/// One tool's gauges, as a pass leaves them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolGauges {
    /// The `WeeboSiTeam`.
    pub team: String,
    /// The catalogue key.
    pub tool: String,
    /// The workload's replicas.
    pub replicas: i64,
    /// DevWorkspaces of the team requesting the key.
    pub requesters: i64,
    /// Up, no requester, past the grace and 60 s more.
    pub up_without_requester: bool,
}

/// The six metrics.
pub struct TeamToolsMetrics {
    replicas: IntGaugeVec,
    requesters: IntGaugeVec,
    scale_total: IntCounterVec,
    up_without_requester: IntGaugeVec,
    reconcile_total: IntCounterVec,
    entries: IntGaugeVec,
    series: Mutex<BTreeSet<(String, String)>>,
}

impl TeamToolsMetrics {
    /// Register every metric against `registry`, the known label values at zero.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let gauge =
            |name: &str, help: &str| IntGaugeVec::new(Opts::new(name, help), &["team", "tool"]);
        let replicas = gauge(
            "weebo_si_team_tools_replicas",
            "Replicas of each team tool's workload",
        )?;
        let requesters = gauge(
            "weebo_si_team_tools_requesters",
            "DevWorkspaces of the team requesting each tool, any phase",
        )?;
        let up_without_requester = gauge(
            "weebo_si_team_tools_up_without_requester",
            "1 when a tool is up with no requester past its idle grace plus 60 s",
        )?;
        let scale_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_team_tools_scale_total",
                "Writes through /scale, by direction and result",
            ),
            &["team", "tool", "direction", "result"],
        )?;
        let reconcile_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_team_tools_reconcile_total",
                "team-tools reconcile outcomes, by result",
            ),
            &["result"],
        )?;
        let entries = IntGaugeVec::new(
            Opts::new(
                "weebo_si_team_tools_entries",
                "Team tool catalogue entries, by whether they are safe to apply",
            ),
            &["state"],
        )?;
        registry.register(Box::new(replicas.clone()))?;
        registry.register(Box::new(requesters.clone()))?;
        registry.register(Box::new(scale_total.clone()))?;
        registry.register(Box::new(up_without_requester.clone()))?;
        registry.register(Box::new(reconcile_total.clone()))?;
        registry.register(Box::new(entries.clone()))?;
        for result in RESULTS {
            reconcile_total.with_label_values(&[result]);
        }
        for state in ["valid", "invalid"] {
            entries.with_label_values(&[state]).set(0);
        }
        Ok(Self {
            replicas,
            requesters,
            scale_total,
            up_without_requester,
            reconcile_total,
            entries,
            series: Mutex::new(BTreeSet::new()),
        })
    }

    /// One reconcile outcome; `result` is one of [`RESULTS`].
    pub fn reconciled(&self, result: &str) {
        self.reconcile_total.with_label_values(&[result]).inc();
    }

    /// One `/scale` write.
    pub fn scaled(&self, team: &str, tool: &str, up: bool, ok: bool) {
        self.scale_total
            .with_label_values(&[
                team,
                tool,
                if up { "up" } else { "down" },
                if ok { "ok" } else { "error" },
            ])
            .inc();
    }

    /// The catalogue was checked.
    pub fn entries(&self, valid: usize, invalid: usize) {
        let as_gauge = |count: usize| i64::try_from(count).unwrap_or(i64::MAX);
        self.entries
            .with_label_values(&["valid"])
            .set(as_gauge(valid));
        self.entries
            .with_label_values(&["invalid"])
            .set(as_gauge(invalid));
    }

    /// The gauges of every tool a full pass saw; a tool no longer seen loses its series.
    pub fn tools(&self, tools: &[ToolGauges]) {
        let mut series = self
            .series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let seen: BTreeSet<(String, String)> = tools
            .iter()
            .map(|tool| (tool.team.clone(), tool.tool.clone()))
            .collect();
        for (team, tool) in series.difference(&seen) {
            for gauge in [&self.replicas, &self.requesters, &self.up_without_requester] {
                // A series never set is simply absent: nothing to remove is not an error.
                if gauge.remove_label_values(&[team, tool]).is_err() {
                    tracing::debug!("team-tools gauge series {team}/{tool} already absent");
                }
            }
        }
        for tool in tools {
            let labels = [tool.team.as_str(), tool.tool.as_str()];
            self.replicas.with_label_values(&labels).set(tool.replicas);
            self.requesters
                .with_label_values(&labels)
                .set(tool.requesters);
            self.up_without_requester
                .with_label_values(&labels)
                .set(i64::from(tool.up_without_requester));
        }
        *series = seen;
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

    fn gauges(tool: &str, replicas: i64) -> ToolGauges {
        ToolGauges {
            team: "weebo".to_string(),
            tool: tool.to_string(),
            replicas,
            requesters: 1,
            up_without_requester: false,
        }
    }

    #[test]
    fn a_tool_no_longer_seen_loses_its_series() {
        let registry = Registry::new();
        let metrics = TeamToolsMetrics::register(&registry).unwrap();
        metrics.tools(&[gauges("buildkit", 1), gauges("android", 0)]);
        metrics.tools(&[gauges("buildkit", 0)]);
        let replicas = registry
            .gather()
            .into_iter()
            .find(|family| family.name() == "weebo_si_team_tools_replicas")
            .unwrap();
        assert_eq!(replicas.get_metric().len(), 1);
        metrics.scaled("weebo", "buildkit", true, true);
        metrics.reconciled("applied");
        metrics.entries(1, 0);
    }
}
