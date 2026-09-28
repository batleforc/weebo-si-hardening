//! In-memory fakes for this crate's ports — the same `testing` feature every other brick here
//! ships, so the controller's own tests can drive a provisioner that never touches a cluster.

use std::collections::BTreeMap;
use std::sync::Mutex;

use weebo_si_chassis::DomainError;
use weebo_si_crd::TargetState;

use crate::port::{DesiredObject, Observation, PortFuture, ProvisionObserver, Provisioner};

/// A provisioner over a `BTreeMap`. Records everything applied, so a test can assert on what was
/// written *and* on what was not.
pub struct FakeProvisioner {
    kind: &'static str,
    observed: Mutex<BTreeMap<String, Observation>>,
    applied: Mutex<Vec<DesiredObject>>,
    fails: Mutex<bool>,
}

impl FakeProvisioner {
    /// A provisioner of `kind` holding nothing.
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            observed: Mutex::new(BTreeMap::new()),
            applied: Mutex::new(Vec::new()),
            fails: Mutex::new(false),
        }
    }

    /// Seed what the cluster holds under `name`.
    pub fn with(self, name: &str, observation: Observation) -> Self {
        if let Ok(mut observed) = self.observed.lock() {
            observed.insert(name.to_owned(), observation);
        }
        self
    }

    /// Make every call fail, for the "the apiserver said no" path.
    pub fn failing(self) -> Self {
        if let Ok(mut fails) = self.fails.lock() {
            *fails = true;
        }
        self
    }

    /// Everything [`Provisioner::apply`] was called with, in order.
    pub fn applied(&self) -> Vec<DesiredObject> {
        self.applied
            .lock()
            .map(|applied| applied.clone())
            .unwrap_or_default()
    }

    fn failing_now(&self) -> bool {
        self.fails.lock().map(|fails| *fails).unwrap_or(false)
    }
}

impl Provisioner for FakeProvisioner {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn observe<'a>(
        &'a self,
        name: &'a str,
        _namespace: Option<&'a str>,
    ) -> PortFuture<'a, Observation> {
        Box::pin(async move {
            if self.failing_now() {
                return Err(DomainError::PortFailed("fake failure".to_string()));
            }
            Ok(self
                .observed
                .lock()
                .ok()
                .and_then(|observed| observed.get(name).cloned())
                .unwrap_or(Observation::Missing))
        })
    }

    fn apply<'a>(&'a self, desired: &'a DesiredObject) -> PortFuture<'a, ()> {
        Box::pin(async move {
            if self.failing_now() {
                return Err(DomainError::PortFailed("fake failure".to_string()));
            }
            if let Ok(mut applied) = self.applied.lock() {
                applied.push(desired.clone());
            }
            if let Ok(mut observed) = self.observed.lock() {
                observed.insert(
                    desired.name.clone(),
                    Observation::Present {
                        owner_uid: Some(desired.owner.uid.clone()),
                        spec: desired.spec.clone(),
                    },
                );
            }
            Ok(())
        })
    }
}

/// An observer that counts, for tests that care that something was reported at all.
#[derive(Default)]
pub struct FakeObserver {
    events: Mutex<Vec<String>>,
}

impl FakeObserver {
    /// Everything reported, in order, as `"<what>:<detail>"`.
    pub fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    fn record(&self, event: String) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

impl ProvisionObserver for FakeObserver {
    fn team_reconciled(&self, degraded: bool) {
        self.record(format!("team:{degraded}"));
    }

    fn user_reconciled(&self, kind: &str, state: TargetState) {
        self.record(format!("user:{kind}:{state}"));
    }

    fn provision_failed(&self, kind: &str) {
        self.record(format!("failed:{kind}"));
    }
}
