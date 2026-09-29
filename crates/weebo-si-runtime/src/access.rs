//! "May this process watch that?" — asked of the apiserver before an optional watch is started.
//!
//! Several watches in this operator only make sense when the chart granted the matching read
//! (`networkProfiles.cilium.enabled`, `kubearmorPolicy.rbac.enabled`,
//! `registryConfig.rbac.enabled`, `endpointAuth.rbac.enabled`). A reflector started without that
//! grant does not fail: it retries a `403` forever, and every startup that waits on its initial
//! list waits forever with it — health never served, the pod restarted in a loop, and every
//! `failurePolicy: Fail` webhook refusing writes in the meantime. Asking first, with a
//! `SelfSubjectAccessReview` (which every authenticated identity may create), turns a missing
//! grant into a feature that is inert and says so on stdout, rather than a process that never
//! starts.
//!
//! **Only an answer is an answer.** The question is asked once, at boot, and whatever it returns
//! shapes the process for its whole lifetime. Reading a failed *request* as "not allowed" would
//! let a single apiserver blip silently disable a feature until the next restart — and, for the
//! Cilium backend, let the webhook and the controller (which each ask independently) disagree
//! about which backend is live, so that every baseline check misses and every DevWorkspace
//! `CREATE` is refused. So a failed request is retried with a bounded exponential backoff, and
//! only an actual `status.allowed == false` reads as "not allowed". If the apiserver still cannot
//! be asked once the budget is spent, the error is returned: startup fails loudly, the process
//! exits non-zero and Kubernetes restarts it, instead of running with a feature quietly off.

use std::fmt::Display;
use std::future::Future;
use std::time::Duration;

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use kube::api::PostParams;
use kube::{Api, Client};
use tokio::time::Instant;

/// What a watch needs: an initial `list`, then a `watch`.
const WATCH_VERBS: [&str; 2] = ["list", "watch"];

/// How long, and how patiently, a failed review request is retried.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryPolicy {
    /// The delay after the first failure; doubled after each further one.
    pub(crate) initial: Duration,
    /// The longest single delay.
    pub(crate) max_delay: Duration,
    /// The total time, across every verb of one question, after which the last error is
    /// returned instead of retried.
    pub(crate) budget: Duration,
}

/// Exponential from 500ms, capped at 8s per wait, about a minute in all — long enough to ride out
/// an apiserver rollout or a leader change, short enough that a genuinely unreachable apiserver
/// fails the pod's startup well inside any sane startup probe window.
const DEFAULT_RETRY: RetryPolicy = RetryPolicy {
    initial: Duration::from_millis(500),
    max_delay: Duration::from_secs(8),
    budget: Duration::from_secs(60),
};

/// A review request that did not produce an answer.
#[derive(Debug)]
enum ReviewError {
    /// The request itself failed.
    Request(kube::Error),
    /// The apiserver answered without a `status` — not an answer either.
    NoStatus,
}

impl Display for ReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(err) => write!(f, "{err}"),
            Self::NoStatus => write!(f, "the SelfSubjectAccessReview came back without a status"),
        }
    }
}

impl From<ReviewError> for kube::Error {
    fn from(err: ReviewError) -> Self {
        match err {
            ReviewError::Request(err) => err,
            no_status @ ReviewError::NoStatus => kube::Error::Discovery(
                kube::error::DiscoveryError::MissingResource(no_status.to_string()),
            ),
        }
    }
}

/// Whether this process may `list` and `watch` `resource` in `group` — cluster-wide when
/// `namespace` is `None`, in that namespace otherwise.
///
/// `Ok(false)` only when the apiserver actually answered "not allowed" for one of the verbs. A
/// request that fails is retried (see the module docs); once the retry budget is spent the last
/// error is returned, and the caller is expected to fail startup with it.
pub async fn can_watch(
    client: &Client,
    group: &str,
    resource: &str,
    namespace: Option<&str>,
) -> Result<bool, kube::Error> {
    let api: Api<SelfSubjectAccessReview> = Api::all(client.clone());
    let what = format!("{resource}.{group}");
    decide(DEFAULT_RETRY, &what, |verb| {
        let api = api.clone();
        let review = review_for(group, resource, namespace, verb);
        async move {
            match api.create(&PostParams::default(), &review).await {
                Ok(answer) => answer
                    .status
                    .map(|status| status.allowed)
                    .ok_or(ReviewError::NoStatus),
                Err(err) => Err(ReviewError::Request(err)),
            }
        }
    })
    .await
    .map_err(kube::Error::from)
}

fn review_for(
    group: &str,
    resource: &str,
    namespace: Option<&str>,
    verb: &str,
) -> SelfSubjectAccessReview {
    SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                group: Some(group.to_string()),
                resource: Some(resource.to_string()),
                namespace: namespace.map(str::to_string),
                verb: Some(verb.to_string()),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        ..SelfSubjectAccessReview::default()
    }
}

/// The decision, with the one review call as a seam: every verb in [`WATCH_VERBS`] must be
/// answered `true`; the first `false` answer decides "not allowed"; a failed call is retried with
/// `policy`'s backoff until its budget — shared by every verb of this one question — is spent,
/// and then its error is returned.
async fn decide<F, Fut, E>(policy: RetryPolicy, what: &str, mut review: F) -> Result<bool, E>
where
    F: FnMut(&'static str) -> Fut,
    Fut: Future<Output = Result<bool, E>>,
    E: Display,
{
    let started = Instant::now();
    let mut delay = policy.initial;
    let mut attempts: u32 = 0;
    for verb in WATCH_VERBS {
        loop {
            attempts = attempts.saturating_add(1);
            match review(verb).await {
                Ok(true) => break,
                Ok(false) => return Ok(false),
                Err(err) => {
                    let elapsed = started.elapsed();
                    if elapsed.saturating_add(delay) > policy.budget {
                        eprintln!(
                            "ERROR weebo-si-operator: could not ask whether {verb} {what} is \
                             allowed after {attempts} attempts over {elapsed:?} ({err}); giving up"
                        );
                        return Err(err);
                    }
                    eprintln!(
                        "WARN weebo-si-operator: could not ask whether {verb} {what} is allowed \
                         ({err}); retrying in {delay:?}"
                    );
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(policy.max_delay);
                }
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    const FAST: RetryPolicy = RetryPolicy {
        initial: Duration::from_millis(1),
        max_delay: Duration::from_millis(4),
        budget: Duration::from_millis(200),
    };

    /// A scripted review: each call pops the next answer and records which verb it was for.
    struct Script {
        answers: RefCell<VecDeque<Result<bool, String>>>,
        asked: RefCell<Vec<&'static str>>,
    }

    impl Script {
        fn new(answers: Vec<Result<bool, String>>) -> Self {
            Self {
                answers: RefCell::new(answers.into()),
                asked: RefCell::new(Vec::new()),
            }
        }

        fn call(&self, verb: &'static str) -> std::future::Ready<Result<bool, String>> {
            self.asked.borrow_mut().push(verb);
            let next = self
                .answers
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err("apiserver unreachable".to_string()));
            std::future::ready(next)
        }
    }

    #[tokio::test]
    async fn both_verbs_allowed_is_allowed() {
        let script = Script::new(vec![Ok(true), Ok(true)]);
        let result = decide(FAST, "x.y", |verb| script.call(verb)).await;
        assert_eq!(result, Ok(true));
        assert_eq!(*script.asked.borrow(), vec!["list", "watch"]);
    }

    #[tokio::test]
    async fn an_explicit_denial_is_not_allowed_and_stops_asking() {
        let script = Script::new(vec![Ok(false)]);
        let result = decide(FAST, "x.y", |verb| script.call(verb)).await;
        assert_eq!(result, Ok(false));
        assert_eq!(*script.asked.borrow(), vec!["list"]);
    }

    #[tokio::test]
    async fn a_transient_error_is_retried_not_read_as_a_denial() {
        // The regression: one blip used to disable the feature for the pod's lifetime.
        let script = Script::new(vec![
            Err("connection reset".to_string()),
            Ok(true),
            Err("503".to_string()),
            Err("503".to_string()),
            Ok(true),
        ]);
        let result = decide(FAST, "x.y", |verb| script.call(verb)).await;
        assert_eq!(result, Ok(true));
        assert_eq!(
            *script.asked.borrow(),
            vec!["list", "list", "watch", "watch", "watch"]
        );
    }

    #[tokio::test]
    async fn a_denial_after_a_retry_is_still_a_denial() {
        let script = Script::new(vec![Err("timeout".to_string()), Ok(true), Ok(false)]);
        let result = decide(FAST, "x.y", |verb| script.call(verb)).await;
        assert_eq!(result, Ok(false));
    }

    #[tokio::test]
    async fn an_apiserver_that_never_answers_is_an_error_once_the_budget_is_spent() {
        // Not `Ok(false)`: the caller must fail startup rather than run with the feature off.
        let script = Script::new(Vec::new());
        let started = std::time::Instant::now();
        let result = decide(FAST, "x.y", |verb| script.call(verb)).await;
        assert_eq!(result, Err("apiserver unreachable".to_string()));
        assert!(script.asked.borrow().len() > 1, "it must have retried");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the budget must bound the wait"
        );
    }

    #[test]
    fn the_default_policy_backs_off_exponentially_from_half_a_second_within_a_minute() {
        assert_eq!(DEFAULT_RETRY.initial, Duration::from_millis(500));
        assert!(DEFAULT_RETRY.max_delay >= DEFAULT_RETRY.initial);
        assert_eq!(DEFAULT_RETRY.budget, Duration::from_secs(60));
    }
}
