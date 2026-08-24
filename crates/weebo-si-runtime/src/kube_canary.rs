//! `CanaryProbe` implementation: two pods and a deny policy in the operator's own namespace.
//!
//! Answers the one question `kubectl get networkpolicy` cannot — RFC 0004's *Security
//! considerations*, "The CNI not enforcing... the failure that makes everything above decorative
//! while every object looks correct."
//!
//! **The bounds are the whole design here, because this is the only thing in the brick that
//! creates a workload.** Per the RFC: "The canary is the only pod we create, in our own
//! namespace, from a pinned image, with no service account token mounted." All four are
//! properties of [`KubeCanary::pod`] below and none of them is configurable:
//! [`KubeCanary::new`] takes the namespace from the process's own downward API, the image is one
//! value with no templating around it, and `automountServiceAccountToken: false` is written
//! unconditionally.
//!
//! The verdict logic itself is not here — it is pure, and lives in
//! `weebo_si_network_profiles::canary`. This module observes; it does not decide.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Client;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use serde_json::{Value, json};
use weebo_si_chassis::DomainError;
use weebo_si_crd::CANARY_LABEL;
use weebo_si_network_profiles::{CanaryProbe, Reachability};

/// The pod that listens. Public so a test — and an admin reading `kubectl get pods` — can name it.
pub const SERVER_POD: &str = "weebo-si-canary-server";
/// The pod that tries to reach it.
pub const CLIENT_POD: &str = "weebo-si-canary-client";
/// The policy that should stop it.
pub const DENY_POLICY: &str = "weebo-si-canary-deny";
/// The port the server listens on and the client connects to. Above 1024 so nothing here needs a
/// capability the pod security context drops.
const PROBE_PORT: u16 = 8080;

/// The default probe image. `agnhost` is Kubernetes' own end-to-end network test image: it
/// carries both halves of this probe (`netexec` listens, `connect` dials and exits non-zero when
/// it cannot), it is on `registry.k8s.io` rather than a rate-limited public registry, and it is
/// already mirrored in most air-gapped clusters. Pinned to a tag, never `latest` — a canary that
/// silently changed what it measures is worse than no canary.
pub const DEFAULT_CANARY_IMAGE: &str = "registry.k8s.io/e2e-test-images/agnhost:2.53";

/// How long to wait for the server pod to schedule, pull and report an IP. Generous: on a
/// cluster that has never pulled the image, this is an image pull.
const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(180);
/// How long to wait for the client pod to reach a terminal phase. Its own dial timeout is
/// [`CONNECT_TIMEOUT`]; the rest is scheduling.
const CLIENT_TERMINAL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the client waits for the connection before giving up — long enough that a slow but
/// permitted flow is not read as a block, short enough that a blocked leg does not dominate the
/// probe's runtime.
const CONNECT_TIMEOUT: &str = "5s";
/// How long to let the CNI program a freshly written policy before dialing through it. Without
/// this, a fast probe on a slow CNI reads "not yet programmed" as "not enforcing" — the exact
/// false negative this whole feature exists to avoid producing.
const POLICY_SETTLE: Duration = Duration::from_secs(5);
/// Poll interval for every wait loop above.
const POLL: Duration = Duration::from_millis(500);

/// The JSON one canary pod is built from — pure, so the properties RFC 0004 requires of it are
/// assertable without a cluster.
///
/// A free function rather than a method for exactly that reason: nothing here needs a
/// `kube::Client`, and a test that had to hold one could not run in this crate's unit tier.
fn canary_pod_spec(
    name: &str,
    role: &str,
    namespace: &str,
    image: &str,
    args: Vec<String>,
) -> Value {
    json!({
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {CANARY_LABEL: role},
        },
        "spec": {
            "restartPolicy": "Never",
            // RFC 0004: "with no service account token mounted." The canary talks to one
            // TCP port and never to the apiserver; a token here would be a credential in a
            // pod whose whole purpose is to be reached from elsewhere.
            "automountServiceAccountToken": false,
            "securityContext": {
                "runAsNonRoot": true,
                "runAsUser": 65532,
                "runAsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "canary",
                "image": image,
                "args": args,
                "securityContext": {
                    "allowPrivilegeEscalation": false,
                    "readOnlyRootFilesystem": true,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "requests": {"cpu": "10m", "memory": "16Mi"},
                    "limits": {"memory": "64Mi"},
                },
            }],
        },
    })
}

/// The deny-all-ingress policy the restricted leg dials through — pure, same reasoning as
/// [`canary_pod_spec`]. This object is the entire experiment: if the server is still reachable
/// with it in place, the cluster is not evaluating NetworkPolicy at all.
fn canary_deny_policy_spec(namespace: &str) -> Value {
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": DENY_POLICY,
            "namespace": namespace,
            "labels": {CANARY_LABEL: "deny"},
        },
        "spec": {
            // Selects the server pod and nothing else — the blast radius of this object is
            // one pod this operator created, in this operator's own namespace.
            "podSelector": {"matchLabels": {CANARY_LABEL: "server"}},
            "policyTypes": ["Ingress"],
            // No `ingress` key at all: nothing is permitted in. Under NetworkPolicy's union
            // semantics that is the strongest statement a single object can make, which is
            // what makes a still-reachable server proof the union is not being evaluated.
        },
    })
}

/// The arguments the listener half runs with.
fn server_args() -> Vec<String> {
    vec![
        "netexec".to_string(),
        format!("--http-port={PROBE_PORT}"),
        // netexec opens a UDP listener too by default, which this probe never uses and
        // which is one more thing that can fail to bind.
        "--udp-port=-1".to_string(),
    ]
}

/// The arguments the client half runs with, against `ip`.
fn client_args(ip: &str) -> Vec<String> {
    vec![
        "connect".to_string(),
        format!("--timeout={CONNECT_TIMEOUT}"),
        format!("{ip}:{PROBE_PORT}"),
    ]
}

/// Runs the enforcement probe against a real cluster.
pub struct KubeCanary {
    client: Client,
    namespace: String,
    image: String,
}

impl KubeCanary {
    /// Build a canary that creates its pods in `namespace` — the operator's own, and the only
    /// one the namespaced `Role` backing this permits.
    pub fn new(client: Client, namespace: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            client,
            namespace: namespace.into(),
            image: image.into(),
        }
    }

    fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn policies(&self) -> Api<NetworkPolicy> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    /// One canary pod. Every hardening property of this probe is in this function.
    ///
    /// **Fallible on purpose.** An earlier revision ended this with `unwrap_or_default()`, which
    /// turns a malformed spec into an empty `Pod` — no name, no container — and hands the
    /// apiserver a rejection that describes the symptom rather than the cause. A probe whose
    /// failure mode is a confusing error message is a probe nobody trusts the *verdict* of, and
    /// this one exists to be trusted about bad news specifically.
    fn pod(&self, name: &str, role: &str, args: Vec<String>) -> Result<Pod, DomainError> {
        serde_json::from_value(canary_pod_spec(
            name,
            role,
            &self.namespace,
            &self.image,
            args,
        ))
        .map_err(|err| {
            DomainError::PortFailed(format!("could not build the canary pod {name}: {err}"))
        })
    }

    /// Create the server pod if it is not already there, and return the IP it ended up with.
    async fn server_ip(&self) -> Result<Option<String>, DomainError> {
        let pods = self.pods();
        let desired = self.pod(SERVER_POD, "server", server_args())?;
        match pods.create(&PostParams::default(), &desired).await {
            Ok(_) => {}
            // Left over from a probe that was interrupted before its cleanup ran. Reused rather
            // than recreated: it is the same pod spec, and recreating costs another image pull.
            Err(kube::Error::Api(err)) if err.code == 409 => {}
            Err(err) => return Err(DomainError::PortFailed(err.to_string())),
        }

        let deadline = tokio::time::Instant::now() + SERVER_READY_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            let pod = pods
                .get_opt(SERVER_POD)
                .await
                .map_err(|err| DomainError::PortFailed(err.to_string()))?;
            if let Some(status) = pod.and_then(|pod| pod.status) {
                let running = status.phase.as_deref() == Some("Running");
                if running && let Some(ip) = status.pod_ip {
                    return Ok(Some(ip));
                }
                if matches!(status.phase.as_deref(), Some("Failed") | Some("Succeeded")) {
                    // The listener exited. Nothing to dial; the caller reports Inconclusive.
                    return Ok(None);
                }
            }
            tokio::time::sleep(POLL).await;
        }
        Ok(None)
    }

    /// Put the deny policy in place, or take it away. Server-side apply so a leftover policy
    /// from an interrupted run converges rather than conflicting.
    async fn set_deny(&self, denied: bool) -> Result<(), DomainError> {
        let policies = self.policies();
        if !denied {
            return match policies.delete(DENY_POLICY, &DeleteParams::default()).await {
                Ok(_) => Ok(()),
                Err(kube::Error::Api(err)) if err.code == 404 => Ok(()),
                Err(err) => Err(DomainError::PortFailed(err.to_string())),
            };
        }

        let policy = canary_deny_policy_spec(&self.namespace);
        policies
            .patch(
                DENY_POLICY,
                &PatchParams::apply("weebo-si-operator"),
                &Patch::Apply(policy),
            )
            .await
            .map_err(|err| DomainError::PortFailed(err.to_string()))?;
        tokio::time::sleep(POLICY_SETTLE).await;
        Ok(())
    }

    /// Delete a pod and wait until the apiserver stops reporting it.
    async fn remove_pod(&self, name: &str) -> Result<(), DomainError> {
        let pods = self.pods();
        match pods
            .delete(name, &DeleteParams::default().grace_period(0))
            .await
        {
            Ok(_) => {}
            Err(kube::Error::Api(err)) if err.code == 404 => return Ok(()),
            Err(err) => return Err(DomainError::PortFailed(err.to_string())),
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while tokio::time::Instant::now() < deadline {
            let gone = pods
                .get_opt(name)
                .await
                .map_err(|err| DomainError::PortFailed(err.to_string()))?
                .is_none();
            if gone {
                return Ok(());
            }
            tokio::time::sleep(POLL).await;
        }
        Ok(())
    }

    /// Dial `ip` from a fresh client pod and read the answer off its terminal phase.
    ///
    /// The phase *is* the result — no `exec`, no log scraping, no second connection from the
    /// operator to the pod. `agnhost connect` exits `0` when it reached the target and non-zero
    /// when it was refused or timed out, so `Succeeded`/`Failed` map onto the two answers
    /// directly and the operator needs no permission beyond the `get` it already has.
    async fn dial(&self, ip: &str) -> Result<Reachability, DomainError> {
        self.remove_pod(CLIENT_POD).await?;
        let pods = self.pods();
        let client_pod = self.pod(CLIENT_POD, "client", client_args(ip))?;
        pods.create(&PostParams::default(), &client_pod)
            .await
            .map_err(|err| DomainError::PortFailed(err.to_string()))?;

        let deadline = tokio::time::Instant::now() + CLIENT_TERMINAL_TIMEOUT;
        let mut observed = Reachability::Inconclusive;
        while tokio::time::Instant::now() < deadline {
            let phase = pods
                .get_opt(CLIENT_POD)
                .await
                .map_err(|err| DomainError::PortFailed(err.to_string()))?
                .and_then(|pod| pod.status)
                .and_then(|status| status.phase);
            match phase.as_deref() {
                Some("Succeeded") => {
                    observed = Reachability::Reached;
                    break;
                }
                Some("Failed") => {
                    observed = Reachability::Blocked;
                    break;
                }
                _ => tokio::time::sleep(POLL).await,
            }
        }
        self.remove_pod(CLIENT_POD).await?;
        Ok(observed)
    }

    async fn tear_down(&self) -> Result<(), DomainError> {
        // Order matters: the pods first, then the policy. The reverse would leave a window where
        // the server pod is reachable with the deny policy already gone, which is harmless here
        // but reads as "the probe opened something up" to anyone watching the namespace.
        self.remove_pod(CLIENT_POD).await?;
        self.remove_pod(SERVER_POD).await?;
        self.set_deny(false).await
    }
}

impl CanaryProbe for KubeCanary {
    fn reachability(
        &self,
        restricted: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Reachability, DomainError>> + Send + '_>> {
        Box::pin(async move {
            let Some(ip) = self.server_ip().await? else {
                return Ok(Reachability::Inconclusive);
            };
            self.set_deny(restricted).await?;
            self.dial(&ip).await
        })
    }

    /// Delete everything this probe created — both pods and the deny policy. Called after every
    /// full run, by the `canary` subcommand and the controller's periodic loop alike, including
    /// after a run that errored: the probe is the only thing in this brick that creates a
    /// workload, and leaving a stale deny policy behind is leaving a namespace in a state nobody
    /// remembers asking for.
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + '_>> {
        Box::pin(self.tear_down())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    const NS: &str = "weebo-si-hardening";

    fn build(name: &str, role: &str, args: Vec<String>) -> Pod {
        serde_json::from_value(canary_pod_spec(name, role, NS, DEFAULT_CANARY_IMAGE, args))
            .expect("the canary pod spec must deserialize into a real Pod")
    }

    /// The regression this module's biggest latent bug deserved: `pod()` used to end in
    /// `unwrap_or_default()`, so a spec that stopped deserializing became an empty `Pod` and the
    /// apiserver reported a missing name instead of the real cause. This asserts the spec is
    /// well-formed *and* that a well-formed one is not the default.
    #[test]
    fn the_pod_spec_deserializes_into_a_real_pod_not_a_default_one() {
        let pod = build(SERVER_POD, "server", server_args());
        assert_ne!(pod, Pod::default());
        assert_eq!(pod.metadata.name.as_deref(), Some(SERVER_POD));
        assert_eq!(pod.metadata.namespace.as_deref(), Some(NS));
    }

    /// RFC 0004's *Security considerations*, verbatim: "The canary is the only pod we create, in
    /// our own namespace, from a pinned image, **with no service account token mounted**." That
    /// last clause is the one a refactor could silently drop, so it gets its own assertion.
    #[test]
    fn no_service_account_token_is_ever_mounted() {
        for (name, role, args) in [
            (SERVER_POD, "server", server_args()),
            (CLIENT_POD, "client", client_args("10.0.0.1")),
        ] {
            let pod = build(name, role, args);
            assert_eq!(
                pod.spec
                    .as_ref()
                    .expect("spec")
                    .automount_service_account_token,
                Some(false),
                "{name} must not mount a service account token"
            );
        }
    }

    #[test]
    fn the_probe_pods_never_restart() {
        // `Never` is load-bearing, not hygiene: the verdict is read off the pod's *terminal
        // phase*, and a pod that restarts never reaches one — every leg would time out into
        // `Inconclusive` and the canary would report `unknown` forever.
        let pod = build(CLIENT_POD, "client", client_args("10.0.0.1"));
        assert_eq!(
            pod.spec.as_ref().expect("spec").restart_policy.as_deref(),
            Some("Never")
        );
    }

    #[test]
    fn the_pod_runs_unprivileged_and_non_root() {
        let pod = build(SERVER_POD, "server", server_args());
        let spec = pod.spec.as_ref().expect("spec");
        let security = spec.security_context.as_ref().expect("pod securityContext");
        assert_eq!(security.run_as_non_root, Some(true));
        assert_eq!(security.run_as_user, Some(65532));

        let container = spec.containers.first().expect("one container");
        let container_security = container
            .security_context
            .as_ref()
            .expect("container securityContext");
        assert_eq!(container_security.allow_privilege_escalation, Some(false));
        assert_eq!(container_security.read_only_root_filesystem, Some(true));
        assert_eq!(
            container_security
                .capabilities
                .as_ref()
                .and_then(|caps| caps.drop.as_ref()),
            Some(&vec!["ALL".to_string()])
        );
    }

    #[test]
    fn the_image_is_whatever_the_caller_pinned_not_a_hardcoded_one() {
        // The air-gapped-mirror path: `--canary-image` / `values.yaml` has to reach the pod.
        let spec = canary_pod_spec(
            SERVER_POD,
            "server",
            NS,
            "mirror.internal/agnhost:2.53",
            server_args(),
        );
        let pod: Pod = serde_json::from_value(spec).expect("deserializes");
        assert_eq!(
            pod.spec
                .as_ref()
                .expect("spec")
                .containers
                .first()
                .expect("one container")
                .image
                .as_deref(),
            Some("mirror.internal/agnhost:2.53")
        );
    }

    #[test]
    fn the_default_image_is_pinned_to_a_tag_never_latest() {
        // A canary that silently changed what it measures is worse than no canary.
        assert!(
            DEFAULT_CANARY_IMAGE.contains(':') && !DEFAULT_CANARY_IMAGE.ends_with(":latest"),
            "the default probe image must be pinned: {DEFAULT_CANARY_IMAGE}"
        );
    }

    #[test]
    fn the_two_halves_are_labelled_so_the_deny_policy_can_select_only_the_server() {
        let server = build(SERVER_POD, "server", server_args());
        let client = build(CLIENT_POD, "client", client_args("10.0.0.1"));
        let label_of = |pod: &Pod| {
            pod.metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(CANARY_LABEL))
                .cloned()
        };
        assert_eq!(label_of(&server).as_deref(), Some("server"));
        assert_eq!(label_of(&client).as_deref(), Some("client"));
    }

    #[test]
    fn the_client_dials_the_address_it_was_given_on_the_probe_port() {
        let pod = build(CLIENT_POD, "client", client_args("10.42.0.7"));
        let args = pod
            .spec
            .as_ref()
            .expect("spec")
            .containers
            .first()
            .expect("one container")
            .args
            .clone()
            .expect("args");
        assert_eq!(args[0], "connect");
        assert!(
            args.iter().any(|arg| arg == "10.42.0.7:8080"),
            "the client must dial the server's IP on the probe port: {args:?}"
        );
        assert!(
            args.iter().any(|arg| arg.starts_with("--timeout=")),
            "without a dial timeout a blocked leg hangs instead of failing: {args:?}"
        );
    }

    #[test]
    fn the_deny_policy_permits_nothing_in_and_selects_only_the_server() {
        let policy: NetworkPolicy = serde_json::from_value(canary_deny_policy_spec(NS))
            .expect("the deny policy must deserialize into a real NetworkPolicy");
        let spec = policy.spec.as_ref().expect("spec");
        assert_eq!(spec.policy_types, Some(vec!["Ingress".to_string()]));
        assert!(
            spec.ingress.is_none() || spec.ingress.as_ref().is_some_and(|rules| rules.is_empty()),
            "an ingress rule here would permit exactly the flow the experiment needs blocked"
        );
        assert_eq!(
            spec.pod_selector
                .as_ref()
                .and_then(|selector| selector.match_labels.as_ref())
                .and_then(|labels| labels.get(CANARY_LABEL)),
            Some(&"server".to_string()),
            "the deny policy must select the canary server and nothing else — its blast radius \
             is the whole reason this is safe to run in the operator's own namespace"
        );
    }

    #[test]
    fn the_deny_policy_never_carries_the_ownership_label() {
        // The reconcile diff keys off `hardening.weebo.io/managed-by`. If the canary's own
        // policy carried it, `managed_in` would report it as a stray managed object and a
        // reconcile pass would produce a `Delete` for it mid-probe.
        let policy: NetworkPolicy =
            serde_json::from_value(canary_deny_policy_spec(NS)).expect("deserializes");
        let labels = policy.metadata.labels.expect("labels");
        assert!(!labels.contains_key(weebo_si_crd::MANAGED_BY_LABEL));
        assert_eq!(labels.get(CANARY_LABEL), Some(&"deny".to_string()));
    }

    #[test]
    fn every_object_this_probe_creates_lands_in_the_namespace_it_was_told() {
        // The `Role`, not `ClusterRole`, grant only covers the operator's own namespace — RFC
        // 0004: "it must be impossible for it to create one anywhere but at home."
        let namespace = "somewhere-else";
        let pod: Pod = serde_json::from_value(canary_pod_spec(
            SERVER_POD,
            "server",
            namespace,
            "img:1",
            server_args(),
        ))
        .expect("deserializes");
        let policy: NetworkPolicy =
            serde_json::from_value(canary_deny_policy_spec(namespace)).expect("deserializes");
        assert_eq!(pod.metadata.namespace.as_deref(), Some(namespace));
        assert_eq!(policy.metadata.namespace.as_deref(), Some(namespace));
    }
}
