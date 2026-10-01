//! The end-to-end tier's harness: a kind cluster running real Eclipse Che, real DevWorkspace
//! Operator and this repo's own images, built by `scripts/e2e.sh`.
//!
//! Every other tier stops short of the platform. Unit tests prove the decisions, envtest proves
//! them against a bare apiserver, conformance proves the gateway against one ingress controller.
//! None of them starts a workspace, so none of them can say whether DevWorkspace Operator honours
//! the configuration `dwoc-pin` wrote, whether the pod Che actually builds passes `image-policy`,
//! or whether a baseline `NetworkPolicy` actually drops a packet. This tier can, and that is all
//! it is for — which is also why it runs nightly and not on every pull request.
//!
//! **Everything goes through `kubectl`**, and every failure message prints the command it ran, so
//! a red nightly can be replayed by pasting a line. The suites run one test at a time
//! (`--test-threads=1`): they share one cluster and one `WeeboSiConfig` singleton, and each test
//! states the whole configuration it needs rather than inheriting the last one's.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use serde_json::{Value, json};

/// The namespace the charts are installed into.
pub const OPERATOR_NAMESPACE: &str = "weebo-si-hardening";
/// The wildcard domain every rig host lives under.
pub const DOMAIN: &str = "127.0.0.1.nip.io";
/// The workspace image `scripts/e2e.sh build` produces.
pub const WORKSPACE_IMAGE: &str = "localhost/e2e-workspace:e2e";
/// The field manager every apply here uses, so a later apply of the singleton removes what an
/// earlier one set instead of merging with it.
const FIELD_MANAGER: &str = "weebo-e2e";

/// How long a workspace gets to reach `Running`: the first one on a fresh cluster pulls images.
pub const WORKSPACE_START: Duration = Duration::from_secs(600);
/// How long a controller-side effect gets to land.
pub const RECONCILE: Duration = Duration::from_secs(180);

/// The repository root — for the charts a suite installs itself. `E2E_REPO_ROOT` wins: CI runs a
/// test binary built in another job, where the compile-time path may not exist.
pub fn repo_root() -> String {
    std::env::var("E2E_REPO_ROOT")
        .unwrap_or_else(|_| format!("{}/../..", env!("CARGO_MANIFEST_DIR")))
}

/// The rig's certificate authority, which every Ingress and the identity provider chain to.
pub fn ca_file() -> String {
    std::env::var("E2E_CA_FILE").unwrap_or_else(|_| "/tmp/weebo-si-e2e/ca.crt".to_string())
}

// --- kubectl ----------------------------------------------------------------------------------------

/// Run `kubectl`, feeding `stdin` if given: `Ok(stdout)` on success, `Err` naming the command and
/// its stderr otherwise.
pub fn kubectl_with(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let mut child = Command::new("kubectl")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("kubectl {}: could not start: {err}", args.join(" ")))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())
            .map_err(|err| format!("kubectl {}: writing stdin: {err}", args.join(" ")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("kubectl {}: {err}", args.join(" ")))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "kubectl {} failed ({}): {}{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        ))
    }
}

/// [`kubectl_with`] without stdin.
pub fn kubectl(args: &[&str]) -> Result<String, String> {
    kubectl_with(args, None)
}

/// [`kubectl`], failing the test on error.
#[track_caller]
pub fn must(args: &[&str]) -> String {
    match kubectl(args) {
        Ok(out) => out,
        Err(err) => fail(&err),
    }
}

/// Fail the test with `message`. One function so every harness failure reads the same.
#[track_caller]
#[allow(clippy::panic, reason = "a harness failure is the test failing")]
pub fn fail(message: &str) -> ! {
    panic!("{message}")
}

/// Server-side apply `yaml`, returning the apiserver's refusal (an admission denial included)
/// rather than failing — the shape a test asserting a refusal needs.
pub fn try_apply(yaml: &str) -> Result<String, String> {
    kubectl_with(
        &[
            "apply",
            "--server-side",
            "--force-conflicts",
            &format!("--field-manager={FIELD_MANAGER}"),
            "-f",
            "-",
        ],
        Some(yaml),
    )
}

/// [`try_apply`], failing the test on error.
#[track_caller]
pub fn apply(yaml: &str) {
    if let Err(err) = try_apply(yaml) {
        fail(&format!("{err}\n--- manifest ---\n{yaml}"));
    }
}

/// `kubectl get <args> -o json`, or `None` when the object does not exist.
pub fn get(args: &[&str]) -> Option<Value> {
    let mut full = vec!["get"];
    full.extend_from_slice(args);
    full.extend_from_slice(&["-o", "json"]);
    match kubectl(&full) {
        Ok(out) => serde_json::from_str(&out).ok(),
        Err(err) if err.contains("NotFound") || err.contains("not found") => None,
        Err(err) => fail(&err),
    }
}

/// Delete without waiting; absent is fine. Used by every fixture's `Drop`.
pub fn delete(args: &[&str]) {
    let mut full = vec!["delete", "--ignore-not-found", "--wait=false"];
    full.extend_from_slice(args);
    let _ = kubectl(&full);
}

/// Poll `probe` every two seconds until it returns `Ok`, or fail with its last `Err` after
/// `timeout`. The last error is the whole diagnostic, so probes should make it say what they saw.
#[track_caller]
pub fn wait_until<T>(
    what: &str,
    timeout: Duration,
    mut probe: impl FnMut() -> Result<T, String>,
) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        match probe() {
            Ok(value) => return value,
            Err(last) if Instant::now() >= deadline => fail(&format!(
                "timed out after {timeout:?} waiting for {what}: {last}"
            )),
            Err(_) => std::thread::sleep(Duration::from_secs(2)),
        }
    }
}

/// Assert that `probe` keeps returning `Ok` for the whole of `window` — the shape of "nothing
/// happens", which a single check cannot prove against an asynchronous controller.
#[track_caller]
pub fn stays(what: &str, window: Duration, mut probe: impl FnMut() -> Result<(), String>) {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        if let Err(err) = probe() {
            fail(&format!(
                "expected {what} to hold for {window:?}, but: {err}"
            ));
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// A JSON pointer lookup rendered as a string, empty when absent — the comparison most
/// assertions here want.
pub fn text(value: &Value, pointer: &str) -> String {
    match value.pointer(pointer) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

// --- the singleton ----------------------------------------------------------------------------------

/// Replace `WeeboSiConfig/cluster`'s `spec.features` with `features`, and wait until every
/// webhook and controller replica has observed the new generation.
///
/// Waiting on the replicas' own `weebo_si_config_observed_generation` gauge rather than on the
/// object's status is the point: status is written by the controller leader, and a test whose
/// next step is an admission request needs to know the *webhook* has the new configuration.
#[track_caller]
pub fn set_features(features: Value) {
    let manifest = json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "cluster" },
        "spec": { "features": features },
    });
    apply(&manifest.to_string());
    let generation = wait_until("the singleton to exist", RECONCILE, || {
        get(&["weebosiconfig", "cluster"])
            .and_then(|config| {
                config
                    .pointer("/metadata/generation")
                    .and_then(Value::as_i64)
            })
            .ok_or_else(|| "no generation yet".to_string())
    });
    for component in ["webhook", "controller"] {
        wait_until(
            &format!("every {component} replica to observe generation {generation}"),
            RECONCILE,
            || {
                let pods = operator_pods(component);
                if pods.is_empty() {
                    return Err(format!("no {component} pods"));
                }
                for pod in pods {
                    let observed =
                        metric(&pod, "weebo_si_config_observed_generation", &[]).unwrap_or(-1.0);
                    #[allow(clippy::cast_precision_loss, reason = "generations are small")]
                    if observed < generation as f64 {
                        return Err(format!("{pod} still at {observed}"));
                    }
                }
                Ok(())
            },
        );
    }
}

/// The singleton's status, once the controller has reconciled the current generation.
#[track_caller]
pub fn config_status() -> Value {
    wait_until(
        "the controller to report the current generation",
        RECONCILE,
        || {
            let config = get(&["weebosiconfig", "cluster"]).ok_or("no singleton")?;
            let generation = config
                .pointer("/metadata/generation")
                .and_then(Value::as_i64);
            let observed = config
                .pointer("/status/observedGeneration")
                .and_then(Value::as_i64);
            if generation.is_some() && generation == observed {
                Ok(config.pointer("/status").cloned().unwrap_or(Value::Null))
            } else {
                Err(format!("generation {generation:?}, observed {observed:?}"))
            }
        },
    )
}

/// The status entry for one feature.
#[track_caller]
pub fn feature_status(name: &str) -> Value {
    let status = config_status();
    status
        .pointer("/features")
        .and_then(Value::as_array)
        .and_then(|features| {
            features
                .iter()
                .find(|feature| feature.get("name").and_then(Value::as_str) == Some(name))
                .cloned()
        })
        .unwrap_or_else(|| fail(&format!("no status entry for {name} in {status}")))
}

// --- metrics ----------------------------------------------------------------------------------------

/// The names of the operator's pods for one component, `webhook` or `controller`.
pub fn operator_pods(component: &str) -> Vec<String> {
    get(&[
        "pods",
        "-n",
        OPERATOR_NAMESPACE,
        "-l",
        &format!(
            "app.kubernetes.io/name=weebo-si-operator,app.kubernetes.io/component={component}"
        ),
        "--field-selector=status.phase=Running",
    ])
    .and_then(|list| list.get("items").and_then(Value::as_array).cloned())
    .unwrap_or_default()
    .iter()
    .map(|pod| text(pod, "/metadata/name"))
    .collect()
}

/// One pod's `/metrics`, through the apiserver's pod proxy — no port-forward to leak.
pub fn scrape(pod: &str) -> Result<String, String> {
    kubectl(&[
        "get",
        "--raw",
        &format!("/api/v1/namespaces/{OPERATOR_NAMESPACE}/pods/http:{pod}:8081/proxy/metrics"),
    ])
}

/// The value of the sample `name{labels}` on `pod`, where every `(key, value)` in `labels` is
/// among the sample's labels. `None` when no sample matches.
pub fn metric(pod: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    let body = scrape(pod).ok()?;
    sample(&body, name, labels)
}

/// The sum of `name{labels}` across every replica of `component` — counters are per replica, and
/// which replica served a request is not something a test gets to choose.
pub fn metric_sum(component: &str, name: &str, labels: &[(&str, &str)]) -> f64 {
    operator_pods(component)
        .iter()
        .filter_map(|pod| metric(pod, name, labels))
        .sum()
}

/// The sum of `name{labels}` across every endpoint-gateway replica, read from each pod's metrics
/// port (the chart's `metrics.port`, 9090) through the apiserver's pod proxy.
pub fn gateway_metric_sum(name: &str, labels: &[(&str, &str)]) -> f64 {
    get(&[
        "pods",
        "-n",
        OPERATOR_NAMESPACE,
        "-l",
        "app.kubernetes.io/name=endpoint-gateway",
        "--field-selector=status.phase=Running",
    ])
    .and_then(|list| list.get("items").and_then(Value::as_array).cloned())
    .unwrap_or_default()
    .iter()
    .map(|pod| text(pod, "/metadata/name"))
    .filter_map(|pod| {
        kubectl(&[
            "get",
            "--raw",
            &format!("/api/v1/namespaces/{OPERATOR_NAMESPACE}/pods/http:{pod}:9090/proxy/metrics"),
        ])
        .ok()
        .and_then(|body| sample(&body, name, labels))
    })
    .sum()
}

/// Parse one sample out of a Prometheus text exposition.
pub fn sample(body: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (series, value) = line.rsplit_once(' ')?;
            let (metric, rest) = match series.split_once('{') {
                Some((metric, rest)) => (metric, rest.trim_end_matches('}')),
                None => (series, ""),
            };
            if metric != name {
                return None;
            }
            let matches = labels.iter().all(|(key, want)| {
                rest.split(',')
                    .any(|pair| pair == format!("{key}=\"{want}\""))
            });
            matches.then(|| value.parse::<f64>().ok()).flatten()
        })
        .reduce(|a, b| a + b)
}

// --- fixtures ---------------------------------------------------------------------------------------

/// Deletes what it names when dropped: `args` are what `kubectl delete` takes after its flags,
/// e.g. `["configmap", "-n", "ns", "name"]`.
pub struct Cleanup(Vec<String>);

impl Cleanup {
    /// Delete the object `args` names when this is dropped.
    pub fn new(args: &[&str]) -> Self {
        Self(args.iter().map(|arg| (*arg).to_string()).collect())
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let args: Vec<&str> = self.0.iter().map(String::as_str).collect();
        delete(&args);
    }
}

/// Apply a `WeeboSiTeam` and delete it when dropped.
#[track_caller]
pub fn team(name: &str, spec: Value) -> Cleanup {
    apply(
        &json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiTeam",
            "metadata": { "name": name },
            "spec": spec,
        })
        .to_string(),
    );
    Cleanup::new(&["weebositeam", name])
}

/// A user namespace, labelled the way Che labels a pre-provisioned one and opted into every
/// opt-in webhook, deleted when dropped.
pub struct Namespace {
    /// The namespace's name.
    pub name: String,
}

impl Namespace {
    /// Create `<user>-<suffix>` for `user`, in `team` if given.
    #[track_caller]
    pub fn workspace(user: &str, suffix: &str, team: Option<&str>) -> Self {
        let name = format!("{user}-{suffix}");
        let mut labels = json!({
            "app.kubernetes.io/part-of": "che.eclipse.org",
            "app.kubernetes.io/component": "workspaces-namespace",
            "hardening.weebo.io/workspace-namespace": "",
        });
        if let Some(team) = team {
            labels["weebo.io/team"] = json!(team);
        }
        apply(
            &json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": name,
                    "labels": labels,
                    "annotations": { "che.eclipse.org/username": user },
                },
            })
            .to_string(),
        );
        Self { name }
    }

    /// Set one annotation on the namespace.
    #[track_caller]
    pub fn annotate(&self, key: &str, value: &str) {
        must(&[
            "annotate",
            "--overwrite",
            "namespace",
            &self.name,
            &format!("{key}={value}"),
        ]);
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        delete(&["namespace", &self.name]);
    }
}

/// One DevWorkspace, as the Che dashboard would create it.
#[derive(Debug)]
pub struct Workspace {
    /// Its namespace.
    pub namespace: String,
    /// Its name.
    pub name: String,
}

/// What a test may vary about a workspace; everything else is the dashboard's shape.
pub struct WorkspaceSpec<'a> {
    /// The container image of the single `tools` component.
    pub image: &'a str,
    /// Extra `spec.template.attributes`.
    pub attributes: Value,
    /// Endpoints on the `tools` component.
    pub endpoints: &'a [Endpoint<'a>],
}

/// One devfile endpoint. `annotation` (singular — the devfile's spelling, see the endpoint
/// gateway's ground-truth row 3a) is copied by DevWorkspace Operator onto the routing object.
pub struct Endpoint<'a> {
    /// The endpoint's name.
    pub name: &'a str,
    /// The container port. serve.py listens on 8080.
    pub port: u16,
    /// `public`, `internal` or `none`.
    pub exposure: &'a str,
    /// The devfile `annotation` map.
    pub annotation: Value,
}

impl Default for WorkspaceSpec<'_> {
    fn default() -> Self {
        Self {
            image: WORKSPACE_IMAGE,
            attributes: json!({}),
            endpoints: &[],
        }
    }
}

impl Workspace {
    /// The manifest the dashboard would write: `routingClass: che`, ephemeral storage, and the
    /// dashboard's own `controller.devfile.io/devworkspace-config` attribute pointing at Che's
    /// DevWorkspaceOperatorConfig — which is what `dwoc-pin` exists to replace.
    pub fn manifest(namespace: &str, name: &str, spec: &WorkspaceSpec<'_>) -> Value {
        let mut attributes = json!({
            "controller.devfile.io/storage-type": "ephemeral",
            "controller.devfile.io/devworkspace-config": {
                "name": "devworkspace-config",
                "namespace": "eclipse-che",
            },
        });
        if let (Some(base), Some(extra)) = (attributes.as_object_mut(), spec.attributes.as_object())
        {
            for (key, value) in extra {
                base.insert(key.clone(), value.clone());
            }
        }
        let endpoints: Vec<Value> = spec
            .endpoints
            .iter()
            .map(|endpoint| {
                json!({
                    "name": endpoint.name,
                    "targetPort": endpoint.port,
                    "exposure": endpoint.exposure,
                    "protocol": "http",
                    "annotation": endpoint.annotation,
                })
            })
            .collect();
        json!({
            "apiVersion": "workspace.devfile.io/v1alpha2",
            "kind": "DevWorkspace",
            "metadata": { "name": name, "namespace": namespace },
            "spec": {
                "started": true,
                "routingClass": "che",
                "template": {
                    "attributes": attributes,
                    "components": [{
                        "name": "tools",
                        "container": {
                            "image": spec.image,
                            "memoryLimit": "128Mi",
                            "mountSources": false,
                            "endpoints": endpoints,
                        },
                    }],
                },
            },
        })
    }

    /// Create it, returning the apiserver's answer — an admission refusal included.
    pub fn try_create(
        namespace: &str,
        name: &str,
        spec: &WorkspaceSpec<'_>,
    ) -> Result<Self, String> {
        try_apply(&Self::manifest(namespace, name, spec).to_string())?;
        Ok(Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
        })
    }

    /// Create it, failing the test on a refusal.
    #[track_caller]
    pub fn create(namespace: &str, name: &str, spec: &WorkspaceSpec<'_>) -> Self {
        Self::try_create(namespace, name, spec).unwrap_or_else(|err| fail(&err))
    }

    /// The object as the apiserver has it now.
    #[track_caller]
    pub fn object(&self) -> Value {
        get(&["devworkspace", "-n", &self.namespace, &self.name]).unwrap_or_else(|| {
            fail(&format!(
                "devworkspace {}/{} is gone",
                self.namespace, self.name
            ))
        })
    }

    /// Wait for `status.phase: Running`, failing early — with DevWorkspace Operator's own
    /// message — on `Failed`.
    #[track_caller]
    pub fn wait_running(&self) -> &Self {
        wait_until(
            &format!("devworkspace {}/{} to run", self.namespace, self.name),
            WORKSPACE_START,
            || {
                let object = self.object();
                match text(&object, "/status/phase").as_str() {
                    "Running" => Ok(()),
                    "Failed" => fail(&format!(
                        "devworkspace {}/{} failed: {}",
                        self.namespace,
                        self.name,
                        text(&object, "/status/message")
                    )),
                    phase => Err(format!(
                        "phase {phase:?}: {}",
                        text(&object, "/status/message")
                    )),
                }
            },
        );
        self
    }

    /// DevWorkspace Operator's id for this workspace, which labels its pod and names the
    /// operator's per-workspace objects.
    #[track_caller]
    pub fn id(&self) -> String {
        wait_until("a devworkspace id", RECONCILE, || {
            let id = text(&self.object(), "/status/devworkspaceId");
            if id.is_empty() {
                Err("not assigned yet".into())
            } else {
                Ok(id)
            }
        })
    }

    /// The running pod.
    #[track_caller]
    pub fn pod(&self) -> String {
        wait_until("the workspace pod", RECONCILE, || {
            let list = get(&[
                "pods",
                "-n",
                &self.namespace,
                "-l",
                &format!("controller.devfile.io/devworkspace_name={}", self.name),
                "--field-selector=status.phase=Running",
            ])
            .ok_or("no pod list")?;
            list.pointer("/items/0/metadata/name")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| "no running pod yet".to_string())
        })
    }

    /// Run `command` in the `tools` container.
    pub fn exec(&self, command: &[&str]) -> Result<String, String> {
        let pod = self.pod();
        let mut args = vec!["exec", "-n", &self.namespace, &pod, "-c", "tools", "--"];
        args.extend_from_slice(command);
        kubectl(&args)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        delete(&["devworkspace", "-n", &self.namespace, &self.name]);
    }
}

// --- HTTPS through the real ingress controller ------------------------------------------------------

/// `kubectl port-forward` to the ingress controller, and a client that sends every rig hostname
/// through it and trusts the rig's CA — so a request here crosses exactly the path a browser's
/// would: ingress-nginx, its `auth-url` subrequest, the gateway, the workspace.
pub struct Ingress {
    forward: Child,
    /// The local port the forward listens on.
    pub port: u16,
    /// The client. It never follows redirects: where a redirect points is usually the assertion.
    pub client: reqwest::blocking::Client,
}

struct AllToLoopback(u16);

impl reqwest::dns::Resolve for AllToLoopback {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.0));
        Box::pin(async move {
            let addrs: reqwest::dns::Addrs = Box::new(std::iter::once(addr));
            Ok(addrs)
        })
    }
}

impl Ingress {
    /// Open the forward and wait until it answers.
    #[track_caller]
    pub fn open() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|addr| addr.port())
            .unwrap_or_else(|err| fail(&format!("no free local port: {err}")));
        let forward = Command::new("kubectl")
            .args([
                "port-forward",
                "-n",
                "ingress-nginx",
                "svc/ingress-nginx-controller",
                &format!("{port}:443"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|err| fail(&format!("kubectl port-forward: {err}")));
        let pem = std::fs::read(ca_file())
            .unwrap_or_else(|err| fail(&format!("the rig CA at {}: {err}", ca_file())));
        let ca = reqwest::Certificate::from_pem(&pem)
            .unwrap_or_else(|err| fail(&format!("the rig CA: {err}")));
        let client = reqwest::blocking::Client::builder()
            .add_root_certificate(ca)
            .dns_resolver(Arc::new(AllToLoopback(port)))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|err| fail(&format!("building the client: {err}")));
        let ingress = Self {
            forward,
            port,
            client,
        };
        wait_until("the ingress port-forward", Duration::from_secs(60), || {
            ingress
                .client
                .get(ingress.url(&format!("sso.{DOMAIN}"), "/realms/che"))
                .send()
                .map(|_| ())
                .map_err(|err| err.to_string())
        });
        ingress
    }

    /// `https://<host>:<forwarded port><path>`.
    pub fn url(&self, host: &str, path: &str) -> String {
        format!("https://{host}:{}{path}", self.port)
    }

    /// A password-grant access token for `user` (password = username) from the rig's Keycloak,
    /// minted for the `endpoint-gateway` client — so its `aud` names the gateway, which is what
    /// the gateway's bearer branch requires.
    #[track_caller]
    pub fn token(&self, user: &str) -> String {
        let response = self
            .client
            .post(self.url(
                &format!("sso.{DOMAIN}"),
                "/realms/che/protocol/openid-connect/token",
            ))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "endpoint-gateway"),
                ("client_secret", "endpoint-gateway-secret"),
                ("username", user),
                ("password", user),
                ("scope", "openid"),
            ])
            .send()
            .unwrap_or_else(|err| fail(&format!("token for {user}: {err}")));
        let body: Value = response
            .json()
            .unwrap_or_else(|err| fail(&format!("token for {user}: {err}")));
        body.get("access_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| fail(&format!("token for {user}: {body}")))
    }
}

impl Drop for Ingress {
    fn drop(&mut self) {
        let _ = self.forward.kill();
        let _ = self.forward.wait();
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

    #[test]
    fn a_sample_is_found_by_name_and_a_subset_of_its_labels() {
        let body = "# HELP x\n\
                    weebo_si_dwoc_pin_total{result=\"added\",team=\"_none\"} 2\n\
                    weebo_si_dwoc_pin_total{result=\"replaced\",team=\"gpu\"} 3\n\
                    weebo_si_config_observed_generation 7\n";
        assert_eq!(
            sample(body, "weebo_si_config_observed_generation", &[]),
            Some(7.0)
        );
        assert_eq!(
            sample(body, "weebo_si_dwoc_pin_total", &[("result", "replaced")]),
            Some(3.0)
        );
        assert_eq!(sample(body, "weebo_si_dwoc_pin_total", &[]), Some(5.0));
        assert_eq!(
            sample(body, "weebo_si_dwoc_pin_total", &[("team", "nobody")]),
            None
        );
    }

    #[test]
    fn a_dashboard_shaped_workspace_carries_the_dashboards_config_attribute() {
        let manifest = Workspace::manifest("ns", "ws", &WorkspaceSpec::default());
        assert_eq!(
            text(
                &manifest,
                "/spec/template/attributes/controller.devfile.io~1devworkspace-config/name"
            ),
            "devworkspace-config"
        );
        assert_eq!(text(&manifest, "/spec/routingClass"), "che");
    }
}
