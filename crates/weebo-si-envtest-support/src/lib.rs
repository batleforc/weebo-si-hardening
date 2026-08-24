//! A real, ephemeral Kubernetes apiserver for tests.
//!
//! Spawns etcd and kube-apiserver as child processes, hands out a `kube::Client` pointed at
//! them, and tears everything down on drop. This is the only way to check what a mock cannot
//! fake: that `WeeboSiConfig` is actually accepted by an apiserver, that the controller's status
//! writes actually land, and — for `weebo-si-webhook`'s suite — that a real
//! `MutatingWebhookConfiguration` actually calls back into a locally running webhook.
//!
//! Binaries come from `KUBEBUILDER_ASSETS` (see `task envtest:setup`). Ported from
//! `batleforc/proxyauthk8s`'s `envtest_support` harness, adapted for this repo's own dependency
//! set (`tempfile` in place of a hand-rolled scratch directory).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long to wait for the apiserver to answer before giving up.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);

/// Static bearer token wired into `--token-auth-file`, authenticating as `system:masters`.
///
/// [`start`](EnvTest::start) runs with `--authorization-mode AlwaysAllow`, so this only has to
/// authenticate. [`start_rbac`](EnvTest::start_rbac) enforces RBAC instead — this token still
/// authenticates as `system:masters` there too, which is what keeps it a full admin identity.
const TEST_TOKEN: &str = "envtest-token";

/// A real, ephemeral `etcd` + `kube-apiserver` pair.
pub struct EnvTest {
    etcd: Child,
    apiserver: Child,
    /// Kept alive so the scratch directory outlives the processes.
    _workdir: tempfile::TempDir,
    apiserver_url: String,
}

impl EnvTest {
    /// Start etcd and kube-apiserver, or explain why the suite cannot run.
    ///
    /// Runs with `--authorization-mode AlwaysAllow`: these suites are about CRD admission and
    /// controller/webhook behaviour, not RBAC. For a suite that needs to check what an identity
    /// is and is not allowed to do, use [`start_rbac`](Self::start_rbac) instead.
    pub async fn start() -> Result<Self, String> {
        Self::start_with("AlwaysAllow", &[]).await
    }

    /// Like [`start`](Self::start), but authenticating `extra_tokens` (`(token, username)` pairs)
    /// alongside the admin token, **without** turning RBAC on.
    ///
    /// The combination exists for exactly one kind of suite: one that needs several *distinct
    /// identities* so an admission webhook can tell them apart, but must not have RBAC
    /// second-guessing the verdict. `start_rbac` would refuse a non-admin identity's write before
    /// admission ever ran, which would green the test for the wrong reason — the request has to
    /// reach the webhook for the webhook's answer to be what is under test.
    pub async fn start_with_identities(extra_tokens: &[(&str, &str)]) -> Result<Self, String> {
        Self::start_with("AlwaysAllow", extra_tokens).await
    }

    /// Like [`start`](Self::start), but with `RBAC` authorization actually enforced, and
    /// `extra_tokens` (`(token, username)` pairs, no groups — e.g.
    /// `system:serviceaccount:<namespace>:<name>` to authenticate as a given `ServiceAccount`
    /// identity) authenticated alongside the built-in admin token.
    ///
    /// The admin token still authenticates as `system:masters`: kube-apiserver's own
    /// `rbac/bootstrap-roles` post-start hook binds `cluster-admin` to that group as soon as RBAC
    /// authorization is enabled, with no `kube-controller-manager` required to reconcile it.
    pub async fn start_rbac(extra_tokens: &[(&str, &str)]) -> Result<Self, String> {
        Self::start_with("RBAC", extra_tokens).await
    }

    async fn start_with(
        authorization_mode: &str,
        extra_tokens: &[(&str, &str)],
    ) -> Result<Self, String> {
        install_crypto_provider();
        let assets = assets_dir()?;
        let etcd_bin = assets.join("etcd");
        let apiserver_bin = assets.join("kube-apiserver");
        for binary in [&etcd_bin, &apiserver_bin] {
            if !binary.exists() {
                return Err(format!(
                    "{} not found; run `task envtest:setup`",
                    binary.display()
                ));
            }
        }

        let workdir =
            tempfile::tempdir().map_err(|err| format!("could not create a scratch dir: {err}"))?;
        let (sa_key, sa_pub) = generate_service_account_keys(workdir.path())?;
        let token_file = workdir.path().join("tokens.csv");
        let mut tokens = format!("{TEST_TOKEN},envtest-admin,uid-1,\"system:masters\"\n");
        for (index, (token, username)) in extra_tokens.iter().enumerate() {
            tokens.push_str(&format!("{token},{username},uid-extra-{index},\"\"\n"));
        }
        std::fs::write(&token_file, tokens)
            .map_err(|err| format!("could not write the token file: {err}"))?;

        let etcd_client_port = free_port()?;
        let etcd_peer_port = free_port()?;
        let apiserver_port = free_port()?;
        let etcd_url = format!("http://127.0.0.1:{etcd_client_port}");
        let apiserver_url = format!("https://127.0.0.1:{apiserver_port}");

        let etcd = Command::new(&etcd_bin)
            .args([
                "--listen-client-urls",
                &etcd_url,
                "--advertise-client-urls",
                &etcd_url,
                "--listen-peer-urls",
                &format!("http://127.0.0.1:{etcd_peer_port}"),
                "--data-dir",
            ])
            .arg(workdir.path().join("etcd"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| format!("could not start etcd: {err}"))?;

        let apiserver = Command::new(&apiserver_bin)
            .args([
                "--etcd-servers",
                &etcd_url,
                "--bind-address",
                "127.0.0.1",
                "--secure-port",
                &apiserver_port.to_string(),
                "--authorization-mode",
                authorization_mode,
                // The ServiceAccount admission plugin needs a running controller-manager, which
                // envtest does not provide.
                "--disable-admission-plugins",
                "ServiceAccount",
                "--service-cluster-ip-range",
                "10.0.0.0/24",
                "--service-account-issuer",
                "https://kubernetes.default.svc",
            ])
            .arg("--cert-dir")
            .arg(workdir.path().join("certs"))
            .arg("--service-account-key-file")
            .arg(&sa_pub)
            .arg("--service-account-signing-key-file")
            .arg(&sa_key)
            .arg("--token-auth-file")
            .arg(&token_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| format!("could not start kube-apiserver: {err}"))?;

        let env_test = Self {
            etcd,
            apiserver,
            _workdir: workdir,
            apiserver_url,
        };
        env_test.wait_until_ready().await?;
        Ok(env_test)
    }

    /// Start the apiserver, or skip the test when the binaries are missing.
    ///
    /// Returns `None` after printing why, unless `REQUIRE_ENVTEST` is set — which CI does, so a
    /// broken setup can never silently green the suite.
    pub async fn try_start() -> Option<Self> {
        Self::resolve_or_skip(Self::start().await)
    }

    /// Like [`try_start`](Self::try_start), for [`start_rbac`](Self::start_rbac).
    pub async fn try_start_rbac(extra_tokens: &[(&str, &str)]) -> Option<Self> {
        Self::resolve_or_skip(Self::start_rbac(extra_tokens).await)
    }

    /// Like [`try_start`](Self::try_start), for
    /// [`start_with_identities`](Self::start_with_identities).
    pub async fn try_start_with_identities(extra_tokens: &[(&str, &str)]) -> Option<Self> {
        Self::resolve_or_skip(Self::start_with_identities(extra_tokens).await)
    }

    fn resolve_or_skip(result: Result<Self, String>) -> Option<Self> {
        match result {
            Ok(env_test) => Some(env_test),
            Err(err) => {
                assert!(
                    std::env::var("REQUIRE_ENVTEST").is_err(),
                    "REQUIRE_ENVTEST is set but envtest could not start: {err}"
                );
                eprintln!("SKIPPED: {err}");
                None
            }
        }
    }

    async fn wait_until_ready(&self) -> Result<(), String> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|err| err.to_string())?;
        let healthz = format!("{}/healthz", self.apiserver_url);
        let deadline = Instant::now() + STARTUP_TIMEOUT;

        while Instant::now() < deadline {
            let response = client
                .get(&healthz)
                .bearer_auth(TEST_TOKEN)
                .send()
                .await
                .and_then(|response| response.error_for_status());
            if let Ok(response) = response
                && response.text().await.unwrap_or_default().trim() == "ok"
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Err(format!(
            "kube-apiserver did not become ready within {STARTUP_TIMEOUT:?}"
        ))
    }

    /// The apiserver's own base URL — `https://127.0.0.1:<port>`.
    pub fn url(&self) -> &str {
        &self.apiserver_url
    }

    /// The static bearer token every request against this apiserver authenticates with.
    pub fn token(&self) -> &'static str {
        TEST_TOKEN
    }

    /// A client trusting the apiserver's self-signed certificate, authenticating as the built-in
    /// admin token.
    pub fn client(&self) -> Result<kube::Client, String> {
        self.client_as(TEST_TOKEN)
    }

    /// Like [`client`](Self::client), authenticating as `token` instead — one of the pairs
    /// passed to [`start_rbac`](Self::start_rbac), for a suite that needs to check what that
    /// identity is and is not allowed to do.
    pub fn client_as(&self, token: &str) -> Result<kube::Client, String> {
        let mut config = kube::Config::new(
            self.apiserver_url
                .parse()
                .map_err(|err| format!("invalid apiserver url: {err}"))?,
        );
        config.accept_invalid_certs = true;
        config.auth_info.token = Some(secrecy::SecretBox::new(token.to_string().into()));
        kube::Client::try_from(config).map_err(|err| err.to_string())
    }
}

impl Drop for EnvTest {
    fn drop(&mut self) {
        // Kill the apiserver first: it holds connections to etcd.
        let _ = self.apiserver.kill();
        let _ = self.apiserver.wait();
        let _ = self.etcd.kill();
        let _ = self.etcd.wait();
    }
}

/// The apiserver refuses to start without a service account signing key.
///
/// Shelling out to openssl keeps a 2048-bit RSA generation out of the debug build, where doing
/// it in Rust takes several seconds per test run.
fn generate_service_account_keys(dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let key = dir.join("sa.key");
    let public = dir.join("sa.pub");

    let generated = Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(&key)
        .arg("2048")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("openssl is required by the envtest harness: {err}"))?;
    if !generated.success() {
        return Err("openssl could not generate the service account key".to_string());
    }

    let extracted = Command::new("openssl")
        .arg("rsa")
        .arg("-in")
        .arg(&key)
        .arg("-pubout")
        .arg("-out")
        .arg(&public)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| err.to_string())?;
    if !extracted.success() {
        return Err("openssl could not extract the service account public key".to_string());
    }

    Ok((key, public))
}

/// A self-signed TLS certificate for the webhook's own axum server, generated the same way as
/// the service account keypair. A SAN IP entry is mandatory — the apiserver's admission-webhook
/// HTTP client enforces SAN matching, not CN fallback.
pub fn generate_webhook_tls(dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let key = dir.join("webhook.key");
    let cert = dir.join("webhook.crt");

    let generated = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("openssl is required by the envtest harness: {err}"))?;
    if !generated.success() {
        return Err("openssl could not generate the webhook's self-signed certificate".to_string());
    }
    Ok((key, cert))
}

/// The webhook TLS certificate's raw PEM bytes, for use as a `MutatingWebhookConfiguration`'s
/// `caBundle` — self-signed, so the leaf certificate is its own trust anchor.
pub fn read_ca_bundle(cert_path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(cert_path).map_err(|err| format!("could not read {}: {err}", cert_path.display()))
}

/// The kube client speaks TLS to the apiserver, so rustls needs its provider.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn assets_dir() -> Result<PathBuf, String> {
    std::env::var("KUBEBUILDER_ASSETS")
        .map(PathBuf::from)
        .map_err(|_| "KUBEBUILDER_ASSETS is not set; run `task envtest:run`".to_string())
}

/// Ask the OS for a port, then release it. Racy in principle, fine in practice for a test
/// harness and far simpler than plumbing a port out of the binaries.
pub fn free_port() -> Result<u16, String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|err| format!("could not find a port: {err}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|err| err.to_string())
}
