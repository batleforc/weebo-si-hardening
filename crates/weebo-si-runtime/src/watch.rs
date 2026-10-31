//! Running a watch-backed cache's stream, and reporting what goes wrong with it.
//!
//! Every store in this crate starts a `reflector` stream with `default_backoff()` and drives it
//! in a background task. Before RFC 0012 that task discarded every item, errors included, so a
//! watch the apiserver kept refusing left a pod `Ready` with a cache frozen at its last list —
//! `todo.md` M12. [`drive`] logs each error and reports it to the process's liveness, so a watch
//! that keeps failing past `weebo-kit-runtime`'s threshold fails `/livez` and the kubelet
//! restarts the pod.
//!
//! **Why a process-wide sink rather than a parameter.** A watch failing is a fact about the
//! process, not about the store that noticed it, and threading a `Health` handle through every
//! store's `spawn` would change ~45 call sites — most of them envtest suites with no probe to
//! feed. The composition root calls [`report_to`] once, before any store starts; a process that
//! never calls it (every test) drives its watches exactly as before, logging included.

use std::sync::{Arc, OnceLock};

use futures_util::{Stream, StreamExt};
use weebo_kit_runtime::Health;

static HEALTH: OnceLock<Arc<Health>> = OnceLock::new();

/// Report every watch failure from now on to `health`. Only the first call counts: one process,
/// one liveness.
pub fn report_to(health: Arc<Health>) {
    let _ = HEALTH.set(health);
}

/// Drive `stream` until it ends, logging and reporting each error under `component` — the
/// resource the watch is on (`"namespaces"`, `"weebosiconfigs"`, …), which is what `/livez`
/// names when it fails.
pub async fn drive<S, T, E>(component: &'static str, stream: S)
where
    S: Stream<Item = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut stream = std::pin::pin!(stream);
    while let Some(item) = stream.next().await {
        if let Err(err) = item {
            report(component, &err);
        }
    }
}

/// Log one watch error and report it to the liveness sink, for a stream driven by hand rather
/// than through [`drive`] (`KubeConfigStore`'s, which acts on every successful event).
pub fn report(component: &'static str, err: &dyn std::fmt::Display) {
    tracing::warn!(watch = component, error = %err, "watch error, retrying with backoff");
    if let Some(health) = HEALTH.get() {
        health.failed(component, err.to_string());
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

    #[tokio::test]
    async fn drive_consumes_every_item_and_survives_errors() {
        let items: Vec<Result<u8, String>> = vec![Ok(1), Err("boom".to_string()), Ok(2)];
        // Without a sink set this must neither panic nor stop at the error.
        drive("test", futures_util::stream::iter(items)).await;
    }
}
