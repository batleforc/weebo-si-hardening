//! `NamespaceLabelStore` over the apiserver: a server-side apply for the six labels, a merge patch
//! to put them back — and the apiserver's `Warning` headers, which is how a level change reports
//! the existing pods it would refuse.
//!
//! **Why a raw request rather than `Api::patch`.** `Api::patch` returns the object and drops the
//! response headers, and the warnings are only in the headers. RFC 0013 left open whether
//! kube-client surfaces them; it does not, so this adapter builds the same request `Api::patch`
//! would and sends it with `Client::send`, which hands back the whole response.

use std::future::Future;
use std::pin::Pin;

use http::header::HeaderMap;
use kube::Client;
use kube::api::{Patch, PatchParams};
use kube::core::Request;
use weebo_si_chassis::DomainError;
use weebo_si_crd::{NamespaceName, PodSecurityLevel, PodSecurityVersion};
use weebo_si_pod_security::{
    ENFORCE, ENFORCE_VERSION, FIELD_MANAGER, LabelWrite, NamespaceLabelStore, PREVIOUS_ANNOTATION,
    PodSecurityLabels, Restore,
};

/// The field manager the restore write uses. Deliberately not [`FIELD_MANAGER`]: once restored,
/// the keys are no longer this feature's, and a later pass must not read them as its own.
pub const RESTORE_FIELD_MANAGER: &str = "weebo-si-pod-security-restore";

/// Writes the six labels to namespaces through the apiserver.
pub struct KubeNamespaceLabelStore {
    client: Client,
}

impl KubeNamespaceLabelStore {
    /// A store writing through `client`.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// What the apiserver would warn about if `namespace` enforced `level` at `version`: a
    /// server-side **dry run** of the two `enforce` labels, which writes nothing. The question
    /// `pods audit` asks before anything is switched on. Needs the same RBAC as the write.
    pub async fn dry_run_enforce(
        &self,
        namespace: &NamespaceName,
        level: PodSecurityLevel,
        version: &PodSecurityVersion,
    ) -> Result<Vec<String>, DomainError> {
        let params = PatchParams {
            dry_run: true,
            field_manager: Some(FIELD_MANAGER.to_string()),
            ..PatchParams::default()
        };
        self.patch(
            namespace,
            &params,
            &Patch::Merge(serde_json::json!({
                "metadata": {"labels": {
                    ENFORCE: level.as_str(),
                    ENFORCE_VERSION: version.as_str(),
                }},
            })),
        )
        .await
    }

    /// Send one patch to `namespace` and return the `Warning` headers of the answer.
    async fn patch(
        &self,
        namespace: &NamespaceName,
        params: &PatchParams,
        patch: &Patch<serde_json::Value>,
    ) -> Result<Vec<String>, DomainError> {
        let request = Request::new("/api/v1/namespaces")
            .patch(namespace.as_str(), params, patch)
            .map_err(|err| DomainError::PortFailed(format!("building the patch: {err}")))?;
        let response = self
            .client
            .send(request.map(kube::client::Body::from))
            .await
            .map_err(|err| DomainError::PortFailed(format!("patching {namespace}: {err}")))?;
        let warnings = warnings(response.headers());
        let status = response.status();
        if !status.is_success() {
            let body = response
                .into_body()
                .collect_bytes()
                .await
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            return Err(DomainError::PortFailed(format!(
                "patching {namespace}: {status}: {body}"
            )));
        }
        Ok(warnings)
    }
}

/// The server-side apply body: the six labels and the annotation, and nothing else. Every field
/// in it becomes this manager's; every field this manager owned and left out is removed.
pub fn apply_body(
    namespace: &NamespaceName,
    labels: &PodSecurityLabels,
    previous: &str,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": namespace.as_str(),
            "labels": labels.as_map(),
            "annotations": {PREVIOUS_ANNOTATION: previous},
        },
    })
}

/// An apply body with no field at all: sent under [`FIELD_MANAGER`] before a restore, it gives up
/// every field this manager owns. A field nobody else owns is removed with it.
pub fn release_body(namespace: &NamespaceName) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": namespace.as_str()},
    })
}

/// The merge patch that puts the keys back: a value for each key found before the first write,
/// `null` for the others and for the annotation.
pub fn restore_body(restore: &Restore) -> serde_json::Value {
    let mut labels = serde_json::Map::new();
    for key in &restore.remove {
        labels.insert(key.clone(), serde_json::Value::Null);
    }
    for (key, value) in &restore.set {
        labels.insert(key.clone(), serde_json::Value::String(value.clone()));
    }
    serde_json::json!({
        "metadata": {
            "labels": labels,
            "annotations": {PREVIOUS_ANNOTATION: null},
        },
    })
}

/// The text of every `Warning` header: `299 - "text"`, per RFC 9111, as the apiserver sends them.
/// A header in another shape is kept whole rather than dropped.
pub fn warnings(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(http::header::WARNING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| {
            value
                .strip_prefix("299 - \"")
                .and_then(|rest| rest.strip_suffix('"'))
                .map_or_else(
                    || value.to_string(),
                    |text| text.replace("\\\"", "\"").replace("\\\\", "\\"),
                )
        })
        .collect()
}

impl NamespaceLabelStore for KubeNamespaceLabelStore {
    fn write<'a>(
        &'a self,
        namespace: &'a NamespaceName,
        write: &'a LabelWrite,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DomainError>> + Send + 'a>> {
        Box::pin(async move {
            match write {
                LabelWrite::Apply { labels, previous } => {
                    // Forced: the first write takes the keys over from whoever set them, which is
                    // the point — the previous values are already in the annotation.
                    let params = PatchParams::apply(FIELD_MANAGER).force();
                    self.patch(
                        namespace,
                        &params,
                        &Patch::Apply(apply_body(namespace, labels, previous)),
                    )
                    .await
                }
                LabelWrite::Restore(restore) => {
                    let release = PatchParams::apply(FIELD_MANAGER).force();
                    self.patch(namespace, &release, &Patch::Apply(release_body(namespace)))
                        .await?;
                    let params = PatchParams {
                        field_manager: Some(RESTORE_FIELD_MANAGER.to_string()),
                        ..PatchParams::default()
                    };
                    self.patch(namespace, &params, &Patch::Merge(restore_body(restore)))
                        .await
                }
            }
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use http::HeaderValue;
    use weebo_si_pod_security::KEYS;

    use super::*;

    #[test]
    fn the_apply_body_carries_the_six_labels_and_the_annotation_only() {
        let labels = PodSecurityLabels::desired(
            PodSecurityLevel::Restricted,
            PodSecurityLevel::Restricted,
            &PodSecurityVersion::new("v1.34"),
        );
        let body = apply_body(&NamespaceName::new("user-bob"), &labels, "{}");
        let metadata = body["metadata"].as_object().unwrap();
        let mut keys: Vec<&String> = metadata.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["annotations", "labels", "name"]);
        assert_eq!(metadata["labels"].as_object().unwrap().len(), KEYS.len());
        assert_eq!(metadata["annotations"][PREVIOUS_ANNOTATION], "{}");
        assert_eq!(body["kind"], "Namespace");
    }

    #[test]
    fn the_restore_body_sets_back_removes_the_rest_and_drops_the_annotation() {
        let restore = Restore {
            set: BTreeMap::from([(ENFORCE.to_string(), "privileged".to_string())]),
            remove: KEYS[1..].iter().map(|key| (*key).to_string()).collect(),
            previous_lost: false,
        };
        let body = restore_body(&restore);
        assert_eq!(body["metadata"]["labels"][ENFORCE], "privileged");
        for key in &KEYS[1..] {
            assert!(body["metadata"]["labels"][*key].is_null());
        }
        assert!(body["metadata"]["annotations"][PREVIOUS_ANNOTATION].is_null());
        assert_eq!(body["metadata"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn warnings_are_unwrapped_from_the_299_format() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::WARNING,
            HeaderValue::from_static(
                r#"299 - "existing pods in namespace \"user-bob\" violate the new PodSecurity enforce level \"restricted:v1.34\"""#,
            ),
        );
        headers.append(
            http::header::WARNING,
            HeaderValue::from_static(r#"299 - "debug: runAsNonRoot != true""#),
        );
        headers.append(http::header::WARNING, HeaderValue::from_static("odd"));
        assert_eq!(
            warnings(&headers),
            vec![
                r#"existing pods in namespace "user-bob" violate the new PodSecurity enforce level "restricted:v1.34""#
                    .to_string(),
                "debug: runAsNonRoot != true".to_string(),
                "odd".to_string(),
            ]
        );
    }
}
