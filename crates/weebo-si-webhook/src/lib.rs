//! The admission side's shared half (RFC 0012): the `DevWorkspace` mutation route, where
//! `dwoc-pin` and the `network-profiles` workspace gate run over the same request (RFC 0002,
//! RFC 0004); `AdmissionReview` extraction and JSON Patch rendering; the admission metrics; and
//! [`AdmissionShared`], what the composition root hands every feature's adapters crate. The
//! other features' routes live in their adapters crates.

pub mod extract;
pub mod metrics;
pub mod render;
pub mod router;
pub mod shared;

pub use metrics::WebhookMetrics;
pub use router::{AppState, MUTATE_DEVWORKSPACES_PATH, NetworkProfilesAdmission, router};
pub use shared::AdmissionShared;

/// RFC 0012's companion to `router.rs`'s "the object's `data` is read in exactly one place":
/// `tracing` makes `?object` — a whole admitted object, a token in its env vars included — one
/// keystroke away, so no log macro in this crate may name the admitted object, the review that
/// carries it, or a `DynamicObject` at all.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failed assertion is the test failing"
)]
mod no_object_in_logs {
    const SOURCES: &[(&str, &str)] = &[
        ("extract.rs", include_str!("extract.rs")),
        ("metrics.rs", include_str!("metrics.rs")),
        ("render.rs", include_str!("render.rs")),
        ("router.rs", include_str!("router.rs")),
        ("shared.rs", include_str!("shared.rs")),
    ];

    /// Every `tracing::<level>!( … )` invocation in `source`, parentheses balanced.
    fn log_calls(source: &str) -> Vec<&str> {
        let mut calls = Vec::new();
        for level in ["trace", "debug", "info", "warn", "error"] {
            let needle = format!("tracing::{level}!(");
            let mut from = 0;
            while let Some(found) = source[from..].find(&needle) {
                let start = from + found;
                let mut depth = 0usize;
                let mut end = start;
                for (offset, ch) in source[start..].char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = start + offset + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                calls.push(&source[start..end]);
                from = end.max(start + needle.len());
            }
        }
        calls
    }

    fn names_a_whole_object(call: &str) -> bool {
        let words: Vec<&str> = call
            .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
            .collect();
        [
            "object",
            "old_object",
            "review",
            "DynamicObject",
            "AdmissionReview",
        ]
        .iter()
        .any(|forbidden| words.contains(forbidden))
    }

    #[test]
    fn every_source_file_is_scanned() {
        let on_disk = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src"))
            .unwrap()
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.ends_with(".rs") && name != "lib.rs")
            .count();
        assert_eq!(
            on_disk,
            SOURCES.len(),
            "a source file was added to weebo-si-webhook: add it to SOURCES"
        );
    }

    #[test]
    fn no_log_macro_names_the_admitted_object() {
        for (file, source) in SOURCES {
            for call in log_calls(source) {
                assert!(
                    !names_a_whole_object(call),
                    "{file}: a log line names the admitted object or its review — log the \
                     fields RFC 0002 lists, never the object:\n{call}"
                );
            }
        }
    }

    #[test]
    fn the_scan_catches_an_object_in_a_log_macro() {
        let planted = ["tracing", "::info!(?object, \"admitted\");"].concat();
        let calls = log_calls(&planted);
        assert_eq!(calls.len(), 1);
        assert!(names_a_whole_object(calls[0]));
    }
}
