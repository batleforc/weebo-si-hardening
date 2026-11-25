#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]

use std::collections::BTreeMap;

use serde_json::{Value, json};
use weebo_si_chassis::NamespaceFacts;
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_crd::{FeatureMode, NamespaceName};

use super::*;
use crate::subject::is_start;

const BRANCH_URI: &str = "https://raw.githubusercontent.com/batleforc/WeeboDevImage/refs/heads/main/che-min-mise/devfile.yaml";
const PINNED_URI: &str =
    "https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.4.0/che-min-mise/devfile.yaml";
const OLD_URI: &str =
    "https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.2.0/che-min-mise/devfile.yaml";
const OLD_PREFIX: &str = "https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.2.0/";

/// The mocks' config: `currentContract: 3`, `minimumContract: 2`, `minimumSchemaVersion: 2.2.0`.
fn config() -> DevfileContractConfig {
    DevfileContractConfig {
        mode: FeatureMode::Enforce,
        namespace_selector: None,
        current_contract: 3,
        minimum_contract: 2,
        minimum_schema_version: Some("2.2.0".to_string()),
        denied_contracts: Vec::new(),
        denied_parents: Vec::new(),
        on_denied: OnDenied::Deny,
    }
}

fn prefix(uri_prefix: &str) -> DeniedParent {
    DeniedParent {
        uri_prefix: Some(uri_prefix.to_string()),
        id: None,
        versions: Vec::new(),
    }
}

/// A current devfile, as the generator writes it: contract 3, pinned parent, schema 2.3.0.
fn workspace() -> DevfileWorkspace {
    DevfileWorkspace {
        name: "go-api".to_string(),
        namespace: NamespaceName::new("dev-ws-batleforc-test"),
        platform_contract: Some(json!(3)),
        generator: None,
        parent: Some(Parent::Uri(PINNED_URI.to_string())),
        che_devfile: Some("schemaVersion: 2.3.0".to_string()),
        stored_verdict: None,
        stored_reasons: None,
        starting: true,
    }
}

fn run(subject: &DevfileWorkspace, config: DevfileContractConfig) -> Decision<DevfileWorkspace> {
    let feature = DevfileContract::new(Arc::new(RwLock::new(Some(config))));
    let namespace = NamespaceFacts {
        labels: BTreeMap::new(),
        selection_annotation: None,
    };
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    feature
        .evaluate(subject, &Context::new(&[], &namespace, &catalog))
        .unwrap()
}

fn annotations(decision: &Decision<DevfileWorkspace>) -> BTreeMap<String, String> {
    decision
        .mutations
        .iter()
        .map(|mutation| match mutation {
            Mutation::Annotate { key, value } => (key.clone(), value.clone()),
            other => panic!("unexpected mutation {other:?}"),
        })
        .collect()
}

fn reasons(decision: &Decision<DevfileWorkspace>) -> String {
    annotations(decision)
        .get(DEVFILE_CONTRACT_REASON_ANNOTATION)
        .cloned()
        .unwrap()
}

#[test]
fn the_uninteresting_case_prints_nothing_and_annotates_current() {
    let decision = run(&workspace(), config());
    assert_eq!(decision.denial, None);
    assert!(decision.warnings.is_empty());
    assert_eq!(decision.result, "current");
    assert_eq!(
        annotations(&decision),
        BTreeMap::from([
            (
                DEVFILE_CONTRACT_ANNOTATION.to_string(),
                "current".to_string()
            ),
            (
                DEVFILE_CONTRACT_REASON_ANNOTATION.to_string(),
                "contract-ok,parent-pinned,schema-ok".to_string()
            ),
        ])
    );
}

/// Every row of *Behaviour rules*, with the mocks' exact warning text.
#[test]
fn behaviour_rules_table() {
    struct Row {
        name: &'static str,
        contract: Option<Value>,
        parent: Option<Parent>,
        schema: Option<&'static str>,
        verdict: &'static str,
        reasons: &'static str,
        warnings: &'static [&'static str],
    }
    let id = |version: Option<&str>| Parent::Id {
        id: "che-min-mise".to_string(),
        version: version.map(str::to_string),
    };
    let rows = [
        Row {
            name: "outdated contract",
            contract: Some(json!(1)),
            parent: None,
            schema: None,
            verdict: "outdated",
            reasons: "contract-below-minimum,parent-none,schema-unknown",
            warnings: &[
                "devfile written for platform contract 1, minimum is 2: see the User Guide changes for contracts 2 to 3",
            ],
        },
        Row {
            name: "absent contract below the minimum, parent on a branch (weebo-che-project)",
            contract: None,
            parent: Some(Parent::Uri(BRANCH_URI.to_string())),
            schema: None,
            verdict: "unknown",
            reasons: "contract-absent,parent-branch,schema-unknown",
            warnings: &[
                "devfile has no weebo.io/platform-contract attribute; add \"weebo.io/platform-contract: 3\" to its attributes",
                "devfile parent follows branch \"main\": pin parent.uri to a tag or a commit",
            ],
        },
        Row {
            name: "not an integer",
            contract: Some(json!("three")),
            parent: None,
            schema: Some("schemaVersion: 2.3.0"),
            verdict: "unknown",
            reasons: "contract-invalid,parent-none,schema-ok",
            warnings: &[
                "weebo.io/platform-contract must be an integer, read as absent; current is 3",
            ],
        },
        Row {
            name: "a quoted integer is accepted",
            contract: Some(json!("2")),
            parent: None,
            schema: None,
            verdict: "current",
            reasons: "contract-ok,parent-none,schema-unknown",
            warnings: &[],
        },
        Row {
            name: "from the future",
            contract: Some(json!(9)),
            parent: None,
            schema: None,
            verdict: "unknown",
            reasons: "contract-future,parent-none,schema-unknown",
            warnings: &[
                "weebo.io/platform-contract 9 is newer than this platform (3): check the value",
            ],
        },
        Row {
            name: "mutable parent",
            contract: Some(json!(3)),
            parent: Some(Parent::Kubernetes),
            schema: None,
            verdict: "outdated",
            reasons: "contract-ok,parent-mutable,schema-unknown",
            warnings: &[
                "devfile parent is a DevWorkspaceTemplate (parent.kubernetes): the workspace itself can change it",
            ],
        },
        Row {
            name: "registry parent without a version",
            contract: Some(json!(3)),
            parent: Some(id(None)),
            schema: None,
            verdict: "outdated",
            reasons: "contract-ok,parent-no-version,schema-unknown",
            warnings: &["devfile parent \"che-min-mise\" has no version: set parent.version"],
        },
        Row {
            name: "registry parent with an empty version",
            contract: Some(json!(3)),
            parent: Some(id(Some(""))),
            schema: None,
            verdict: "outdated",
            reasons: "contract-ok,parent-no-version,schema-unknown",
            warnings: &["devfile parent \"che-min-mise\" has no version: set parent.version"],
        },
        Row {
            name: "registry parent with a version",
            contract: Some(json!(3)),
            parent: Some(id(Some("1.4.0"))),
            schema: None,
            verdict: "current",
            reasons: "contract-ok,parent-pinned,schema-unknown",
            warnings: &[],
        },
        Row {
            name: "unrecognised uri",
            contract: Some(json!(3)),
            parent: Some(Parent::Uri("https://example.org/devfile.yaml".to_string())),
            schema: None,
            verdict: "outdated",
            reasons: "contract-ok,parent-unpinned,schema-unknown",
            warnings: &["devfile parent is not pinned to a tag or a commit: pin parent.uri to one"],
        },
        Row {
            name: "old schemaVersion",
            contract: Some(json!(3)),
            parent: None,
            schema: Some("schemaVersion: 2.1.0"),
            verdict: "outdated",
            reasons: "contract-ok,parent-none,schema-below-minimum",
            warnings: &["devfile schemaVersion 2.1.0 is below the platform minimum 2.2.0"],
        },
        Row {
            name: "unreadable schemaVersion warns nothing",
            contract: Some(json!(3)),
            parent: None,
            schema: Some("schemaVersion: latest"),
            verdict: "current",
            reasons: "contract-ok,parent-none,schema-unknown",
            warnings: &[],
        },
    ];
    for row in rows {
        let subject = DevfileWorkspace {
            platform_contract: row.contract,
            parent: row.parent,
            che_devfile: row.schema.map(str::to_string),
            ..workspace()
        };
        let decision = run(&subject, config());
        assert_eq!(decision.denial, None, "{}", row.name);
        assert_eq!(decision.result, row.verdict, "{}", row.name);
        assert_eq!(reasons(&decision), row.reasons, "{}", row.name);
        assert_eq!(decision.warnings, row.warnings, "{}", row.name);
        for warning in &decision.warnings {
            assert!(warning.chars().count() <= 120, "{}: {warning}", row.name);
        }
    }
}

#[test]
fn no_schema_minimum_means_no_schema_warning() {
    let subject = DevfileWorkspace {
        che_devfile: Some("schemaVersion: 1.0.0".to_string()),
        ..workspace()
    };
    let decision = run(
        &subject,
        DevfileContractConfig {
            minimum_schema_version: None,
            ..config()
        },
    );
    assert!(decision.warnings.is_empty());
    assert!(reasons(&decision).ends_with("schema-ok"));
}

#[test]
fn a_denied_parent_on_a_start_is_refused_quoting_the_admin_entry() {
    let subject = DevfileWorkspace {
        parent: Some(Parent::Uri(OLD_URI.to_string())),
        ..workspace()
    };
    let decision = run(
        &subject,
        DevfileContractConfig {
            denied_parents: vec![prefix(OLD_PREFIX)],
            ..config()
        },
    );
    assert_eq!(
        decision.denial.as_deref(),
        Some(
            "devfile parent is denied by the platform (deniedParents entry 1: https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.2.0/): move parent.uri to a newer version; contract 3 in the User Guide lists them"
        )
    );
    assert_eq!(decision.result, "denied");
    assert!(decision.mutations.is_empty());
    // R1: the refusal's log note carries its reasons.
    assert_eq!(
        decision.note.as_deref(),
        Some(
            "devfile=current reasons=contract-ok,parent-pinned,schema-ok,parent-denied contract=3"
        )
    );
}

#[test]
fn a_denial_never_quotes_credentials_from_the_admin_prefix() {
    let subject = DevfileWorkspace {
        parent: Some(Parent::Uri(OLD_URI.to_string())),
        ..workspace()
    };
    let decision = run(
        &subject,
        DevfileContractConfig {
            denied_parents: vec![prefix(
                "https://bot:ghp0tok@raw.githubusercontent.com/batleforc/WeeboDevImage/v1.2.0/",
            )],
            ..config()
        },
    );
    let denial = decision.denial.unwrap();
    assert!(
        denial.contains(&format!("entry 1: {OLD_PREFIX})")),
        "{denial}"
    );
    assert!(!denial.contains("ghp0tok"));
}

#[test]
fn a_denied_contract_refuses_a_devfile_without_the_attribute() {
    let subject = DevfileWorkspace {
        platform_contract: None,
        ..workspace()
    };
    let decision = run(
        &subject,
        DevfileContractConfig {
            denied_contracts: vec![1],
            ..config()
        },
    );
    assert_eq!(
        decision.denial.as_deref(),
        Some(
            "platform contract 1 is denied (devfiles without weebo.io/platform-contract count as 1): add \"weebo.io/platform-contract: 3\" and follow the User Guide"
        )
    );
}

#[test]
fn a_denied_registry_id_matches_its_versions() {
    let denied = [DeniedParent {
        uri_prefix: None,
        id: Some("che-min-mise".to_string()),
        versions: vec!["1.2.0".to_string()],
    }];
    let parent = |version: Option<&str>| Parent::Id {
        id: "che-min-mise".to_string(),
        version: version.map(str::to_string),
    };
    assert!(denied_match(&parent(Some("1.2.0")), &denied).is_some());
    assert!(denied_match(&parent(Some("1.4.0")), &denied).is_none());
    assert!(denied_match(&parent(None), &denied).is_none());
    let every = [DeniedParent {
        versions: Vec::new(),
        ..denied[0].clone()
    }];
    assert!(denied_match(&parent(None), &every).is_some());
    assert!(denied_match(&Parent::Uri(OLD_URI.to_string()), &every).is_none());

    let subject = DevfileWorkspace {
        parent: Some(parent(Some("1.2.0"))),
        ..workspace()
    };
    let decision = run(
        &subject,
        DevfileContractConfig {
            denied_parents: denied.to_vec(),
            ..config()
        },
    );
    assert_eq!(
        decision.denial.as_deref(),
        Some(
            "devfile parent is denied by the platform (deniedParents entry 1: id che-min-mise): move parent.version to a newer version; contract 3 in the User Guide lists them"
        )
    );
}

#[test]
fn a_denied_prefix_matches_despite_query_and_userinfo() {
    let denied = [
        prefix("https://other.example/"),
        prefix("HTTPS://Raw.GitHubUserContent.com/batleforc/WeeboDevImage/v1.2.0/"),
    ];
    for uri in [
        OLD_URI.to_string(),
        format!("{OLD_URI}?token=abc#frag"),
        "https://user:tok@RAW.githubusercontent.com/batleforc/WeeboDevImage/v1.2.0/x.yaml"
            .to_string(),
    ] {
        let (index, _) = denied_match(&Parent::Uri(uri.clone()), &denied).unwrap();
        assert_eq!(index, 2, "{uri}");
    }
    // The path is compared without case: GitHub serves `WeeboDevImage` and `weebodevimage` alike.
    assert!(
        denied_match(
            &Parent::Uri(
                "https://raw.githubusercontent.com/batleforc/weebodevimage/v1.2.0/x".to_string()
            ),
            &denied
        )
        .is_some()
    );
}

#[test]
fn a_denied_parent_on_a_non_start_update_is_a_warning() {
    let subject = DevfileWorkspace {
        parent: Some(Parent::Uri(OLD_URI.to_string())),
        starting: false,
        ..workspace()
    };
    let decision = run(
        &subject,
        DevfileContractConfig {
            denied_parents: vec![prefix(OLD_PREFIX)],
            ..config()
        },
    );
    assert_eq!(decision.denial, None);
    assert_eq!(
        decision.warnings,
        [
            "devfile parent is denied by the platform (deniedParents entry 1): this workspace will be refused at its next start"
        ]
    );
    assert_eq!(
        reasons(&decision),
        "contract-ok,parent-pinned,schema-ok,parent-denied"
    );
}

#[test]
fn on_denied_warn_never_refuses() {
    let subject = DevfileWorkspace {
        parent: Some(Parent::Uri(OLD_URI.to_string())),
        platform_contract: None,
        ..workspace()
    };
    let decision = run(
        &subject,
        DevfileContractConfig {
            denied_contracts: vec![1],
            denied_parents: vec![prefix(OLD_PREFIX)],
            on_denied: OnDenied::Warn,
            ..config()
        },
    );
    assert_eq!(decision.denial, None);
    assert_eq!(
        decision.warnings[1..],
        [
            "platform contract 1 is denied: add \"weebo.io/platform-contract: 3\" and follow the User Guide",
            "devfile parent is denied by the platform (deniedParents entry 1): move parent.uri to a newer version",
        ]
    );
}

#[test]
fn changing_parent_while_running_is_refused() {
    // D-13: the extraction calls `is_start`; a template change while started is a start.
    let subject = DevfileWorkspace {
        parent: Some(Parent::Uri(OLD_URI.to_string())),
        starting: is_start(false, true, true, true),
        ..workspace()
    };
    let config = DevfileContractConfig {
        denied_parents: vec![prefix(OLD_PREFIX)],
        ..config()
    };
    assert!(run(&subject, config.clone()).denial.is_some());
    let stop = DevfileWorkspace {
        starting: is_start(false, true, false, false),
        ..subject
    };
    assert!(run(&stop, config).denial.is_none());
}

#[test]
fn outdated_is_never_a_denial() {
    for parent in [
        None,
        Some(Parent::Uri(BRANCH_URI.to_string())),
        Some(Parent::Uri("https://example.org/x".to_string())),
        Some(Parent::Kubernetes),
        Some(Parent::Id {
            id: "x".to_string(),
            version: None,
        }),
    ] {
        for contract in [
            None,
            Some(json!("bad")),
            Some(json!(0)),
            Some(json!(1)),
            Some(json!(99)),
        ] {
            let subject = DevfileWorkspace {
                parent: parent.clone(),
                platform_contract: contract,
                che_devfile: Some("schemaVersion: 0.0.1".to_string()),
                ..workspace()
            };
            assert_eq!(run(&subject, config()).denial, None);
        }
    }
}

#[test]
fn generator_attributes_never_change_the_verdict() {
    let plain = DevfileWorkspace {
        parent: Some(Parent::Uri(BRANCH_URI.to_string())),
        ..workspace()
    };
    let claimed = DevfileWorkspace {
        generator: Some("weebo-devfile-generator 9.9.9 official current".to_string()),
        ..plain.clone()
    };
    let (a, b) = (run(&plain, config()), run(&claimed, config()));
    assert_eq!(
        (a.result, a.warnings, a.mutations),
        (b.result, b.warnings, b.mutations)
    );
    assert!(
        b.note
            .unwrap()
            .ends_with(" generator=weebo-devfile-generator9.9.9offi")
    );
}

#[test]
fn a_forged_current_annotation_is_overwritten() {
    let subject = DevfileWorkspace {
        parent: Some(Parent::Kubernetes),
        stored_verdict: Some("current".to_string()),
        stored_reasons: Some("contract-ok,parent-pinned,schema-ok".to_string()),
        ..workspace()
    };
    let decision = run(&subject, config());
    assert_eq!(
        annotations(&decision)
            .get(DEVFILE_CONTRACT_ANNOTATION)
            .unwrap(),
        "outdated"
    );
}

#[test]
fn an_already_annotated_object_emits_no_patch() {
    let subject = DevfileWorkspace {
        stored_verdict: Some("current".to_string()),
        stored_reasons: Some("contract-ok,parent-pinned,schema-ok".to_string()),
        ..workspace()
    };
    assert!(run(&subject, config()).mutations.is_empty());
}

#[test]
fn a_kubernetes_parent_warns() {
    let subject = DevfileWorkspace {
        parent: Some(Parent::Kubernetes),
        ..workspace()
    };
    let decision = run(&subject, config());
    assert_eq!(decision.result, "outdated");
    assert_eq!(decision.warnings.len(), 1);
}

#[test]
fn a_token_in_parent_uri_never_reaches_a_warning_or_log() {
    let secret = "ghp0SECRET0TOKEN";
    for uri in [
        format!(
            "https://x-access-token:{secret}@raw.githubusercontent.com/o/r/refs/heads/main/d.yaml"
        ),
        format!("https://{secret}@host/o/r/develop/d.yaml?token={secret}#{secret}"),
    ] {
        let subject = DevfileWorkspace {
            parent: Some(Parent::Uri(uri.clone())),
            starting: false,
            ..workspace()
        };
        let decision = run(
            &subject,
            DevfileContractConfig {
                denied_parents: vec![prefix("https://")],
                ..config()
            },
        );
        let everything = format!(
            "{:?} {:?} {:?} {:?}",
            decision.warnings, decision.note, decision.denial, decision.mutations
        );
        assert!(!everything.contains(secret), "{uri}: {everything}");
        assert!(!everything.contains("SECRET"), "{uri}: {everything}");
    }
}

#[test]
fn a_control_character_never_reaches_a_warning() {
    let subject = DevfileWorkspace {
        parent: Some(Parent::Uri(
            "https://host/o/r/refs/heads/x\u{1b}[31m\r\nWarning: forged/d.yaml".to_string(),
        )),
        generator: Some("g\u{1b}\r\n".repeat(1000)),
        ..workspace()
    };
    let decision = run(&subject, config());
    for text in decision.warnings.iter().chain(decision.note.iter()) {
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }
    assert_eq!(
        decision.warnings,
        [
            "devfile parent follows branch \"x31mWarningforged\": pin parent.uri to a tag or a commit"
        ]
    );
}

#[test]
fn only_its_own_annotations_are_emitted() {
    let subject = DevfileWorkspace {
        platform_contract: None,
        parent: Some(Parent::Kubernetes),
        ..workspace()
    };
    for mutation in run(&subject, config()).mutations {
        let Mutation::Annotate { key, .. } = mutation else {
            panic!("only Annotate is allowed");
        };
        assert!(
            key == DEVFILE_CONTRACT_ANNOTATION || key == DEVFILE_CONTRACT_REASON_ANNOTATION,
            "{key}"
        );
    }
}

#[test]
fn a_block_removed_mid_request_admits_untouched() {
    let feature = DevfileContract::new(Arc::new(RwLock::new(None)));
    let namespace = NamespaceFacts {
        labels: BTreeMap::new(),
        selection_annotation: None,
    };
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let decision = feature
        .evaluate(&workspace(), &Context::new(&[], &namespace, &catalog))
        .unwrap();
    assert!(decision.denial.is_none() && decision.mutations.is_empty());
    assert!(decision.warnings.is_empty());
    // The literal `weebo-si-runtime`'s `prometheus.rs` filters on: renaming one breaks this.
    assert_eq!(decision.result, "no_config");
    assert_eq!(decision.note.as_deref(), Some("devfile=no_config"));
    assert_eq!(feature.id().kebab(), FEATURE_ID);
}

/// xorshift64*: a deterministic generator, so the property test needs no new dependency
/// (RFC 0019, *Supply chain*) and a failure is reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn string(&mut self) -> String {
        const PIECES: &[&str] = &[
            "",
            "/",
            "refs",
            "heads",
            "tags",
            "raw",
            "branch",
            "commit",
            "main",
            "v1.2.0",
            "2.3.0",
            "://",
            "https",
            "@",
            "?",
            "#",
            ":",
            "\u{1b}",
            "\r\n",
            "é",
            "\u{202e}",
            "\0",
            "0",
            "schemaVersion:",
            " ",
            "\"",
            "0123456789abcdef0123456789abcdef01234567",
            "-1",
            "4294967296",
        ];
        let len = self.below(12);
        (0..len)
            .map(|_| PIECES[usize::try_from(self.below(PIECES.len() as u64)).unwrap()])
            .collect()
    }

    fn json(&mut self, depth: u32) -> Value {
        match self.below(if depth == 0 { 5 } else { 7 }) {
            0 => Value::Null,
            1 => Value::Bool(self.below(2) == 0),
            2 => json!(self.next() as i64),
            3 => json!(f64::from(u32::try_from(self.below(1000)).unwrap()) / 7.0),
            4 => Value::String(self.string()),
            5 => Value::Array((0..self.below(4)).map(|_| self.json(depth - 1)).collect()),
            _ => Value::Object(
                (0..self.below(4))
                    .map(|_| (self.string(), self.json(depth - 1)))
                    .collect(),
            ),
        }
    }

    fn option<T>(&mut self, make: impl FnOnce(&mut Self) -> T) -> Option<T> {
        (self.below(4) != 0).then(|| make(self))
    }
}

#[test]
fn evaluate_never_errs_on_arbitrary_json() {
    const VOCABULARY: &[&str] = &[
        "contract-absent",
        "contract-invalid",
        "contract-future",
        "contract-below-minimum",
        "contract-ok",
        "parent-branch",
        "parent-unpinned",
        "parent-no-version",
        "parent-mutable",
        "parent-pinned",
        "parent-none",
        "parent-denied",
        "contract-denied",
        "schema-below-minimum",
        "schema-ok",
        "schema-unknown",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for case in 0..5000 {
        let parent = rng.option(|rng| match rng.below(3) {
            0 => Parent::Uri(rng.string()),
            1 => Parent::Id {
                id: rng.string(),
                version: rng.option(Rng::string),
            },
            _ => Parent::Kubernetes,
        });
        let subject = DevfileWorkspace {
            platform_contract: rng.option(|rng| rng.json(3)),
            generator: rng.option(Rng::string),
            parent,
            che_devfile: rng.option(Rng::string),
            stored_verdict: rng.option(Rng::string),
            stored_reasons: rng.option(Rng::string),
            starting: rng.below(2) == 0,
            ..workspace()
        };
        let config = DevfileContractConfig {
            denied_contracts: vec![1, 2],
            denied_parents: vec![
                prefix("https://"),
                prefix(&format!("https://{}", rng.string())),
            ],
            on_denied: if rng.below(2) == 0 {
                OnDenied::Deny
            } else {
                OnDenied::Warn
            },
            ..config()
        };
        let on_denied = config.on_denied;
        let decision = run(&subject, config);
        if decision.denial.is_some() {
            assert!(
                subject.starting && on_denied == OnDenied::Deny,
                "case {case}"
            );
            continue;
        }
        for warning in &decision.warnings {
            assert!(
                !warning.chars().any(char::is_control),
                "case {case}: {warning:?}"
            );
        }
        for (key, value) in annotations(&decision) {
            if key == DEVFILE_CONTRACT_ANNOTATION {
                assert!(["current", "outdated", "unknown"].contains(&value.as_str()));
            } else {
                assert_eq!(key, DEVFILE_CONTRACT_REASON_ANNOTATION);
                assert!(
                    value.split(',').all(|code| VOCABULARY.contains(&code)),
                    "{value}"
                );
            }
        }
    }
}

#[test]
fn a_denied_prefix_is_not_bypassed_by_another_spelling() {
    let denied = [prefix("https://github.com/org/old-stack")];
    for uri in [
        "https://github.com/Org/Old-Stack/raw/v1/devfile.yaml",
        "https://github.com/org/%6Fld-stack/raw/v1/devfile.yaml",
        "https://github.com/org/x/../old-stack/raw/v1/devfile.yaml",
        "https://github.com/org/./old-stack/devfile.yaml",
    ] {
        assert!(
            denied_match(&Parent::Uri(uri.to_string()), &denied).is_some(),
            "{uri}"
        );
    }
    let other = Parent::Uri("https://github.com/org/old-stack-2/devfile.yaml".to_string());
    assert!(denied_match(&other, &[prefix("https://github.com/org/new-stack")]).is_none());
}
