//! Service-owned Change-Aware comparison contract.
//!
//! Proves that the comparison reads only retained evidence, refuses
//! incomparable pairs without inventing a verdict, and never starts a campaign.

#![cfg(feature = "change-aware")]

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus, SmokeRunSummary};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::change_impact::{
    ComparabilityRefusal, CoverageComparison, FindingChange, TargetImpact,
};
use hf_service::{
    change_comparison_defectdojo_document, ChangeImpactRequest, RevisionComparisonRequest,
    RevisionComparisonView, ServiceContainer,
};
use hf_storage::{HarnessApprovalKind, RunRecord, RunStatus, Store};
use uuid::Uuid;

const PARSER_DIFF: &str = "\
diff --git a/parser.c b/parser.c
--- a/parser.c
+++ b/parser.c
@@ -4,0 +5,2 @@
+    int extra = 1;
+    use(extra);
";

struct Fixture {
    container: ServiceContainer,
    project: tempfile::TempDir,
    target_id: Uuid,
    base_run: Uuid,
    head_run: Uuid,
    incomparable_run: Uuid,
    settings_mismatches: Vec<(Uuid, ComparabilityRefusal)>,
}

async fn fixture() -> Fixture {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        b"int parse_packet(void);\n",
    )
    .unwrap();
    let store = Arc::new(
        Store::connect(project.path().join("oxfuzz.db"))
            .await
            .unwrap(),
    );

    let mut target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.path().to_path_buf(),
        symbol: "parse_packet".to_owned(),
        language: TargetLanguage::C,
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: project.path().join("parser.c"),
            line: 1,
            col: 1,
            end_line: Some(20),
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 3,
        accumulated_complexity: 3,
        reachable_functions: Vec::new(),
        fit_score: 0.9,
        sanitizers: vec![Sanitizer::Address],
        rationale: "fixture".to_owned(),
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();

    let mut harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_packet"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::SmokePassed,
        smoke_run: Some(SmokeRunSummary {
            duration_secs: 60,
            execs_per_sec: 1.0,
            crashes: 0,
            passed: true,
            source_sha256: Some("a".repeat(64)),
            binary_sha256: Some("b".repeat(64)),
            run_id: Some(Uuid::new_v4()),
        }),
    };
    store.upsert_harness(&harness).await.unwrap();
    harness.status = HarnessStatus::Promoted;
    store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .unwrap();
    target.reachable_functions = Vec::new();

    let config = FuzzRunConfig {
        harness_id: harness.id,
        engine: EngineKind::LibFuzzer,
        duration: Some(std::time::Duration::from_secs(60)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: Some(7),
        replay_of: None,
    };
    let image = format!("docker-image-id-sha256:{}", "f".repeat(64));

    let insert = |source: &str, corpus: &str, sandbox: &str, edges: u64| {
        let mut run = RunRecord::new(
            project.path().to_string_lossy(),
            EngineKind::LibFuzzer,
            Some(config.clone()),
            Utc::now(),
        );
        run.status = RunStatus::Done;
        run.ended_at = Some(Utc::now());
        run.edges = Some(edges);
        run.harness_rev = Some("a".repeat(64));
        run.binary_rev = Some("b".repeat(64));
        run.source_rev = Some(source.to_owned());
        run.corpus_rev = Some(corpus.to_owned());
        run.sandbox_rev = Some(sandbox.to_owned());
        run.context_rev = Some("c".repeat(64));
        run
    };

    let base = insert(&"1".repeat(64), &"2".repeat(64), &image, 1000);
    let mut head = insert(&"3".repeat(64), &"2".repeat(64), &image, 900);
    head.binary_rev = Some("e".repeat(64));
    // Same source as base: a pair that measures no change at all.
    let incomparable = insert(&"1".repeat(64), &"2".repeat(64), &image, 950);
    let mut settings_mismatches = Vec::new();
    let mut variants = Vec::new();
    let mut add_variant = |mut run: RunRecord, refusal| {
        run.id = Uuid::new_v4();
        settings_mismatches.push((run.id, refusal));
        variants.push(run);
    };

    let mut changed = head.clone();
    changed.harness_rev = None;
    add_variant(changed, ComparabilityRefusal::MissingHarnessSource);
    let mut changed = head.clone();
    changed.harness_rev = Some("d".repeat(64));
    add_variant(changed, ComparabilityRefusal::DifferentHarnessSource);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().sanitizer = Sanitizer::Memory;
    add_variant(changed, ComparabilityRefusal::DifferentSanitizer);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().duration =
        Some(std::time::Duration::from_secs(60) + std::time::Duration::from_nanos(1));
    add_variant(changed, ComparabilityRefusal::DifferentDuration);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().max_mem_mb = 4096;
    add_variant(changed, ComparabilityRefusal::DifferentMemoryLimit);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().max_cpus = 2;
    add_variant(changed, ComparabilityRefusal::DifferentCpuLimit);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().extra_args = vec!["-runs=1".to_owned()];
    add_variant(changed, ComparabilityRefusal::DifferentEngineArguments);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().env = vec![("MODE".to_owned(), "strict".to_owned())];
    add_variant(changed, ComparabilityRefusal::DifferentEngineEnvironment);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().seed = Some(8);
    add_variant(changed, ComparabilityRefusal::DifferentRandomSeed);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().duration = None;
    add_variant(changed, ComparabilityRefusal::MissingRunSettings);
    let mut changed = head.clone();
    changed.config.as_mut().unwrap().harness_id = Uuid::new_v4();
    add_variant(changed, ComparabilityRefusal::MissingHarness);

    for run in [&base, &head, &incomparable] {
        store.insert_run(run).await.unwrap();
    }
    for run in &variants {
        store.insert_run(run).await.unwrap();
    }

    let crash = |run_id: Uuid, signature: &str| Crash {
        id: Uuid::new_v4(),
        run_id,
        target_id: target.id,
        input_path: PathBuf::from("runs/input/crash"),
        stack_signature: signature.to_owned(),
        kind: CrashKind::Asan,
        summary: "overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Target,
    };
    for c in [crash(base.id, "shared"), crash(base.id, "gone")] {
        store.upsert_crash(&c).await.unwrap();
    }
    for c in [crash(head.id, "shared"), crash(head.id, "fresh")] {
        store.upsert_crash(&c).await.unwrap();
    }

    Fixture {
        container: ServiceContainer::stubbed().with_store(store),
        target_id: target.id,
        base_run: base.id,
        head_run: head.id,
        incomparable_run: incomparable.id,
        settings_mismatches,
        project,
    }
}

#[tokio::test]
async fn a_supplied_diff_maps_to_affected_targets_and_a_baseline_plan() {
    let fixture = fixture().await;
    let view = fixture
        .container
        .change_impact(ChangeImpactRequest {
            project: fixture.project.path().display().to_string(),
            revisions: None,
            diff: Some(PARSER_DIFF.to_owned()),
        })
        .await
        .expect("a supplied diff needs no checkout");

    assert_eq!(view.files.len(), 1);
    assert_eq!(view.files[0].new_path.as_deref(), Some("parser.c"));

    let affected = view
        .affected
        .iter()
        .find(|entry| entry.target_id == fixture.target_id)
        .expect("the changed target is classified");
    assert_eq!(affected.impact, TargetImpact::Changed);
    assert!(!affected.approximate);

    // The plan names a retained baseline run rather than starting anything.
    let planned = view
        .plan
        .iter()
        .find(|entry| entry.target_id == fixture.target_id)
        .expect("the affected target is planned");
    assert!(planned.baseline_run_id.is_some());
}

#[tokio::test]
async fn comparable_runs_classify_findings_and_report_the_coverage_drop() {
    let fixture = fixture().await;
    let view = fixture
        .container
        .compare_revisions(RevisionComparisonRequest {
            base_run_id: fixture.base_run,
            head_run_id: fixture.head_run,
            regression_threshold_pct: 5.0,
        })
        .await
        .expect("the pair is comparable");

    assert!(view.comparable);
    assert_eq!(view.refusal, None);

    let change = |signature: &str| {
        view.findings
            .iter()
            .find(|entry| entry.stack_signature == signature)
            .map(|entry| entry.change)
            .expect("signature is classified")
    };
    assert_eq!(change("fresh"), FindingChange::ObservedOnlyInHead);
    assert_eq!(change("shared"), FindingChange::ObservedInBoth);
    assert_eq!(change("gone"), FindingChange::ObservedOnlyInBase);

    assert_eq!(
        view.coverage,
        CoverageComparison::Regressed { delta_pct: -10.0 }
    );
}

#[tokio::test]
async fn retained_harness_source_and_run_settings_must_match() {
    let fixture = fixture().await;
    for (head_run_id, expected) in fixture.settings_mismatches {
        let view = fixture
            .container
            .compare_revisions(RevisionComparisonRequest {
                base_run_id: fixture.base_run,
                head_run_id,
                regression_threshold_pct: 5.0,
            })
            .await
            .expect("an evidence mismatch is a comparison refusal");
        assert!(!view.comparable);
        assert_eq!(view.refusal, Some(expected));
    }
}

#[test]
fn defectdojo_document_qualifies_head_only_observations_with_comparison_evidence() {
    let base_run_id = Uuid::new_v4();
    let head_run_id = Uuid::new_v4();
    let comparison = RevisionComparisonView {
        schema_version: 2,
        base_run_id,
        head_run_id,
        comparable: true,
        refusal: None,
        findings: Vec::new(),
        coverage: CoverageComparison::Regressed { delta_pct: -10.0 },
    };
    let crash_id = Uuid::new_v4();
    let crash = Crash {
        id: crash_id,
        run_id: head_run_id,
        target_id: Uuid::new_v4(),
        input_path: PathBuf::from("runs/input/crash"),
        stack_signature: "head-only".to_owned(),
        kind: CrashKind::Asan,
        summary: "overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Target,
    };

    let document = change_comparison_defectdojo_document(&comparison, &[crash]);
    let finding = &document["findings"][0];
    assert_eq!(finding["unique_id_from_tool"], "head-only");
    assert_eq!(finding["vuln_id_from_tool"], crash_id.to_string());
    assert!(finding["title"]
        .as_str()
        .unwrap()
        .contains("observed only in head"));
    let description = finding["description"].as_str().unwrap();
    assert!(description.contains("overflow"));
    assert!(description.contains(&base_run_id.to_string()));
    assert!(description.contains(&head_run_id.to_string()));
    assert!(description.contains("measured coverage drop of 10.00%"));
    assert!(description.contains("does not establish that the source change introduced"));
}

#[tokio::test]
async fn an_incomparable_pair_refuses_instead_of_inventing_a_verdict() {
    let fixture = fixture().await;
    let view = fixture
        .container
        .compare_revisions(RevisionComparisonRequest {
            base_run_id: fixture.base_run,
            head_run_id: fixture.incomparable_run,
            regression_threshold_pct: 5.0,
        })
        .await
        .expect("an incomparable pair is a result, not an error");

    assert!(!view.comparable);
    assert_eq!(view.refusal, Some(ComparabilityRefusal::SameSourceRevision));
    assert!(
        view.findings.is_empty(),
        "an incomparable pair classifies nothing"
    );
    assert_eq!(view.coverage, CoverageComparison::Unavailable);
}

#[tokio::test]
async fn revision_arguments_that_could_reach_the_git_command_line_are_refused() {
    let fixture = fixture().await;
    for revision in [
        "--upload-pack=touch /tmp/pwned",
        "-o",
        "main..other",
        "main;rm -rf /",
        "",
    ] {
        let error = fixture
            .container
            .change_impact(ChangeImpactRequest {
                project: fixture.project.path().display().to_string(),
                revisions: Some(hf_service::RevisionRange {
                    base: revision.to_owned(),
                    head: "main".to_owned(),
                }),
                diff: None,
            })
            .await
            .expect_err("an unsafe revision never reaches git");
        assert!(
            error.to_string().contains("revision"),
            "the refusal names the revision: {error}"
        );
    }
}

#[tokio::test]
async fn publishing_is_refused_before_authorization_when_the_pair_is_incomparable() {
    use hf_guardrails::{DenyAll, GuardrailPolicy, Guardrails, RiskTier};

    let fixture = fixture().await;
    // Even under a policy that denies everything, an incomparable pair is
    // refused on its own merits: there is no verdict to publish.
    let denied = ServiceContainer::stubbed()
        .with_store(Arc::clone(
            fixture.container.store().expect("fixture store"),
        ))
        .with_guardrails(Guardrails::new(
            GuardrailPolicy {
                auto_allow_max: RiskTier::Low,
                deny_at: Some(RiskTier::Low),
            },
            Arc::new(DenyAll),
        ));
    let error = denied
        .publish_change_comparison(hf_service::PublishComparisonRequest {
            base_run_id: fixture.base_run,
            head_run_id: fixture.incomparable_run,
            regression_threshold_pct: 5.0,
            destination: hf_service::PublishDestination::IssueTracker,
        })
        .await
        .expect_err("an incomparable pair carries no verdict to publish");
    assert!(
        error.to_string().contains("incomparable"),
        "the refusal names incomparability, not the guardrail: {error}"
    );
}

#[tokio::test]
async fn publishing_a_real_comparison_requires_guardrail_authorization() {
    use hf_guardrails::{DenyAll, GuardrailPolicy, Guardrails, RiskTier};

    let fixture = fixture().await;
    let denied = ServiceContainer::stubbed()
        .with_store(Arc::clone(
            fixture.container.store().expect("fixture store"),
        ))
        .with_guardrails(Guardrails::new(
            GuardrailPolicy {
                auto_allow_max: RiskTier::Low,
                deny_at: Some(RiskTier::Low),
            },
            Arc::new(DenyAll),
        ));
    let error = denied
        .publish_change_comparison(hf_service::PublishComparisonRequest {
            base_run_id: fixture.base_run,
            head_run_id: fixture.head_run,
            regression_threshold_pct: 5.0,
            destination: hf_service::PublishDestination::IssueTracker,
        })
        .await
        .expect_err("publication is outward-facing and never automatic");
    assert!(
        error.to_string().contains("guardrail"),
        "the refusal names the guardrail: {error}"
    );
}
