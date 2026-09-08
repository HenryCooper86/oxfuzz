#![cfg(feature = "triage-disposition")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{Duration, Utc};
use hf_core::crash::{BugReport, CasrReport, Crash, CrashKind, CrashOrigin, CrashSeverity};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{
    CasrExploitabilityDetermination, FindingDispositionFilter, FindingReviewFilter,
    ServiceContainer,
};
use hf_storage::{RunRecord, RunStatus, Store};
use uuid::Uuid;

fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_finding_review_workspace_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        hf_service::initialize_workspace_root().unwrap();
    });
}

async fn fixture() -> (
    ServiceContainer,
    tempfile::TempDir,
    TargetCandidate,
    Harness,
) {
    isolate_workspace();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("findings.db"))
            .await
            .unwrap(),
    );
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from("/project-a"),
        language: TargetLanguage::C,
        symbol: "parse_packet".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/parser.c"),
            line: 12,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 5,
        fit_score: 0.9,
        sanitizers: vec![Sanitizer::Address],
        rationale: "fixture".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_packet"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    (container, directory, target, harness)
}

fn run(project: &str, harness_id: Uuid, engine: EngineKind, offset_minutes: i64) -> RunRecord {
    let mut run = RunRecord::new(
        project,
        engine,
        Some(FuzzRunConfig {
            harness_id,
            engine,
            duration: None,
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
        }),
        Utc::now() + Duration::minutes(offset_minutes),
    );
    run.status = RunStatus::Done;
    run.ended_at = Some(run.started_at + Duration::seconds(30));
    run
}

fn crash(run: &RunRecord, target: &TargetCandidate, origin: CrashOrigin) -> Crash {
    Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target.id,
        input_path: PathBuf::from(format!("runs/{}/crashes/input", run.id)),
        stack_signature: Uuid::new_v4().to_string(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
        origin,
    }
}

#[tokio::test]
async fn historical_detail_resolves_the_crash_original_run_and_action_scope() {
    let (container, _directory, target, harness) = fixture().await;
    let store = container.store().unwrap();
    let old = run("/project-a", harness.id, EngineKind::AflPlusPlus, -5);
    let latest = run("/project-a", harness.id, EngineKind::LibFuzzer, 0);
    store.insert_run(&old).await.unwrap();
    store.insert_run(&latest).await.unwrap();
    let old_crash = crash(&old, &target, CrashOrigin::Target);
    store.upsert_crash(&old_crash).await.unwrap();

    let item = container
        .finding_review_for_project(Path::new("/project-a"), old_crash.id)
        .await
        .unwrap();

    assert_eq!(item.crash.id, old_crash.id);
    assert_eq!(item.crash.run_id, old.id);
    assert_eq!(item.engine, EngineKind::AflPlusPlus);
    assert_eq!(item.project_root, "/project-a");
    assert_eq!(item.target_id, target.id);
    assert_eq!(item.target_symbol, "parse_packet");
    assert_eq!(item.target_selector, "parse_packet");
    assert_eq!(item.target_language, TargetLanguage::C);
    assert!(!item.latest_scoped_actions_allowed);
    assert!(item
        .latest_scoped_action_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("historical")));
}

#[tokio::test]
async fn latest_duplicate_symbol_actions_use_each_retained_qualified_selector() {
    let (container, directory, mut target, harness) = fixture().await;
    target.project_root = directory.path().to_path_buf();
    let mut alternate = target.clone();
    alternate.id = Uuid::new_v4();
    alternate.location.file = PathBuf::from("src/alternate.c");
    let mut alternate_harness = harness.clone();
    alternate_harness.id = Uuid::new_v4();
    alternate_harness.target_id = alternate.id;
    let store = container.store().unwrap();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_target(&alternate, Utc::now()).await.unwrap();
    store.upsert_harness(&alternate_harness).await.unwrap();
    let project = directory.path().to_str().unwrap();
    let mut primary_run = run(project, harness.id, EngineKind::LibFuzzer, 0);
    primary_run.config.as_mut().unwrap().seed_corpus = Some(
        hf_service::workspace_dir(directory.path(), "src/parser.c::parse_packet").join("corpus"),
    );
    let mut alternate_run = run(project, alternate_harness.id, EngineKind::LibFuzzer, 0);
    alternate_run.config.as_mut().unwrap().seed_corpus = Some(
        hf_service::workspace_dir(directory.path(), "src/alternate.c::parse_packet").join("corpus"),
    );
    store.insert_run(&primary_run).await.unwrap();
    store.insert_run(&alternate_run).await.unwrap();
    store
        .upsert_crash(&crash(&primary_run, &target, CrashOrigin::Target))
        .await
        .unwrap();
    store
        .upsert_crash(&crash(&alternate_run, &alternate, CrashOrigin::Target))
        .await
        .unwrap();

    let items = container
        .finding_review_queue(directory.path(), FindingReviewFilter::default())
        .await
        .unwrap();
    let primary = items
        .iter()
        .find(|item| item.target_id == target.id)
        .unwrap();
    let other = items
        .iter()
        .find(|item| item.target_id == alternate.id)
        .unwrap();
    assert_eq!(primary.target_selector, "src/parser.c::parse_packet");
    assert_eq!(other.target_selector, "src/alternate.c::parse_packet");
    assert!(primary.latest_scoped_actions_allowed);
    assert!(other.latest_scoped_actions_allowed);

    container
        .generate_report_for_run(
            directory.path(),
            &primary.target_selector,
            hf_service::ReportLanguage::En,
            Some(primary_run.id),
        )
        .await
        .unwrap();
    let publish_error = container
        .push_to_defectdojo_for_run(
            directory.path(),
            Some(&other.target_selector),
            Some(alternate_run.id),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(!publish_error.contains("ambiguous"));
    assert!(publish_error.contains("DefectDojo") || publish_error.contains("defectdojo"));
}

#[tokio::test]
async fn latest_reproduction_uses_the_retained_qualified_workspace_source() {
    let (container, directory, mut target, harness) = fixture().await;
    target.project_root = directory.path().to_path_buf();
    let store = container.store().unwrap();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let selector = "src/parser.c::parse_packet";
    let qualified_workspace = hf_service::workspace_dir(directory.path(), selector);
    let bare_workspace = hf_service::workspace_dir(directory.path(), &target.symbol);
    std::fs::create_dir_all(&qualified_workspace).unwrap();
    std::fs::create_dir_all(&bare_workspace).unwrap();
    std::fs::write(
        qualified_workspace.join("harness.source"),
        "qualified retained harness source",
    )
    .unwrap();
    std::fs::write(
        bare_workspace.join("harness.source"),
        "unrelated bare workspace source",
    )
    .unwrap();
    let mut retained = run(
        directory.path().to_str().unwrap(),
        harness.id,
        EngineKind::LibFuzzer,
        0,
    );
    retained.config.as_mut().unwrap().seed_corpus = Some(qualified_workspace.join("corpus"));
    store.insert_run(&retained).await.unwrap();
    let mut finding = crash(&retained, &target, CrashOrigin::Target);
    finding.input_path = directory.path().join("qualified-crash-input");
    std::fs::write(&finding.input_path, b"crash bytes").unwrap();
    store.upsert_crash(&finding).await.unwrap();
    let destination = directory.path().join("reproduction");

    let bundle = container
        .export_repro_bundle_for_latest(
            directory.path(),
            &target.symbol,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            Some(&finding.id.to_string()),
            &destination,
        )
        .await
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(bundle.join("harness.c")).unwrap(),
        "qualified retained harness source"
    );
}

#[tokio::test]
async fn queue_requires_persistence_but_an_empty_store_is_a_valid_empty_queue() {
    let without_store = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let error = without_store
        .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("requires persistent storage"));

    let (with_store, _directory, _target, _harness) = fixture().await;
    let empty = with_store
        .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
        .await
        .unwrap();
    assert!(empty.is_empty());
}

#[test]
fn a_partial_wire_filter_defaults_to_open() {
    let filter: FindingReviewFilter = serde_json::from_value(serde_json::json!({
        "origin": "target"
    }))
    .unwrap();
    assert_eq!(filter.disposition, FindingDispositionFilter::Open);
    assert!(
        serde_json::from_value::<FindingReviewFilter>(serde_json::json!({
            "disposition": { "mode": "bogus" }
        }))
        .is_err()
    );
}

#[tokio::test]
async fn selected_latest_actions_reject_a_run_that_became_historical() {
    let (container, directory, mut target, harness) = fixture().await;
    target.project_root = directory.path().to_path_buf();
    let store = container.store().unwrap();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let project = directory.path().to_string_lossy().into_owned();
    let selected = run(&project, harness.id, EngineKind::LibFuzzer, -5);
    let newer = run(&project, harness.id, EngineKind::LibFuzzer, 0);
    store.insert_run(&selected).await.unwrap();
    store.insert_run(&newer).await.unwrap();
    let retained = crash(&selected, &target, CrashOrigin::Target);
    store.upsert_crash(&retained).await.unwrap();

    let report_error = container
        .generate_report_for_run(
            directory.path(),
            "parse_packet",
            hf_service::ReportLanguage::En,
            Some(selected.id),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(report_error.contains("no longer latest"));
    assert!(report_error.contains(&newer.id.to_string()));

    let publish_error = container
        .push_to_defectdojo_for_run(directory.path(), Some("parse_packet"), Some(selected.id))
        .await
        .unwrap_err()
        .to_string();
    assert!(publish_error.contains("no longer latest"));
    assert!(publish_error.contains(&newer.id.to_string()));
}

#[tokio::test]
async fn default_queue_keeps_report_drafts_open_and_filters_deterministically() {
    let (container, _directory, target, harness) = fixture().await;
    let store = container.store().unwrap();
    let run = run("/project-a", harness.id, EngineKind::LibFuzzer, 0);
    store.insert_run(&run).await.unwrap();

    let mut report_draft = crash(&run, &target, CrashOrigin::Target);
    report_draft.id = Uuid::from_u128(20);
    report_draft.bug_report = Some(BugReport {
        title: "draft".to_owned(),
        summary: "draft".to_owned(),
        repro_steps: "draft".to_owned(),
        stack: "draft".to_owned(),
        severity_guess: "unknown".to_owned(),
        root_cause: None,
        suggested_fix: None,
    });
    let mut harness_fault = crash(&run, &target, CrashOrigin::Harness);
    harness_fault.id = Uuid::from_u128(10);
    harness_fault.casr = Some(CasrReport {
        severity: CrashSeverity::Exploitable,
        severity_short: "write".to_owned(),
        crashline: "harness.c:1".to_owned(),
        stack: Vec::new(),
        cluster: None,
    });
    store.upsert_crash(&report_draft).await.unwrap();
    store.upsert_crash(&harness_fault).await.unwrap();

    let open = container
        .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
        .await
        .unwrap();
    assert_eq!(open.len(), 2, "a report draft is still unresolved");
    assert_eq!(open[0].crash.id, report_draft.id);

    let filtered = container
        .finding_review_queue(
            Path::new("/project-a"),
            FindingReviewFilter {
                origin: Some(CrashOrigin::Harness),
                severity: Some(CasrExploitabilityDetermination::Exploitable),
                disposition: FindingDispositionFilter::All,
                ..FindingReviewFilter::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].crash.id, harness_fault.id);
}

#[tokio::test]
async fn detail_rejects_wrong_project_and_names_missing_durable_records() {
    let (container, _directory, target, harness) = fixture().await;
    let store = container.store().unwrap();
    let run = run("/project-a", harness.id, EngineKind::LibFuzzer, 0);
    store.insert_run(&run).await.unwrap();
    let retained = crash(&run, &target, CrashOrigin::Target);
    store.upsert_crash(&retained).await.unwrap();

    let wrong_project = container
        .finding_review_for_project(Path::new("/project-b"), retained.id)
        .await
        .unwrap_err()
        .to_string();
    assert!(wrong_project.contains("belongs to project"));

    let missing = container
        .finding_review_for_project(Path::new("/project-a"), Uuid::new_v4())
        .await
        .unwrap_err()
        .to_string();
    assert!(missing.contains("finding"));
    assert!(missing.contains("not found"));
}

#[tokio::test]
async fn queue_names_a_missing_run_referenced_by_a_project_finding() {
    let (container, _directory, target, _harness) = fixture().await;
    let orphan = Crash {
        id: Uuid::new_v4(),
        run_id: Uuid::new_v4(),
        target_id: target.id,
        input_path: PathBuf::from("orphan-input"),
        stack_signature: "orphan".to_owned(),
        kind: CrashKind::Asan,
        summary: "orphan".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Target,
    };
    container
        .store()
        .unwrap()
        .upsert_crash(&orphan)
        .await
        .unwrap();

    let error = container
        .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing run"));
    assert!(error.contains(&orphan.run_id.to_string()));
}

#[tokio::test]
async fn queue_names_a_missing_target_referenced_by_a_project_run() {
    let (container, _directory, _target, harness) = fixture().await;
    let run = run("/project-a", harness.id, EngineKind::LibFuzzer, 0);
    let missing_target = Uuid::new_v4();
    let retained = Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: missing_target,
        input_path: PathBuf::from("missing-target-input"),
        stack_signature: "missing-target".to_owned(),
        kind: CrashKind::Asan,
        summary: "missing target".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Target,
    };
    let store = container.store().unwrap();
    store.insert_run(&run).await.unwrap();
    store.upsert_crash(&retained).await.unwrap();

    let error = container
        .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing target"));
    assert!(error.contains(&missing_target.to_string()));
}

#[tokio::test]
async fn queue_names_a_missing_harness_referenced_by_a_project_run() {
    let (container, _directory, target, _harness) = fixture().await;
    let missing_harness = Uuid::new_v4();
    let run = run("/project-a", missing_harness, EngineKind::LibFuzzer, 0);
    let retained = crash(&run, &target, CrashOrigin::Target);
    let store = container.store().unwrap();
    store.insert_run(&run).await.unwrap();
    store.upsert_crash(&retained).await.unwrap();

    let error = container
        .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing harness"));
    assert!(error.contains(&missing_harness.to_string()));
}

#[tokio::test]
async fn issue_export_rejects_a_crash_owned_by_another_project() {
    let (container, _directory, target, harness) = fixture().await;
    let store = container.store().unwrap();
    let run = run("/project-a", harness.id, EngineKind::LibFuzzer, 0);
    store.insert_run(&run).await.unwrap();
    let retained = crash(&run, &target, CrashOrigin::Target);
    store.upsert_crash(&retained).await.unwrap();

    let error = container
        .issue_export(Path::new("/project-b"), &retained.id.to_string())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("belongs to project"));
}

#[cfg(feature = "patch-to-proof")]
#[tokio::test]
async fn proof_card_read_rejects_a_finding_owned_by_another_project() {
    let (container, _directory, target, harness) = fixture().await;
    let store = container.store().unwrap();
    let run = run("/project-a", harness.id, EngineKind::LibFuzzer, 0);
    store.insert_run(&run).await.unwrap();
    let retained = crash(&run, &target, CrashOrigin::Target);
    store.upsert_crash(&retained).await.unwrap();

    let error = container
        .finding_proof_card_for_crash(Path::new("/project-b"), retained.id)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("belongs to project"));
}

#[tokio::test]
#[ignore = "manual actual-service profile; no CI timing threshold"]
async fn profile_retained_multi_target_finding_queue() {
    let (container, _directory, template_target, template_harness) = fixture().await;
    let store = container.store().unwrap();
    // Eighty active targets, twenty with findings, and twenty retained runs each.
    // A second project carries the same amount of unrelated retained history.
    for project in ["/project-a", "/project-b"] {
        for index in 0..80 {
            let mut target = template_target.clone();
            target.id = Uuid::new_v4();
            target.project_root = PathBuf::from(project);
            target.symbol = format!("parse_{index}");
            let mut harness = template_harness.clone();
            harness.id = Uuid::new_v4();
            harness.target_id = target.id;
            store.upsert_target(&target, Utc::now()).await.unwrap();
            store.upsert_harness(&harness).await.unwrap();
            for age in 0..20 {
                let retained = run(project, harness.id, EngineKind::LibFuzzer, -age);
                store.insert_run(&retained).await.unwrap();
                if index < 20 && age % 5 == 0 {
                    store
                        .upsert_crash(&crash(&retained, &target, CrashOrigin::Target))
                        .await
                        .unwrap();
                }
            }
        }
    }
    for sample in 0..6 {
        let start = std::time::Instant::now();
        let items = container
            .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(items.len(), 80);
        assert_eq!(
            items
                .iter()
                .filter(|item| item.latest_scoped_actions_allowed)
                .count(),
            20
        );
        eprintln!("queue_profile sample={sample} targets=161 runs=3200 findings=160 selected_findings=80 debug_assertions={} elapsed_us={}", cfg!(debug_assertions), elapsed.as_micros());
    }
}

#[tokio::test]
async fn queue_does_not_resolve_latest_runs_for_targets_without_findings() {
    let (container, _directory, _target, _harness) = fixture().await;
    let unrelated = run("/project-a", Uuid::new_v4(), EngineKind::LibFuzzer, 0);
    container
        .store()
        .unwrap()
        .insert_run(&unrelated)
        .await
        .unwrap();
    assert!(container
        .finding_review_queue(Path::new("/project-a"), FindingReviewFilter::default())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn queue_stops_before_older_missing_harness_but_rejects_one_before_last_match() {
    let (container, directory, mut target, harness) = fixture().await;
    target.project_root = directory.path().to_path_buf();
    let store = container.store().unwrap();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let project = directory.path().to_str().unwrap();
    let latest = run(project, harness.id, EngineKind::LibFuzzer, 0);
    let older = run(project, Uuid::new_v4(), EngineKind::LibFuzzer, -10);
    store.insert_run(&latest).await.unwrap();
    store.insert_run(&older).await.unwrap();
    let finding = crash(&latest, &target, CrashOrigin::Target);
    store.upsert_crash(&finding).await.unwrap();
    let queue = container
        .finding_review_queue(directory.path(), FindingReviewFilter::default())
        .await
        .unwrap();
    assert!(queue[0].latest_scoped_actions_allowed);
    container
        .generate_report_for_run(
            directory.path(),
            &target.symbol,
            hf_service::ReportLanguage::En,
            Some(latest.id),
        )
        .await
        .unwrap();

    let mut second = target.clone();
    second.id = Uuid::new_v4();
    second.symbol = "second_parser".into();
    let mut second_harness = harness.clone();
    second_harness.id = Uuid::new_v4();
    second_harness.target_id = second.id;
    store.upsert_target(&second, Utc::now()).await.unwrap();
    store.upsert_harness(&second_harness).await.unwrap();
    let second_run = run(project, second_harness.id, EngineKind::LibFuzzer, -20);
    store.insert_run(&second_run).await.unwrap();
    store
        .upsert_crash(&crash(&second_run, &second, CrashOrigin::Target))
        .await
        .unwrap();
    let error = container
        .finding_review_queue(directory.path(), FindingReviewFilter::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing harness"));
    assert!(error.contains(&older.id.to_string()));
    let report_error = container
        .generate_report_for_run(
            directory.path(),
            &second.symbol,
            hf_service::ReportLanguage::En,
            Some(second_run.id),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(report_error.contains(&older.id.to_string()));
}

#[tokio::test]
async fn queue_and_report_share_failed_cancelled_selection_and_skip_active_missing_harness() {
    let (container, directory, mut target, harness) = fixture().await;
    target.project_root = directory.path().to_path_buf();
    let store = container.store().unwrap();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let project = directory.path().to_str().unwrap();
    let old = run(project, harness.id, EngineKind::LibFuzzer, -10);
    let mut latest = run(project, harness.id, EngineKind::LibFuzzer, -5);
    latest.status = RunStatus::Failed;
    let mut active = run(project, Uuid::new_v4(), EngineKind::LibFuzzer, 0);
    active.status = RunStatus::Running;
    active.ended_at = None;
    for item in [&old, &latest, &active] {
        store.insert_run(item).await.unwrap();
    }
    store
        .upsert_crash(&crash(&latest, &target, CrashOrigin::Target))
        .await
        .unwrap();
    for status in [RunStatus::Failed, RunStatus::Cancelled] {
        store
            .set_run_status(latest.id, status, latest.ended_at)
            .await
            .unwrap();
        let items = container
            .finding_review_queue(directory.path(), FindingReviewFilter::default())
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].latest_scoped_actions_allowed);
        assert_eq!(items[0].crash.run_id, latest.id);
        container
            .generate_report_for_run(
                directory.path(),
                &target.symbol,
                hf_service::ReportLanguage::En,
                Some(latest.id),
            )
            .await
            .unwrap();
    }
}
