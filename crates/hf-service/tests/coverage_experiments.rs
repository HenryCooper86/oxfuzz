//! Service experiment lifecycle over disposable retained evidence only.
use chrono::{Duration, Utc};
#[cfg(feature = "coverage-experiments")]
use hf_core::{engine::EngineKind, target::Sanitizer};
use hf_service::{coverage_experiments::*, ServiceContainer};
use hf_storage::{RunRecord, RunStatus, Store};
use std::sync::Arc;
#[cfg(feature = "coverage-experiments")]
use std::{path::PathBuf, time::Duration as StdDuration};
use uuid::Uuid;
#[path = "../src/test_support/retained_campaign.rs"]
mod retained_campaign_fixture;
use retained_campaign_fixture::retained_campaign as fixture;

async fn setup() -> (
    tempfile::TempDir,
    Arc<Store>,
    ServiceContainer,
    RunRecord,
    CreateCoverageExperimentRequest,
) {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().canonicalize().unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("experiments.db"))
            .await
            .unwrap(),
    );
    let run = fixture(
        &store,
        project.to_str().unwrap(),
        Utc::now() - Duration::seconds(120),
    )
    .await;
    let target_id = store
        .coverage_experiment_run_evidence(run.id)
        .await
        .unwrap()
        .target_id;
    let service = ServiceContainer::new(Arc::new(NoExecution), None).with_store(store.clone());
    let request = CreateCoverageExperimentRequest {
        project,
        target_id,
        baseline_run_id: run.id,
        kind: CoverageExperimentKind::GrowCorpus,
        goal_function: "parse_value".into(),
        hypothesis: "More seeds might reach the parser".into(),
        duration_secs: 60,
    };
    (dir, store, service, run, request)
}
fn scope(request: &CreateCoverageExperimentRequest) -> CoverageExperimentScope {
    CoverageExperimentScope {
        project: request.project.clone(),
        target_id: request.target_id,
    }
}
#[tokio::test]
async fn access_missing_storage_and_missing_ids_fail_explicitly() {
    let service = ServiceContainer::new(Arc::new(NoExecution), None);
    assert_eq!(
        service
            .coverage_experiment_owner(Uuid::new_v4())
            .await
            .unwrap_err()
            .code(),
        "storage_unavailable"
    );
    let (_dir, _store, service, _run, _) = setup().await;
    assert_eq!(
        service
            .coverage_experiment_owner(Uuid::new_v4())
            .await
            .unwrap_err()
            .code(),
        "not_found"
    );
}
#[test]
fn foreign_requests_reject_unknown_fields_noncanonical_ids_and_missing_nullable_fields() {
    let project = "/tmp";
    let target = Uuid::new_v4();
    let baseline = Uuid::new_v4();
    let valid = serde_json::json!({"project":project,"target_id":target,"baseline_run_id":baseline,"kind":"grow_corpus","goal_function":"parse","hypothesis":"More seeds", "duration_secs":60});
    assert!(serde_json::from_value::<CreateCoverageExperimentRequest>(valid.clone()).is_ok());
    for (field, value) in [
        ("unexpected", serde_json::json!(true)),
        ("project", serde_json::json!("/tmp/invalid\npath")),
        ("project", serde_json::json!("x".repeat(4097))),
        ("target_id", serde_json::json!(target.simple().to_string())),
        ("duration_secs", serde_json::json!(1.5)),
        ("hypothesis", serde_json::json!(" ")),
        ("goal_function", serde_json::json!("parse\n")),
    ] {
        let mut bad = valid.clone();
        bad[field] = value;
        assert!(
            serde_json::from_value::<CreateCoverageExperimentRequest>(bad).is_err(),
            "{field}"
        );
    }
    assert!(serde_json::from_value::<ListCoverageExperimentsRequest>(
        serde_json::json!({"project":project,"limit":10})
    )
    .is_err());
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn prepare_reopen_and_history_preserve_operator_intent_and_redact_public_values() {
    let (dir, store, service, run, request) = setup().await;
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    assert_eq!(created.status, CoverageExperimentStatus::Prepared);
    assert_eq!(created.baseline_run_id, run.id);
    let json = serde_json::to_value(&created).unwrap();
    assert_eq!(json["hypothesis_origin"], "operator_supplied");
    assert_eq!(json["baseline"]["seed"], u64::MAX.to_string());
    assert_eq!(json["baseline"]["max_mem_mb"], "1024");
    assert_eq!(json["baseline"]["edges"], "0");
    assert_eq!(
        json["baseline"]["engine_env"],
        serde_json::json!([["A", "[REDACTED]"], ["A", "[REDACTED]"]])
    );
    assert!(json["created_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(json["created_at"].as_str().unwrap().len(), 30);
    assert!(json["result"].is_null());
    sqlx::query("UPDATE runs SET edges = 42 WHERE id = ?")
        .bind(run.id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    let reopened = ServiceContainer::new(Arc::new(NoExecution), None).with_store(Arc::new(
        Store::connect(dir.path().join("experiments.db"))
            .await
            .unwrap(),
    ));
    assert_eq!(
        reopened
            .coverage_experiment(created.id, scope(&request))
            .await
            .unwrap(),
        created
    );
    let page = reopened
        .list_coverage_experiments(ListCoverageExperimentsRequest {
            project: request.project.clone(),
            target_id: Some(request.target_id),
            limit: 1,
            before: None,
        })
        .await
        .unwrap();
    assert_eq!(page.items, vec![created.clone()]);
    assert_eq!(
        store
            .coverage_experiment(created.id)
            .await
            .unwrap()
            .unwrap()
            .baseline
            .engine_env[0]
            .1,
        "secret"
    );
    assert_eq!(
        service
            .validate_coverage_experiment_scope(
                created.id,
                CoverageExperimentScope {
                    target_id: Uuid::new_v4(),
                    ..scope(&request)
                },
                None
            )
            .await
            .unwrap_err()
            .code(),
        "different_target"
    );
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn create_rejects_invalid_intent_policy_owner_and_baseline_without_inserting() {
    let (_dir, store, service, run, request) = setup().await;
    for (field, code) in [
        ("hypothesis", "invalid_request"),
        ("duration", "invalid_request"),
        ("target", "different_target"),
        ("budget", "different_run_settings"),
    ] {
        let mut bad = request.clone();
        match field {
            "hypothesis" => bad.hypothesis = " ".into(),
            "duration" => bad.duration_secs = 0,
            "target" => bad.target_id = Uuid::new_v4(),
            _ => bad.duration_secs = 61,
        }
        assert_eq!(
            service
                .create_coverage_experiment(bad)
                .await
                .unwrap_err()
                .code(),
            code,
            "{field}"
        );
    }
    sqlx::query("UPDATE runs SET status = 'running', ended_at = NULL WHERE id = ?")
        .bind(run.id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        service
            .create_coverage_experiment(request.clone())
            .await
            .unwrap_err()
            .code(),
        "invalid_baseline"
    );
    assert!(store
        .list_coverage_experiments(request.project.to_str().unwrap(), None, 100, None)
        .await
        .unwrap()
        .items
        .is_empty());
}

#[cfg(feature = "coverage-experiments")]
fn later(base: &RunRecord) -> RunRecord {
    let mut run = base.clone();
    run.id = Uuid::new_v4();
    run.started_at = Utc::now();
    run.ended_at = Some(run.started_at);
    run
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn completion_retains_unsuccessful_noop_legacy_attempt_and_exact_retry_without_source_refresh(
) {
    let (_dir, store, service, base, request) = setup().await;
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let mut run = later(&base);
    run.status = RunStatus::Failed;
    run.edges = None;
    store.insert_run(&run).await.unwrap();
    let attach = CompleteCoverageExperimentRequest {
        scope: scope(&request),
        result_run_id: run.id,
    };
    let completed = service
        .complete_coverage_experiment(created.id, attach.clone())
        .await
        .unwrap();
    assert_eq!(completed.status, CoverageExperimentStatus::Completed);
    let evidence = completed.result.as_ref().unwrap();
    assert_eq!(evidence.run.status, RunStatus::Failed);
    assert_eq!(
        evidence.input_change,
        CoverageExperimentInputChange::NoObservedInputChange
    );
    assert_eq!(
        evidence.build_comparison,
        CoverageExperimentBuildComparison::UnavailableLegacy
    );
    assert_eq!(
        evidence.limitations,
        vec![
            CoverageExperimentLimitation::AggregateEdgesNotFunctionEntry,
            CoverageExperimentLimitation::LegacyBuildInputsUnavailable,
            CoverageExperimentLimitation::NoObservedInputChange,
            CoverageExperimentLimitation::ResultEdgesUnavailable,
            CoverageExperimentLimitation::ResultFailed
        ]
    );
    sqlx::query("UPDATE runs SET source_rev = 'broken', edges = 987 WHERE id = ?")
        .bind(run.id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        service
            .complete_coverage_experiment(created.id, attach)
            .await
            .unwrap(),
        completed
    );
    assert_eq!(
        service
            .cancel_coverage_experiment(
                created.id,
                CancelCoverageExperimentRequest {
                    scope: scope(&request),
                    reason: "stop".into()
                }
            )
            .await
            .unwrap_err()
            .code(),
        "terminal_conflict"
    );
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn result_setting_mismatches_refuse_without_changing_any_prepared_field() {
    let (_dir, store, service, base, request) = setup().await;
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    for (field, code) in [
        ("source", "different_source"),
        ("sandbox", "different_sandbox"),
        ("memory", "different_run_settings"),
        ("cpu", "different_run_settings"),
        ("duration", "different_run_settings"),
        ("environment", "different_run_settings"),
        ("arguments", "different_run_settings"),
        ("seed", "different_run_settings"),
        ("binary", "different_harness"),
        ("chronology", "invalid_chronology"),
        ("status", "invalid_result"),
        ("kind", "invalid_result"),
    ] {
        let mut run = later(&base);
        match field {
            "source" => run.source_rev = Some("f".repeat(64)),
            "sandbox" => {
                run.sandbox_rev = Some(format!("docker-image-id-sha256:{}", "f".repeat(64)));
            }
            "memory" => run.config.as_mut().unwrap().max_mem_mb += 1,
            "cpu" => run.config.as_mut().unwrap().max_cpus += 1,
            "duration" => run.config.as_mut().unwrap().duration = Some(StdDuration::from_secs(61)),
            "environment" => run.config.as_mut().unwrap().env.reverse(),
            "arguments" => run.config.as_mut().unwrap().extra_args.reverse(),
            "seed" => run.config.as_mut().unwrap().seed = None,
            "binary" => run.binary_rev = Some("f".repeat(64)),
            "chronology" => {
                run.started_at = created.created_at;
                run.ended_at = Some(created.created_at);
            }
            "status" => run.status = RunStatus::Running,
            "kind" => run.kind = hf_storage::RunKind::Smoke,
            _ => unreachable!(),
        }
        store.insert_run(&run).await.unwrap();
        let error = service
            .complete_coverage_experiment(
                created.id,
                CompleteCoverageExperimentRequest {
                    scope: scope(&request),
                    result_run_id: run.id,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), code, "{field}: {error}");
        assert_eq!(
            service
                .coverage_experiment(created.id, scope(&request))
                .await
                .unwrap(),
            created,
            "{field}"
        );
        assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
    }
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn cancellation_and_competing_attachments_are_atomic_and_terminal() {
    let (_dir, store, service, base, request) = setup().await;
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let first = later(&base);
    let second = later(&base);
    store.insert_run(&first).await.unwrap();
    store.insert_run(&second).await.unwrap();
    let (a, b) = tokio::join!(
        service.complete_coverage_experiment(
            created.id,
            CompleteCoverageExperimentRequest {
                scope: scope(&request),
                result_run_id: first.id
            }
        ),
        service.complete_coverage_experiment(
            created.id,
            CompleteCoverageExperimentRequest {
                scope: scope(&request),
                result_run_id: second.id
            }
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let loser = if let Err(error) = a {
        error
    } else {
        b.unwrap_err()
    };
    assert_eq!(loser.code(), "terminal_conflict");
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let cancel = CancelCoverageExperimentRequest {
        scope: scope(&request),
        reason: "No remaining budget".into(),
    };
    let cancelled = service
        .cancel_coverage_experiment(created.id, cancel.clone())
        .await
        .unwrap();
    assert_eq!(cancelled.status, CoverageExperimentStatus::Cancelled);
    assert_eq!(
        service
            .cancel_coverage_experiment(created.id, cancel)
            .await
            .unwrap(),
        cancelled
    );
    assert_eq!(
        service
            .cancel_coverage_experiment(
                created.id,
                CancelCoverageExperimentRequest {
                    scope: scope(&request),
                    reason: "Changed".into()
                }
            )
            .await
            .unwrap_err()
            .code(),
        "terminal_conflict"
    );
}

#[tokio::test]
async fn retained_runs_refuse_deletion_and_history_clear_before_evidence_path_resolution() {
    let (_dir, store, service, base, request) = setup().await;
    let now = Utc::now();
    let record = hf_storage::CoverageExperimentRecord {
        id: Uuid::new_v4(),
        schema_version: 1,
        project_root: request.project.to_str().unwrap().into(),
        target_id: request.target_id,
        target_symbol: "parse_value".into(),
        baseline_run_id: base.id,
        kind: request.kind,
        goal_function: request.goal_function.clone(),
        hypothesis: request.hypothesis.clone(),
        duration_secs: 60,
        baseline: store
            .coverage_experiment_run_evidence(base.id)
            .await
            .unwrap(),
        status: CoverageExperimentStatus::Prepared,
        result: None,
        cancellation_reason: None,
        created_at: now,
        updated_at: now,
        ended_at: None,
    };
    store.insert_coverage_experiment(&record).await.unwrap();
    sqlx::query("UPDATE runs SET evidence_dir = '/outside/invalid' WHERE id = ?")
        .bind(base.id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    for error in [
        service.delete_run(&base.id.to_string()).await.unwrap_err(),
        service.clear_all_runs().await.unwrap_err(),
    ] {
        match error {
            hf_service::RunHistoryError::RunRetainedByExperiment {
                run_id,
                experiment_id,
                role,
            } => {
                assert_eq!(run_id, base.id);
                assert_eq!(experiment_id, record.id);
                assert_eq!(role, CoverageExperimentRunRole::Baseline);
            }
            other @ hf_service::RunHistoryError::Classified(_) => {
                panic!("expected typed retention before evidence path resolution, got {other}")
            }
        }
    }
    assert_eq!(
        service
            .coverage_experiment_owner(record.id)
            .await
            .unwrap()
            .target_id,
        request.target_id
    );
    service
        .validate_coverage_experiment_scope(record.id, scope(&request), None)
        .await
        .unwrap();
    assert!(store.get_run(base.id).await.unwrap().is_some());
    assert!(store
        .coverage_experiment(record.id)
        .await
        .unwrap()
        .is_some());
}

struct NoExecution;
#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for NoExecution {
    async fn run_command(
        &self,
        _cmd: &[String],
        _cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_service::ClassifiedError> {
        panic!("experiment dispatched runtime")
    }
    async fn image_present(&self, _image: &str) -> bool {
        panic!("experiment checked image")
    }
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_service::ClassifiedError>
    {
        panic!("experiment resolved image")
    }
    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_service::ClassifiedError> {
        panic!("experiment wrote runtime file")
    }
    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_service::ClassifiedError> {
        panic!("experiment read runtime file")
    }
}
#[cfg(feature = "coverage-experiments")]
async fn new_harness(store: &Store, run: &mut RunRecord, source: Option<&str>) {
    use sha2::Digest;
    let mut harness = store
        .get_harness(run.config.as_ref().unwrap().harness_id)
        .await
        .unwrap()
        .unwrap();
    harness.id = Uuid::new_v4();
    if let Some(source) = source {
        harness.source = source.into();
    }
    run.harness_rev = Some(hex::encode(sha2::Sha256::digest(harness.source.as_bytes())));
    run.config.as_mut().unwrap().harness_id = harness.id;
    store.upsert_harness(&harness).await.unwrap();
}
#[cfg(feature = "coverage-experiments")]
fn build_inputs(run: &RunRecord) -> hf_storage::HarnessBuildInputsRecord {
    let flags = "a".repeat(64);
    let image = format!("sha256:{}", "e".repeat(64));
    hf_storage::HarnessBuildInputsRecord {
        harness_id: run.config.as_ref().unwrap().harness_id,
        project_root: run.project_root.clone(),
        profile_sha256: None,
        compile_database_sha256: None,
        compile_flags_sha256: flags.clone(),
        sandbox_image_id: image.clone(),
        build_input_sha256: hf_storage::harness_build_input_sha256(None, None, &flags, &image)
            .unwrap(),
        created_at: run.started_at - Duration::seconds(1),
    }
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn captured_builds_compare_counts_as_decimal_strings_without_function_entry_claims() {
    let (_dir, store, service, base, request) = setup().await;
    store
        .set_harness_build_inputs(&build_inputs(&base))
        .await
        .unwrap();
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let mut run = later(&base);
    new_harness(&store, &mut run, None).await;
    run.corpus_rev = Some("f".repeat(64));
    run.edges = Some(i64::MAX as u64);
    run.config.as_mut().unwrap().seed_corpus = Some("/different-provenance".into());
    run.config.as_mut().unwrap().replay_of = Some(Uuid::new_v4());
    run.context_rev = Some("a".repeat(64));
    store
        .set_harness_build_inputs(&build_inputs(&run))
        .await
        .unwrap();
    store.insert_run(&run).await.unwrap();
    let completed = service
        .complete_coverage_experiment(
            created.id,
            CompleteCoverageExperimentRequest {
                scope: scope(&request),
                result_run_id: run.id,
            },
        )
        .await
        .unwrap();
    let evidence = completed.result.as_ref().unwrap();
    assert_eq!(
        evidence.input_change,
        CoverageExperimentInputChange::CorpusChanged
    );
    assert_eq!(
        evidence.build_comparison,
        CoverageExperimentBuildComparison::Matched
    );
    let json = serde_json::to_value(evidence).unwrap();
    assert_eq!(
        json["edge_comparison"],
        serde_json::json!({"status":"observed","baseline_edges":"0","result_edges":i64::MAX.to_string(),"delta":i64::MAX.to_string()})
    );
    assert_eq!(
        json["target_entry"],
        serde_json::json!({"status":"unavailable","reason_code":"no_exact_run_scoped_function_coverage"})
    );
    assert_eq!(
        evidence.limitations,
        vec![CoverageExperimentLimitation::AggregateEdgesNotFunctionEntry]
    );
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn refinement_allows_changed_source_equal_binary_and_mixed_build_presence_but_refuses_other_changes(
) {
    let (_dir, store, service, base, mut request) = setup().await;
    request.kind = CoverageExperimentKind::RefineHarness;
    for case in ["source", "noop", "binary", "corpus"] {
        let created = service
            .create_coverage_experiment(request.clone())
            .await
            .unwrap();
        let mut run = later(&base);
        new_harness(&store, &mut run, (case == "source").then_some("abcd")).await;
        if case == "binary" {
            run.binary_rev = Some("f".repeat(64));
        }
        if case == "corpus" {
            run.corpus_rev = Some("f".repeat(64));
        }
        store
            .set_harness_build_inputs(&build_inputs(&run))
            .await
            .unwrap();
        store.insert_run(&run).await.unwrap();
        let result = service
            .complete_coverage_experiment(
                created.id,
                CompleteCoverageExperimentRequest {
                    scope: scope(&request),
                    result_run_id: run.id,
                },
            )
            .await;
        match case {
            "binary" | "corpus" => {
                assert_eq!(
                    result.unwrap_err().code(),
                    if case == "binary" {
                        "unexpected_binary_change"
                    } else {
                        "different_corpus"
                    }
                );
                assert_eq!(
                    service
                        .coverage_experiment(created.id, scope(&request))
                        .await
                        .unwrap(),
                    created
                );
            }
            _ => {
                let evidence = result.unwrap().result.unwrap();
                assert_eq!(
                    evidence.build_comparison,
                    CoverageExperimentBuildComparison::UnavailableLegacy
                );
                assert_eq!(
                    evidence.input_change,
                    if case == "source" {
                        CoverageExperimentInputChange::HarnessSourceChanged
                    } else {
                        CoverageExperimentInputChange::NoObservedInputChange
                    }
                );
                assert_eq!(
                    evidence
                        .limitations
                        .contains(&CoverageExperimentLimitation::HarnessInstrumentationMayDiffer),
                    case == "source"
                );
            }
        }
    }
    request.kind = CoverageExperimentKind::GrowCorpus;
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let mut run = later(&base);
    new_harness(&store, &mut run, Some("abcd")).await;
    store.insert_run(&run).await.unwrap();
    assert_eq!(
        service
            .complete_coverage_experiment(
                created.id,
                CompleteCoverageExperimentRequest {
                    scope: scope(&request),
                    result_run_id: run.id
                }
            )
            .await
            .unwrap_err()
            .code(),
        "different_harness"
    );
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn captured_build_configuration_differences_are_refused_and_owner_metadata_is_not_compared() {
    let (_dir, store, service, base, request) = setup().await;
    store
        .set_harness_build_inputs(&build_inputs(&base))
        .await
        .unwrap();
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    for field in ["profile", "database", "flags"] {
        let mut run = later(&base);
        new_harness(&store, &mut run, None).await;
        let mut build = build_inputs(&run);
        match field {
            "profile" => {
                build.profile_sha256 = Some("f".repeat(64));
                build.compile_database_sha256 = Some("f".repeat(64));
            }
            "database" => build.compile_database_sha256 = Some("f".repeat(64)),
            "flags" => build.compile_flags_sha256 = "f".repeat(64),
            _ => unreachable!(),
        }
        build.build_input_sha256 = hf_storage::harness_build_input_sha256(
            build.profile_sha256.as_deref(),
            build.compile_database_sha256.as_deref(),
            &build.compile_flags_sha256,
            &build.sandbox_image_id,
        )
        .unwrap();
        store.set_harness_build_inputs(&build).await.unwrap();
        store.insert_run(&run).await.unwrap();
        assert_eq!(
            service
                .complete_coverage_experiment(
                    created.id,
                    CompleteCoverageExperimentRequest {
                        scope: scope(&request),
                        result_run_id: run.id
                    }
                )
                .await
                .unwrap_err()
                .code(),
            "different_build_inputs",
            "{field}"
        );
        assert_eq!(
            service
                .coverage_experiment(created.id, scope(&request))
                .await
                .unwrap(),
            created
        );
    }
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn terminal_baseline_statuses_missing_edges_and_seed_absence_retain_all_limitations() {
    for (baseline_status, result_status) in [
        ("failed", RunStatus::Cancelled),
        ("cancelled", RunStatus::Failed),
    ] {
        let (_dir, store, service, base, request) = setup().await;
        let mut config = base.config.clone().unwrap();
        config.seed = None;
        sqlx::query("UPDATE runs SET status = ?, config_json = ?, edges = NULL WHERE id = ?")
            .bind(baseline_status)
            .bind(serde_json::to_string(&config).unwrap())
            .bind(base.id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        store
            .set_harness_build_inputs(&build_inputs(&base))
            .await
            .unwrap();
        let created = service
            .create_coverage_experiment(request.clone())
            .await
            .unwrap();
        let mut run = later(&base);
        run.config = Some(config);
        run.status = result_status;
        run.edges = None;
        store.insert_run(&run).await.unwrap();
        let result = service
            .complete_coverage_experiment(
                created.id,
                CompleteCoverageExperimentRequest {
                    scope: scope(&request),
                    result_run_id: run.id,
                },
            )
            .await
            .unwrap()
            .result
            .unwrap();
        assert_eq!(
            result.edge_comparison,
            CoverageExperimentEdgeView::Unavailable {
                reason_code: CoverageExperimentEdgeUnavailableReason::BaselineEdgesUnavailable
            }
        );
        for limitation in [
            CoverageExperimentLimitation::BaselineEdgesUnavailable,
            CoverageExperimentLimitation::ResultEdgesUnavailable,
            CoverageExperimentLimitation::RandomSeedUnrecorded,
        ] {
            assert!(result.limitations.contains(&limitation));
        }
        assert!(result
            .limitations
            .contains(&if baseline_status == "failed" {
                CoverageExperimentLimitation::BaselineFailed
            } else {
                CoverageExperimentLimitation::BaselineCancelled
            }));
        assert!(result
            .limitations
            .contains(&if result_status == RunStatus::Failed {
                CoverageExperimentLimitation::ResultFailed
            } else {
                CoverageExperimentLimitation::ResultCancelled
            }));
    }
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn different_engine_sanitizer_target_and_project_are_refused_at_service_operation() {
    let (_dir, store, service, base, request) = setup().await;
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    for field in ["engine", "sanitizer", "target", "project"] {
        let mut run = later(&base);
        new_harness(&store, &mut run, None).await;
        let mut harness = store
            .get_harness(run.config.as_ref().unwrap().harness_id)
            .await
            .unwrap()
            .unwrap();
        match field {
            "engine" => {
                run.engine = EngineKind::Honggfuzz;
                run.config.as_mut().unwrap().engine = run.engine;
                harness.engine = run.engine;
            }
            "sanitizer" => {
                harness.sanitizer = Sanitizer::Undefined;
                run.config.as_mut().unwrap().sanitizer = harness.sanitizer;
            }
            "target" => {
                let mut target = store.list_all_targets().await.unwrap().remove(0);
                target.id = Uuid::new_v4();
                target.symbol = "another".into();
                store.upsert_target(&target, Utc::now()).await.unwrap();
                harness.target_id = target.id;
            }
            "project" => run.project_root = "/another-project".into(),
            _ => unreachable!(),
        }
        harness.id = Uuid::new_v4();
        run.config.as_mut().unwrap().harness_id = harness.id;
        store.upsert_harness(&harness).await.unwrap();
        store.insert_run(&run).await.unwrap();
        assert_eq!(
            service
                .complete_coverage_experiment(
                    created.id,
                    CompleteCoverageExperimentRequest {
                        scope: scope(&request),
                        result_run_id: run.id
                    }
                )
                .await
                .unwrap_err()
                .code(),
            match field {
                "engine" => "different_engine",
                "sanitizer" => "different_run_settings",
                "target" => "different_target",
                _ => "different_project",
            }
        );
        assert_eq!(
            service
                .coverage_experiment(created.id, scope(&request))
                .await
                .unwrap(),
            created
        );
    }
}

#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn honggfuzz_retained_seed_is_labeled_ignored_and_all_operations_make_zero_provider_calls() {
    let (_dir, store, _service, base, request) = setup().await;
    let provider = Arc::new(hf_test_utils::mock_provider::MockProvider::failing(
        "must never call",
    ));
    let pool = Arc::new(hf_provider::ProviderPoolImpl::from_providers(
        vec![provider.clone()],
        &hf_provider::ProviderPoolConfig::default(),
    ));
    let service =
        ServiceContainer::new(Arc::new(NoExecution), Some(pool)).with_store(store.clone());
    let mut base = base;
    let mut harness = store
        .get_harness(base.config.as_ref().unwrap().harness_id)
        .await
        .unwrap()
        .unwrap();
    harness.id = Uuid::new_v4();
    harness.engine = EngineKind::Honggfuzz;
    store.upsert_harness(&harness).await.unwrap();
    base.id = Uuid::new_v4();
    base.engine = harness.engine;
    base.config.as_mut().unwrap().engine = harness.engine;
    base.config.as_mut().unwrap().harness_id = harness.id;
    store.insert_run(&base).await.unwrap();
    let request = CreateCoverageExperimentRequest {
        baseline_run_id: base.id,
        ..request
    };
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let mut run = later(&base);
    run.edges = Some(0);
    store.insert_run(&run).await.unwrap();
    let result = service
        .complete_coverage_experiment(
            created.id,
            CompleteCoverageExperimentRequest {
                scope: scope(&request),
                result_run_id: run.id,
            },
        )
        .await
        .unwrap();
    assert!(result
        .result
        .as_ref()
        .unwrap()
        .limitations
        .contains(&CoverageExperimentLimitation::EngineIgnoresRetainedSeed));
    assert_eq!(
        service
            .coverage_experiment(created.id, scope(&request))
            .await
            .unwrap(),
        result
    );
    let page = service
        .list_coverage_experiments(ListCoverageExperimentsRequest {
            project: request.project.clone(),
            target_id: None,
            limit: 100,
            before: None,
        })
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    let pending = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    service
        .cancel_coverage_experiment(
            pending.id,
            CancelCoverageExperimentRequest {
                scope: scope(&request),
                reason: "Budget withdrawn".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(provider.call_count(), 0);
}
#[test]
fn typed_storage_failures_map_without_debug_or_secret_strings() {
    let id = Uuid::new_v4();
    for (storage, code) in [
        (
            hf_storage::StorageError::CoverageExperimentConflict { id },
            "terminal_conflict",
        ),
        (
            hf_storage::StorageError::CoverageExperimentSourceChanged { run_id: id },
            "source_evidence_changed",
        ),
        (
            hf_storage::StorageError::CoverageExperimentInvalidChronology,
            "invalid_chronology",
        ),
        (
            hf_storage::StorageError::CoverageExperimentMissingSetup { field: "config" },
            "missing_setup_evidence",
        ),
        (
            hf_storage::StorageError::InvalidData("secret contents".into()),
            "storage_error",
        ),
    ] {
        let error = CoverageExperimentError::from(storage);
        assert_eq!(error.code(), code);
        assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
    }
    let unavailable = CoverageExperimentError::new(CoverageExperimentErrorCode::FeatureUnavailable);
    assert_eq!(
        serde_json::to_value(unavailable).unwrap(),
        serde_json::json!({"code":"feature_unavailable","error":COVERAGE_EXPERIMENT_UNAVAILABLE})
    );
}
#[cfg(feature = "coverage-experiments")]
#[test]
fn creation_uses_current_policy_but_retained_lifecycle_does_not() {
    let config = tempfile::tempdir().unwrap();
    std::fs::write(config.path().join("oxfuzz.toml"), "").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "policy_change_child", "--ignored", "--nocapture"])
        .env("HF_CONFIG_DIR", config.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
#[ignore = "runs in an isolated process with a temporary configuration directory"]
async fn policy_change_child() {
    let (_dir, store, service, base, request) = setup().await;
    let created = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let pending = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let config = PathBuf::from(std::env::var_os("HF_CONFIG_DIR").unwrap()).join("oxfuzz.toml");
    for (engine, maximum) in [("libfuzzer", 1), ("honggfuzz", 7200)] {
        std::fs::write(&config,format!("[fuzzing]\nenabled_engines = [\"{engine}\"]\ndefault_engine = \"{engine}\"\ndefault_duration_secs = 1\n[fuzzing.sandbox]\nmax_duration_secs = {maximum}\nmax_mem_mb = 64\nmax_cpus = 1\n")).unwrap();
        assert_eq!(
            service
                .create_coverage_experiment(request.clone())
                .await
                .unwrap_err()
                .code(),
            "invalid_request"
        );
    }
    let run = later(&base);
    store.insert_run(&run).await.unwrap();
    let result = service
        .complete_coverage_experiment(
            created.id,
            CompleteCoverageExperimentRequest {
                scope: scope(&request),
                result_run_id: run.id,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.baseline.max_mem_mb, 1024);
    assert_eq!(
        service
            .coverage_experiment(created.id, scope(&request))
            .await
            .unwrap(),
        result
    );
    assert_eq!(
        service
            .list_coverage_experiments(ListCoverageExperimentsRequest {
                project: request.project.clone(),
                target_id: None,
                limit: 100,
                before: None
            })
            .await
            .unwrap()
            .items
            .len(),
        2
    );
    service
        .cancel_coverage_experiment(
            pending.id,
            CancelCoverageExperimentRequest {
                scope: scope(&request),
                reason: "Policy changed".into(),
            },
        )
        .await
        .unwrap();
}

#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn bounded_history_cursor_must_identify_an_existing_row_in_selected_scope() {
    let (_dir, _store, service, _base, request) = setup().await;
    let first = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let second = service
        .create_coverage_experiment(request.clone())
        .await
        .unwrap();
    let list = ListCoverageExperimentsRequest {
        project: request.project.clone(),
        target_id: Some(request.target_id),
        limit: 1,
        before: None,
    };
    let page = service
        .list_coverage_experiments(list.clone())
        .await
        .unwrap();
    assert_eq!(page.items[0].id, second.id);
    assert_eq!(
        service
            .list_coverage_experiments(ListCoverageExperimentsRequest {
                before: page.next_cursor,
                ..list.clone()
            })
            .await
            .unwrap()
            .items[0]
            .id,
        first.id
    );
    for before in [
        CoverageExperimentCursor {
            created_at: first.created_at,
            id: Uuid::new_v4(),
        },
        CoverageExperimentCursor {
            created_at: first.created_at + Duration::seconds(1),
            id: first.id,
        },
    ] {
        assert_eq!(
            service
                .list_coverage_experiments(ListCoverageExperimentsRequest {
                    before: Some(before),
                    ..list.clone()
                })
                .await
                .unwrap_err()
                .code(),
            "invalid_request"
        );
    }
}
#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn missing_setup_and_future_timestamps_never_become_default_evidence() {
    for field in ["config", "source", "end", "future"] {
        let (_dir, store, service, base, request) = setup().await;
        let query = match field {
            "config" => "UPDATE runs SET config_json = NULL WHERE id = ?",
            "source" => "UPDATE runs SET source_rev = NULL WHERE id = ?",
            "end" => "UPDATE runs SET ended_at = NULL WHERE id = ?",
            _ => "UPDATE runs SET ended_at = '9999-01-01T00:00:00Z' WHERE id = ?",
        };
        sqlx::query(query)
            .bind(base.id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            service
                .create_coverage_experiment(request)
                .await
                .unwrap_err()
                .code(),
            if field == "future" {
                "invalid_chronology"
            } else {
                "missing_setup_evidence"
            },
            "{field}"
        );
    }
}

#[test]
fn experiment_wire_ids_require_canonical_nonnil_version_four_uuid() {
    let id = Uuid::new_v4();
    assert_eq!(parse_coverage_experiment_id(&id.to_string()).unwrap(), id);
    for text in [
        id.simple().to_string(),
        id.to_string().to_uppercase(),
        Uuid::nil().to_string(),
        "00000000-0000-1000-8000-000000000001".into(),
        "00000000-0000-4000-0000-000000000001".into(),
        "not-an-id".into(),
    ] {
        assert_eq!(
            parse_coverage_experiment_id(&text).unwrap_err().code(),
            "invalid_request"
        );
    }
}

#[test]
fn project_access_validation_is_available_without_store_or_lifecycle() {
    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    assert_eq!(
        validate_coverage_experiment_project(&nested.join("..")).unwrap(),
        directory.path().canonicalize().unwrap()
    );
    let file = directory.path().join("file");
    std::fs::write(&file, b"data").unwrap();
    for path in [file, directory.path().join("missing")] {
        assert_eq!(
            validate_coverage_experiment_project(&path)
                .unwrap_err()
                .code(),
            "invalid_project_path"
        );
    }
}

#[test]
fn cursor_and_list_decode_require_experiment_ids_but_preserve_historical_target_ids() {
    let historical_id = "00000000-0000-1000-8000-000000000001";
    let valid_id = Uuid::new_v4();
    let cursor = serde_json::json!({
        "created_at": "2026-09-08T00:00:00.000000000Z",
        "id": valid_id,
    });
    let decoded: CoverageExperimentCursor = serde_json::from_value(cursor.clone()).unwrap();
    assert_eq!(decoded.id, valid_id);
    let list = serde_json::json!({
        "project": "/project",
        "target_id": historical_id,
        "limit": 1,
        "before": cursor,
    });
    let decoded: ListCoverageExperimentsRequest = serde_json::from_value(list.clone()).unwrap();
    assert_eq!(decoded.target_id, Some(historical_id.parse().unwrap()));
    assert_eq!(decoded.before.unwrap().id, valid_id);
    let create = serde_json::json!({
        "project": "/project", "target_id": historical_id, "baseline_run_id": historical_id,
        "kind": "grow_corpus", "goal_function": "parse", "hypothesis": "More seeds",
        "duration_secs": 60,
    });
    let decoded: CreateCoverageExperimentRequest = serde_json::from_value(create).unwrap();
    assert_eq!(
        decoded.baseline_run_id,
        historical_id.parse::<Uuid>().unwrap()
    );
    let acceptance: Vec<_> = [historical_id, "00000000-0000-4000-0000-000000000001"]
        .into_iter()
        .map(|malformed_id| {
            let mut malformed_cursor = cursor.clone();
            malformed_cursor["id"] = serde_json::json!(malformed_id);
            let mut malformed_list = list.clone();
            malformed_list["before"] = malformed_cursor.clone();
            (
                serde_json::from_value::<CoverageExperimentCursor>(malformed_cursor).is_ok(),
                serde_json::from_value::<ListCoverageExperimentsRequest>(malformed_list).is_ok(),
            )
        })
        .collect();
    assert_eq!(acceptance, vec![(false, false), (false, false)]);
}

#[tokio::test]
async fn run_history_retains_exact_target_identity_and_requested_budget() {
    let (_dir, store, service, run, request) = setup().await;
    let history = service.run_history(Some(&request.project)).await.unwrap();
    let item = history
        .iter()
        .find(|item| item.id == run.id.to_string())
        .unwrap();
    assert_eq!(item.target_id, Some(request.target_id));
    assert_eq!(item.requested_duration_secs, Some(60));
    let mut without_config = RunRecord::new(
        request.project.to_string_lossy(),
        run.engine,
        None,
        Utc::now(),
    );
    without_config.status = RunStatus::Failed;
    without_config.ended_at = Some(without_config.started_at + Duration::seconds(3));
    store.insert_run(&without_config).await.unwrap();
    let history = service.run_history(Some(&request.project)).await.unwrap();
    let item = history
        .iter()
        .find(|item| item.id == without_config.id.to_string())
        .unwrap();
    assert_eq!(item.duration_secs, Some(3));
    assert_eq!(item.target_id, None);
    assert_eq!(item.requested_duration_secs, None);
}
