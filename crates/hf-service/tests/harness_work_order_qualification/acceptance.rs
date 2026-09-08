//! Complete service workflow with inert runtime artifacts and explicit operator calls.
use super::*;
use hf_service::coverage_experiments::*;
use hf_service::{CloseoutStep, StepOutcome};
use hf_storage::{RunKind, RunStatus};
use tokio::sync::Notify;

struct CampaignRuntime {
    qualification: Arc<ControlledRuntime>,
    entered: Notify,
    release: Notify,
    campaigns: AtomicUsize,
}

#[async_trait::async_trait]
impl RuntimeAdapter for CampaignRuntime {
    async fn resolve_image_reference(
        &self,
        image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        self.qualification.resolve_image_reference(image).await
    }
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.qualification.run_command(cmd, cwd, limits).await
    }
    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        assert_eq!(
            limits.max_duration_secs, 120,
            "bounded 60-second campaign plus runtime grace"
        );
        self.campaigns.fetch_add(1, Ordering::SeqCst);
        let prefix = cmd
            .iter()
            .find_map(|arg| arg.strip_prefix("-artifact_prefix="))
            .expect("actual libFuzzer artifact argument");
        let output = cwd.join(
            prefix
                .strip_prefix("/work/")
                .expect("sandbox workspace path"),
        );
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("crash-acceptance"), b"synthetic crash input").unwrap();
        for _ in 0..32 {
            on_line("#100 NEW cov: 12 ft: 24 corp: 2/8b exec/s: 128");
        }
        self.entered.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(10), self.release.notified())
            .await
            .expect("test releases bounded fake campaign");
        self.qualification.command_result(cmd, cwd)
    }
    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        self.qualification.write_file(path, content).await
    }
    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        self.qualification.read_file(path).await
    }
}

async fn observe_active(
    service: &ServiceContainer,
    runtime: &CampaignRuntime,
) -> (Uuid, serde_json::Value) {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        runtime.entered.notified(),
    )
    .await
    .unwrap();
    let active = service.active_run_ids();
    assert_eq!(active.len(), 1);
    let id = active[0];
    let store = service.store().unwrap();
    let record = store.get_run(id).await.unwrap().unwrap();
    assert_eq!(record.kind, RunKind::Campaign);
    assert_eq!(record.status, RunStatus::Running);
    assert!(record.ended_at.is_none());
    let telemetry = service.campaign_telemetry(id).await.unwrap();
    assert_eq!(telemetry.run_id, id);
    assert_eq!(telemetry.edges, Some(12));
    assert_eq!(telemetry.mean_execs, Some(128.0));
    assert_eq!(telemetry.managed_invocations_alive, 1);
    service
        .assess_and_emit_campaign_health(id, Utc::now())
        .await
        .unwrap();
    let events = service.campaign_health_events(id).await.unwrap();
    assert!(events
        .iter()
        .any(|event| event.condition
            == hf_service::campaign_health::HealthCondition::CoveragePlateau));
    assert!(events
        .iter()
        .all(|event| event.run_id == id && event.id.is_some()));
    assert_eq!(
        store.get_run(id).await.unwrap().unwrap().status,
        RunStatus::Running
    );
    runtime.release.notify_one();
    (id, serde_json::to_value(events).unwrap())
}

async fn assert_qualified_review(fixture: &QualificationFixture, harness_id: Uuid) {
    let review = fixture
        .service
        .harness_review_queue(
            Some(&std::fs::canonicalize(&fixture.project).unwrap()),
            Some("alternate.c::parse_packet"),
        )
        .await
        .unwrap();
    assert_eq!(
        review.len(),
        1,
        "qualified selection retains exact harness review"
    );
    assert_eq!(review[0].target_id, fixture.target_id.to_string());
    assert_eq!(review[0].harness_id, harness_id.to_string());
    assert_eq!(
        serde_json::to_value(&review[0]).unwrap()["target_selector"],
        "alternate.c::parse_packet"
    );
}

#[tokio::test]
async fn imported_source_reaches_retained_health_closeout_and_explicit_experiment_result() {
    let fixture = QualificationFixture::new_for_target(
        RuntimeMode::Pass,
        ReviewMode::Approve,
        VALID_HARNESS,
        "alternate.c::parse_packet",
        true,
    )
    .await;
    fixture.assert_no_attempt_or_dispatch().await;
    assert_eq!(fixture.submission.source, VALID_HARNESS);
    let attempt = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .unwrap();
    assert_eq!(attempt.status, HarnessWorkOrderAttemptStatus::SmokePassed);
    let attempt_bytes = raw_attempt(&fixture, attempt.id).await;
    let harness_id = attempt.harness_id.unwrap();
    let smoke_id = attempt.smoke_run_id.unwrap();
    assert_eq!(
        fixture.store.get_run(smoke_id).await.unwrap().unwrap().kind,
        RunKind::Smoke
    );
    assert_qualified_review(&fixture, harness_id).await;
    let calls_before_approval = fixture.runtime.calls.load(Ordering::SeqCst);
    let reviews_before_approval = fixture.review.calls.load(Ordering::SeqCst);
    let promoted = fixture
        .service
        .promote_harness_work_order_attempt(attempt.id)
        .await
        .unwrap();
    assert_eq!(promoted.id, harness_id);
    assert_eq!(
        fixture.runtime.calls.load(Ordering::SeqCst),
        calls_before_approval
    );
    assert_eq!(
        fixture.review.calls.load(Ordering::SeqCst),
        reviews_before_approval
    );
    let result = attempt.result.as_ref().unwrap();
    assert!(fixture
        .store
        .harness_approval(
            harness_id,
            result.source_sha256.as_deref().unwrap(),
            result.binary_sha256.as_deref().unwrap()
        )
        .await
        .unwrap()
        .is_some());

    let runtime = Arc::new(CampaignRuntime {
        qualification: fixture.runtime.clone(),
        entered: Notify::new(),
        release: Notify::new(),
        campaigns: AtomicUsize::new(0),
    });
    // Closeout's optional model report is absent; compilation/review above used a controlled provider.
    let service = ServiceContainer::new(runtime.clone(), None).with_store(fixture.store.clone());
    let progress = AtomicUsize::new(0);
    let admitted = Mutex::new(None);
    let on_progress = |_| {
        progress.fetch_add(1, Ordering::SeqCst);
    };
    let on_started = |id| {
        *admitted.lock().unwrap() = Some(id);
    };
    let (first, first_observed) = tokio::join!(
        async {
            service
                .run_fuzzer_observed(
                    &fixture.project,
                    "alternate.c::parse_packet",
                    EngineKind::LibFuzzer,
                    60,
                    &on_progress,
                    &on_started,
                )
                .await
                .expect("first campaign")
        },
        observe_active(&service, &runtime),
    );
    assert_eq!(first.run_id, first_observed.0);
    assert_eq!(*admitted.lock().unwrap(), Some(first.run_id));
    assert!(progress.load(Ordering::SeqCst) >= 32);
    assert!(service.active_run_ids().is_empty());
    assert!(service.live_campaign_telemetry(first.run_id).is_none());
    let history = service.run_history(Some(&fixture.project)).await.unwrap();
    let retained_history = history
        .iter()
        .find(|run| run.id == first.run_id.to_string())
        .unwrap();
    assert_eq!(retained_history.target_id, Some(fixture.target_id));
    assert_eq!(
        serde_json::to_value(retained_history).unwrap()["target_selector"],
        "alternate.c::parse_packet"
    );
    let baseline = fixture
        .store
        .coverage_experiment_run_evidence(first.run_id)
        .await
        .unwrap();
    assert_eq!(baseline.target_id, fixture.target_id);
    assert_eq!(baseline.harness_id, harness_id);
    assert!(baseline.build_inputs.is_some());
    let calls_before_read = fixture.runtime.calls.load(Ordering::SeqCst);
    let pending = service.retained_run_closeout(first.run_id).await.unwrap();
    assert!(pending.steps.is_empty());
    assert_eq!(
        fixture.runtime.calls.load(Ordering::SeqCst),
        calls_before_read
    );
    let closeout = service.close_out_run(first.run_id).await.unwrap();
    assert_eq!(closeout.run_id, first.run_id);
    assert_eq!(closeout.steps.len(), 7);
    assert!(
        closeout.steps.iter().all(|step| step.outcome.is_terminal()),
        "{closeout:?}"
    );
    assert!(closeout
        .steps
        .iter()
        .any(|step| step.step == CloseoutStep::Coverage
            && matches!(step.outcome, StepOutcome::Skipped { .. })));
    let crashes = fixture
        .store
        .list_crashes_by_run(first.run_id)
        .await
        .unwrap();
    assert_eq!(crashes.len(), 1);
    let finding = &crashes[0];
    assert_eq!(finding.target_id, fixture.target_id);
    let exact = service
        .finding_review_for_project(&fixture.project, finding.id)
        .await
        .unwrap();
    assert_eq!(exact.crash.run_id, first.run_id);
    assert!(exact.latest_scoped_actions_allowed);

    let reopened_store = Arc::new(
        hf_storage::Store::connect(fixture.project.parent().unwrap().join("qualification.db"))
            .await
            .unwrap(),
    );
    let reopened = ServiceContainer::new(runtime.clone(), None).with_store(reopened_store.clone());
    let calls_before_reopen = fixture.runtime.calls.load(Ordering::SeqCst);
    let restored = reopened.retained_run_closeout(first.run_id).await.unwrap();
    assert_eq!(
        serde_json::to_value(&restored.steps).unwrap(),
        serde_json::to_value(&closeout.steps).unwrap()
    );
    assert!(!reopened
        .campaign_health_events(first.run_id)
        .await
        .unwrap()
        .is_empty());
    let retained_health =
        serde_json::to_value(reopened.campaign_health_events(first.run_id).await.unwrap()).unwrap();
    for event in first_observed.1.as_array().unwrap() {
        assert!(
            retained_health.as_array().unwrap().contains(event),
            "preterminal health ID and exact evidence survive restart"
        );
    }
    let retried = reopened.close_out_run(first.run_id).await.unwrap();
    assert_eq!(
        serde_json::to_value(&retried.steps).unwrap(),
        serde_json::to_value(&closeout.steps).unwrap()
    );
    assert_eq!(
        fixture.runtime.calls.load(Ordering::SeqCst),
        calls_before_reopen
    );
    let prepared = reopened
        .create_coverage_experiment(CreateCoverageExperimentRequest {
            project: fixture.project.clone(),
            target_id: fixture.target_id,
            baseline_run_id: first.run_id,
            kind: CoverageExperimentKind::GrowCorpus,
            goal_function: "parse_packet".into(),
            hypothesis: "A longer packet may exercise a different parser branch".into(),
            duration_secs: 60,
        })
        .await
        .unwrap();
    assert_eq!(prepared.status, CoverageExperimentStatus::Prepared);
    assert_eq!(prepared.baseline_run_id, first.run_id);
    assert_eq!(
        fixture.runtime.calls.load(Ordering::SeqCst),
        calls_before_reopen
    );
    let prepared_baseline = serde_json::to_value(&prepared.baseline).unwrap();
    let seeds = fixture.project.parent().unwrap().join("new-seeds");
    std::fs::create_dir(&seeds).unwrap();
    std::fs::write(seeds.join("packet"), b"new longer parser packet").unwrap();
    assert_eq!(
        reopened
            .corpus_import(&fixture.project, "alternate.c::parse_packet", &seeds)
            .await
            .unwrap()
            .added,
        1
    );
    // Existing explicit replay preserves the recorded seed while admitting the current corpus.
    let (second, second_observed) = tokio::join!(
        async {
            reopened
                .replay_run(first.run_id, &on_progress)
                .await
                .expect("second campaign")
        },
        observe_active(&reopened, &runtime)
    );
    assert_ne!(second.run_id, first.run_id);
    assert_eq!(second.run_id, second_observed.0);
    let second_record = reopened_store
        .get_run(second.run_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        second_record.config.as_ref().unwrap().replay_of,
        Some(first.run_id)
    );
    let calls_before_attach = fixture.runtime.calls.load(Ordering::SeqCst);
    let scope = CoverageExperimentScope {
        project: fixture.project.clone(),
        target_id: fixture.target_id,
    };
    let completed = reopened
        .complete_coverage_experiment(
            prepared.id,
            CompleteCoverageExperimentRequest {
                scope: scope.clone(),
                result_run_id: second.run_id,
            },
        )
        .await
        .unwrap();
    assert_eq!(completed.status, CoverageExperimentStatus::Completed);
    assert_eq!(
        serde_json::to_value(&completed.baseline).unwrap(),
        prepared_baseline
    );
    let comparison = completed.result.as_ref().unwrap();
    assert_eq!(comparison.run.run_id, second.run_id);
    assert_eq!(comparison.run.target_id, fixture.target_id);
    assert_eq!(comparison.run.harness_id, harness_id);
    assert_eq!(
        serde_json::to_value(
            reopened_store
                .coverage_experiment_run_evidence(first.run_id)
                .await
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(&baseline).unwrap()
    );
    assert_eq!(
        comparison.input_change,
        CoverageExperimentInputChange::CorpusChanged
    );
    assert_eq!(
        fixture.runtime.calls.load(Ordering::SeqCst),
        calls_before_attach
    );
    let historical = reopened
        .finding_review_for_project(&fixture.project, finding.id)
        .await
        .unwrap();
    assert_eq!(historical.crash.id, finding.id);
    assert_eq!(historical.crash.run_id, first.run_id);
    assert_eq!(historical.target_id, fixture.target_id);
    assert!(!historical.latest_scoped_actions_allowed);
    assert_eq!(raw_attempt(&fixture, attempt.id).await, attempt_bytes);
    assert_eq!(
        fixture.review.calls.load(Ordering::SeqCst),
        reviews_before_approval
    );
    assert_eq!(runtime.campaigns.load(Ordering::SeqCst), 2);
    let fresh = ServiceContainer::new(runtime, None).with_store(Arc::new(
        hf_storage::Store::connect(fixture.project.parent().unwrap().join("qualification.db"))
            .await
            .unwrap(),
    ));
    assert_eq!(
        serde_json::to_value(fresh.coverage_experiment(prepared.id, scope).await.unwrap()).unwrap(),
        serde_json::to_value(completed).unwrap()
    );
    eprintln!("acceptance_ids work_order={} submission={} attempt={} harness={} smoke={} target={} first={} finding={} experiment={} second={} health={}", fixture.packet.id, fixture.submission.id, attempt.id, harness_id, smoke_id, fixture.target_id, first.run_id, finding.id, prepared.id, second.run_id, first_observed.1);
}
