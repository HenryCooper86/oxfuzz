use hf_service::ServiceContainer;
#[cfg(feature = "semgrep-enrichment")]
use hf_service::TargetLanguage;
use std::path::PathBuf;

use crate::args::AiOption;
use crate::parse::parse_lang;

#[cfg(not(feature = "semgrep-enrichment"))]
pub(crate) async fn cmd_discover(
    project: PathBuf,
    lang: &str,
    rank: bool,
    ai: AiOption,
) -> anyhow::Result<()> {
    let lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
    #[cfg(feature = "native-analysis")]
    let mut inv = {
        let analyzed = container.discover_analyzed(&project, lang).await?;
        for line in native_overlay_lines(&analyzed) {
            eprintln!("{line}");
        }
        analyzed.inventory
    };
    #[cfg(not(feature = "native-analysis"))]
    let mut inv = container.discover(&project, lang).await?;
    if rank {
        let (ranked, note) = rank_inventory(&container, inv, ai).await?;
        inv = ranked;
        if let Some(note) = note {
            eprintln!("{note}");
        }
    }
    println!("{}", serde_json::to_string_pretty(&inv)?);
    Ok(())
}

/// Apply `--rank` under an [`AiOption`], returning the inventory and an optional
/// operator note.
///
/// One word means one thing on every command that takes it: `off` never calls a
/// model even when one is configured, `require` turns an unavailable or failing
/// model into an error, and `auto` keeps the heuristic scores and says so. The
/// last case matters because a configured-but-unreachable provider previously
/// failed the whole command, which is not what "use the model if you can"
/// should do.
#[cfg(not(feature = "semgrep-enrichment"))]
async fn rank_inventory(
    container: &ServiceContainer,
    inventory: hf_service::TargetInventory,
    ai: AiOption,
) -> anyhow::Result<(hf_service::TargetInventory, Option<String>)> {
    if ai == AiOption::Off {
        return Ok((
            inventory,
            Some("note: --ai off; ranking with heuristic scores only".to_owned()),
        ));
    }
    if container.provider_pool().is_none() {
        if ai == AiOption::Require {
            anyhow::bail!(
                "--ai require: LLM ranking was required but no provider is configured; \
                 set HF_PROVIDER_API_KEY"
            );
        }
        return Ok((
            inventory,
            Some(
                "warning: --rank requested but HF_PROVIDER_API_KEY not set; \
                 using heuristic scores only"
                    .to_owned(),
            ),
        ));
    }
    match container.rank(inventory.clone()).await {
        Ok(ranked) => Ok((ranked, None)),
        Err(error) if ai == AiOption::Require => Err(anyhow::anyhow!(
            "--ai require: LLM ranking was required but the model call failed: {error}"
        )),
        Err(error) => Ok((
            inventory,
            Some(format!(
                "warning: LLM ranking failed ({error}); using heuristic scores only"
            )),
        )),
    }
}

#[cfg(feature = "semgrep-enrichment")]
async fn bootstrap_discover_service<S, Bootstrap, BootstrapFuture>(
    lang: &str,
    bootstrap: Bootstrap,
) -> anyhow::Result<(TargetLanguage, S)>
where
    Bootstrap: FnOnce() -> BootstrapFuture,
    BootstrapFuture: std::future::Future<Output = S>,
{
    let language = parse_lang(lang)?;
    let service = bootstrap().await;
    Ok((language, service))
}

#[cfg(feature = "semgrep-enrichment")]
pub(crate) async fn cmd_discover(
    project: PathBuf,
    lang: &str,
    rank: bool,
    ai: AiOption,
    semgrep: bool,
) -> anyhow::Result<()> {
    let (language, container) =
        bootstrap_discover_service(lang, ServiceContainer::bootstrap).await?;
    let mut output = ConsoleDiscoverOutput;
    run_discover_command(
        &container,
        project,
        language,
        rank,
        ai,
        semgrep,
        &mut output,
        tokio::signal::ctrl_c(),
        || tokio::time::sleep(std::time::Duration::from_millis(250)),
    )
    .await
}

/// Summarize the native static-analysis overlay for the operator.
///
/// Advisory, and written to stderr by the caller so stdout stays pure JSON: the
/// boost changes which targets are worth fuzzing first, and the base score stays
/// visible so it is clear what the signal moved.
#[cfg(feature = "native-analysis")]
fn native_overlay_lines(analyzed: &hf_service::AnalyzedInventory) -> Vec<String> {
    if analyzed.signal_count == 0 {
        return Vec::new();
    }
    let mut boosted: Vec<_> = analyzed
        .scores
        .iter()
        .filter(|score| score.matched_rule_count > 0)
        .collect();
    boosted.sort_by(|a, b| b.effective_score.total_cmp(&a.effective_score));
    let mut lines = vec![format!(
        "static analysis: {} signal(s) across {} target(s)",
        analyzed.signal_count,
        boosted.len()
    )];
    for score in boosted.iter().take(10) {
        let symbol = analyzed
            .inventory
            .candidates
            .iter()
            .find(|candidate| candidate.id == score.target_id)
            .map_or("(unknown)", |candidate| candidate.symbol.as_str());
        lines.push(format!(
            "  {symbol}: {:.2} -> {:.2} ({} rule(s))",
            score.base_score, score.effective_score, score.matched_rule_count
        ));
    }
    lines
}

#[cfg(feature = "semgrep-enrichment")]
#[async_trait::async_trait]
trait DiscoverCommandService {
    async fn discover_targets(
        &self,
        project: &std::path::Path,
        language: TargetLanguage,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError>;

    /// Discovery that also returns the native static-analysis overlay.
    ///
    /// `None` falls back to `discover_targets`, which is what a double that
    /// does not model the analyzer returns.
    #[cfg(feature = "native-analysis")]
    async fn discover_analyzed_targets(
        &self,
        project: &std::path::Path,
        language: TargetLanguage,
    ) -> Result<Option<hf_service::AnalyzedInventory>, hf_service::ClassifiedError>;

    async fn rank_targets(
        &self,
        inventory: hf_service::TargetInventory,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError>;

    fn has_provider(&self) -> bool;

    async fn start_semgrep(
        &self,
        project: PathBuf,
        language: TargetLanguage,
    ) -> Result<uuid::Uuid, hf_service::ClassifiedError>;

    async fn semgrep_status(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<Option<hf_service::SemgrepOperationView>, hf_service::ClassifiedError>;

    async fn cancel_semgrep(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<hf_service::SemgrepCancelOutcome, hf_service::ClassifiedError>;
}

#[cfg(feature = "semgrep-enrichment")]
#[async_trait::async_trait]
impl DiscoverCommandService for ServiceContainer {
    #[cfg(feature = "native-analysis")]
    async fn discover_analyzed_targets(
        &self,
        project: &std::path::Path,
        language: TargetLanguage,
    ) -> Result<Option<hf_service::AnalyzedInventory>, hf_service::ClassifiedError> {
        self.discover_analyzed(project, language).await.map(Some)
    }

    async fn discover_targets(
        &self,
        project: &std::path::Path,
        language: TargetLanguage,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError> {
        self.discover(project, language).await
    }

    async fn rank_targets(
        &self,
        inventory: hf_service::TargetInventory,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError> {
        self.rank(inventory).await
    }

    fn has_provider(&self) -> bool {
        self.provider_pool().is_some()
    }

    async fn start_semgrep(
        &self,
        project: PathBuf,
        language: TargetLanguage,
    ) -> Result<uuid::Uuid, hf_service::ClassifiedError> {
        self.start_semgrep_enrichment(project, language).await
    }

    async fn semgrep_status(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<Option<hf_service::SemgrepOperationView>, hf_service::ClassifiedError> {
        self.semgrep_operation(operation_id).await
    }

    async fn cancel_semgrep(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<hf_service::SemgrepCancelOutcome, hf_service::ClassifiedError> {
        self.request_semgrep_cancel(operation_id).await
    }
}

#[cfg(feature = "semgrep-enrichment")]
trait DiscoverCommandOutput {
    fn stdout_line(&mut self, line: String);
    fn stderr_line(&mut self, line: String);
}

#[cfg(feature = "semgrep-enrichment")]
struct ConsoleDiscoverOutput;

#[cfg(feature = "semgrep-enrichment")]
impl DiscoverCommandOutput for ConsoleDiscoverOutput {
    fn stdout_line(&mut self, line: String) {
        println!("{line}");
    }

    fn stderr_line(&mut self, line: String) {
        eprintln!("{line}");
    }
}

#[cfg(feature = "semgrep-enrichment")]
enum SemgrepPollAction {
    Continue,
    Complete(hf_service::SemgrepInventoryView),
    Fail(String),
}

#[cfg(feature = "semgrep-enrichment")]
fn semgrep_state_name(state: hf_service::SemgrepOperationState) -> &'static str {
    match state {
        hf_service::SemgrepOperationState::Staging => "staging",
        hf_service::SemgrepOperationState::Scanning => "scanning",
        hf_service::SemgrepOperationState::Validating => "validating",
        hf_service::SemgrepOperationState::Persisting => "persisting",
        hf_service::SemgrepOperationState::Done => "done",
        hf_service::SemgrepOperationState::Failed => "failed",
        hf_service::SemgrepOperationState::Cancelled => "cancelled",
    }
}

#[cfg(feature = "semgrep-enrichment")]
fn semgrep_poll_action(view: hf_service::SemgrepOperationView) -> SemgrepPollAction {
    match view.state {
        hf_service::SemgrepOperationState::Done => match view.result {
            Some(result) => SemgrepPollAction::Complete(result),
            None => SemgrepPollAction::Fail(
                "Semgrep enrichment completed without an exact result".to_owned(),
            ),
        },
        hf_service::SemgrepOperationState::Failed
        | hf_service::SemgrepOperationState::Cancelled => {
            SemgrepPollAction::Fail(view.failure_message.unwrap_or_else(|| {
                format!("Semgrep enrichment {}", semgrep_state_name(view.state))
            }))
        }
        _ => SemgrepPollAction::Continue,
    }
}

#[cfg(feature = "semgrep-enrichment")]
async fn wait_for_semgrep<S, O, Signal, Delay, DelayFuture>(
    service: &S,
    operation_id: uuid::Uuid,
    output: &mut O,
    mut signal: std::pin::Pin<&mut Signal>,
    delay: &mut Delay,
) -> anyhow::Result<hf_service::SemgrepInventoryView>
where
    S: DiscoverCommandService,
    O: DiscoverCommandOutput,
    Signal: std::future::Future<Output = std::io::Result<()>>,
    Delay: FnMut() -> DelayFuture,
    DelayFuture: std::future::Future<Output = ()>,
{
    let mut previous_state = None;
    let mut cancellation_requested = false;
    loop {
        let status = if cancellation_requested {
            service.semgrep_status(operation_id).await?
        } else {
            tokio::select! {
                signal_result = signal.as_mut() => {
                    signal_result?;
                    output.stderr_line("Semgrep enrichment: cancellation requested".to_owned());
                    let _ = service.cancel_semgrep(operation_id).await?;
                    cancellation_requested = true;
                    continue;
                }
                status = service.semgrep_status(operation_id) => status?,
            }
        };
        let view = status
            .ok_or_else(|| anyhow::anyhow!("Semgrep operation {operation_id} was not found"))?;
        if previous_state != Some(view.state) {
            output.stderr_line(format!(
                "Semgrep enrichment: {}",
                semgrep_state_name(view.state)
            ));
            previous_state = Some(view.state);
        }
        match semgrep_poll_action(view) {
            SemgrepPollAction::Continue => {}
            SemgrepPollAction::Complete(result) => return Ok(result),
            SemgrepPollAction::Fail(message) => anyhow::bail!("{message}"),
        }

        if cancellation_requested {
            delay().await;
        } else {
            let delay_future = delay();
            tokio::pin!(delay_future);
            tokio::select! {
                () = &mut delay_future => {}
                signal_result = signal.as_mut() => {
                    signal_result?;
                    output.stderr_line("Semgrep enrichment: cancellation requested".to_owned());
                    let _ = service.cancel_semgrep(operation_id).await?;
                    cancellation_requested = true;
                }
            }
        }
    }
}

#[cfg(feature = "semgrep-enrichment")]
async fn run_discover_command<S, O, Signal, Delay, DelayFuture>(
    service: &S,
    project: PathBuf,
    language: TargetLanguage,
    rank: bool,
    ai: AiOption,
    semgrep: bool,
    output: &mut O,
    signal: Signal,
    mut delay: Delay,
) -> anyhow::Result<()>
where
    S: DiscoverCommandService,
    O: DiscoverCommandOutput,
    Signal: std::future::Future<Output = std::io::Result<()>>,
    Delay: FnMut() -> DelayFuture,
    DelayFuture: std::future::Future<Output = ()>,
{
    #[cfg(feature = "native-analysis")]
    let mut inventory = match service
        .discover_analyzed_targets(&project, language)
        .await?
    {
        Some(analyzed) => {
            for line in native_overlay_lines(&analyzed) {
                output.stderr_line(line);
            }
            analyzed.inventory
        }
        None => service.discover_targets(&project, language).await?,
    };
    #[cfg(not(feature = "native-analysis"))]
    let mut inventory = service.discover_targets(&project, language).await?;
    if rank {
        // Same three meanings as the non-semgrep path; see `rank_inventory`.
        if ai == AiOption::Off {
            output.stderr_line("note: --ai off; ranking with heuristic scores only".to_owned());
        } else if service.has_provider() {
            match service.rank_targets(inventory.clone()).await {
                Ok(ranked) => inventory = ranked,
                Err(error) if ai == AiOption::Require => {
                    anyhow::bail!(
                        "--ai require: LLM ranking was required but the model call \
                         failed: {error}"
                    );
                }
                Err(error) => output.stderr_line(format!(
                    "warning: LLM ranking failed ({error}); using heuristic scores only"
                )),
            }
        } else if ai == AiOption::Require {
            anyhow::bail!(
                "--ai require: LLM ranking was required but no provider is configured; \
                 set HF_PROVIDER_API_KEY"
            );
        } else {
            output.stderr_line(
                "warning: --rank requested but HF_PROVIDER_API_KEY not set; using heuristic scores only"
                    .to_owned(),
            );
        }
    }
    if !semgrep {
        output.stdout_line(serde_json::to_string_pretty(&inventory)?);
        return Ok(());
    }
    if !matches!(language, TargetLanguage::C | TargetLanguage::Cpp) {
        anyhow::bail!("Semgrep enrichment supports only C and C++ target inventories");
    }
    let operation_id = service.start_semgrep(project, language).await?;
    tokio::pin!(signal);
    let result =
        wait_for_semgrep(service, operation_id, output, signal.as_mut(), &mut delay).await?;
    output.stderr_line("Semgrep static-analysis signals".to_owned());
    output.stdout_line(serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(all(test, feature = "semgrep-enrichment"))]
mod semgrep_cli_tests {
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use hf_service::{
        ClassifiedError, SemgrepCancelOutcome, SemgrepInventoryView, SemgrepOperationState,
        SemgrepOperationView, SemgrepOverlayState, TargetInventory, TargetLanguage,
    };
    use uuid::Uuid;

    use super::{
        bootstrap_discover_service, run_discover_command, semgrep_poll_action, semgrep_state_name,
        DiscoverCommandOutput, DiscoverCommandService, SemgrepPollAction,
    };
    use crate::args::AiOption;

    enum StatusStep {
        View(Box<SemgrepOperationView>),
        Pending,
    }

    struct FakeDiscoverService {
        events: Mutex<Vec<String>>,
        provider_available: bool,
        discovered: TargetInventory,
        ranked: TargetInventory,
        operation_id: Uuid,
        statuses: Mutex<VecDeque<StatusStep>>,
        cancelled: Mutex<Vec<Uuid>>,
        pending_status_entered: Arc<tokio::sync::Notify>,
    }

    impl FakeDiscoverService {
        fn new(language: TargetLanguage, statuses: Vec<StatusStep>) -> Self {
            let discovered = inventory(language, "/tmp/project");
            let mut ranked = discovered.clone();
            ranked.project_root = PathBuf::from("/tmp/project-ranked");
            Self {
                events: Mutex::new(Vec::new()),
                provider_available: true,
                discovered,
                ranked,
                operation_id: Uuid::from_u128(0x1234),
                statuses: Mutex::new(statuses.into()),
                cancelled: Mutex::new(Vec::new()),
                pending_status_entered: Arc::new(tokio::sync::Notify::new()),
            }
        }

        fn event_names(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        fn cancelled_ids(&self) -> Vec<Uuid> {
            self.cancelled.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DiscoverCommandService for FakeDiscoverService {
        #[cfg(feature = "native-analysis")]
        async fn discover_analyzed_targets(
            &self,
            _project: &std::path::Path,
            _language: TargetLanguage,
        ) -> Result<Option<hf_service::AnalyzedInventory>, hf_service::ClassifiedError> {
            // This double models the discovery command, not the analyzer, so it
            // takes the plain path and keeps its existing assertions meaningful.
            Ok(None)
        }

        async fn discover_targets(
            &self,
            _project: &std::path::Path,
            _language: TargetLanguage,
        ) -> Result<TargetInventory, ClassifiedError> {
            self.events.lock().unwrap().push("discover".to_owned());
            Ok(self.discovered.clone())
        }

        async fn rank_targets(
            &self,
            _inventory: TargetInventory,
        ) -> Result<TargetInventory, ClassifiedError> {
            self.events.lock().unwrap().push("rank".to_owned());
            Ok(self.ranked.clone())
        }

        fn has_provider(&self) -> bool {
            self.provider_available
        }

        async fn start_semgrep(
            &self,
            _project: PathBuf,
            language: TargetLanguage,
        ) -> Result<Uuid, ClassifiedError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("start:{}", language.as_str()));
            Ok(self.operation_id)
        }

        async fn semgrep_status(
            &self,
            operation_id: Uuid,
        ) -> Result<Option<SemgrepOperationView>, ClassifiedError> {
            assert_eq!(operation_id, self.operation_id);
            self.events.lock().unwrap().push("status".to_owned());
            let step = self.statuses.lock().unwrap().pop_front().unwrap();
            match step {
                StatusStep::View(view) => Ok(Some(*view)),
                StatusStep::Pending => {
                    self.pending_status_entered.notify_one();
                    std::future::pending().await
                }
            }
        }

        async fn cancel_semgrep(
            &self,
            operation_id: Uuid,
        ) -> Result<SemgrepCancelOutcome, ClassifiedError> {
            self.events.lock().unwrap().push("cancel".to_owned());
            self.cancelled.lock().unwrap().push(operation_id);
            Ok(SemgrepCancelOutcome::Accepted)
        }
    }

    #[derive(Default)]
    struct RecordingOutput {
        stdout: Vec<String>,
        stderr: Vec<String>,
    }

    impl DiscoverCommandOutput for RecordingOutput {
        fn stdout_line(&mut self, line: String) {
            self.stdout.push(line);
        }

        fn stderr_line(&mut self, line: String) {
            self.stderr.push(line);
        }
    }

    fn inventory(_language: TargetLanguage, project: &str) -> TargetInventory {
        TargetInventory {
            project_root: PathBuf::from(project),
            candidates: Vec::new(),
            call_graph: HashMap::new(),
        }
    }

    fn result(operation_id: Uuid) -> SemgrepInventoryView {
        SemgrepInventoryView {
            project_root: PathBuf::from("/tmp/project"),
            language: TargetLanguage::C,
            scan_id: Some(operation_id),
            source_sha256: Some("1".repeat(64)),
            overlay_state: SemgrepOverlayState::Current,
            candidates: Vec::new(),
            findings: Vec::new(),
            call_graph: HashMap::new(),
        }
    }

    fn operation(state: SemgrepOperationState) -> SemgrepOperationView {
        SemgrepOperationView {
            operation_id: Uuid::from_u128(0x1234),
            project_root: "/tmp/project".to_owned(),
            language: "c".to_owned(),
            state,
            active: true,
            started_at: "2026-07-29T00:00:00Z".to_owned(),
            ended_at: None,
            failure_code: None,
            failure_message: None,
            result: None,
        }
    }

    fn pending_signal() -> impl Future<Output = std::io::Result<()>> {
        std::future::pending()
    }

    fn immediate_delay() -> impl Future<Output = ()> {
        std::future::ready(())
    }

    #[tokio::test]
    async fn invalid_discovery_language_rejects_before_bootstrap_side_effects() {
        let bootstrap_called = Arc::new(AtomicBool::new(false));
        let called_from_bootstrap = Arc::clone(&bootstrap_called);

        let error = bootstrap_discover_service("invalid", move || {
            called_from_bootstrap.store(true, Ordering::SeqCst);
            std::future::ready(())
        })
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("unknown target language 'invalid'"));
        assert!(!bootstrap_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn discover_without_semgrep_preserves_the_existing_inventory_output() {
        let service = FakeDiscoverService::new(TargetLanguage::C, Vec::new());
        let expected = serde_json::to_string_pretty(&service.discovered).unwrap();
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::C,
            false,
            AiOption::Auto,
            false,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(service.event_names(), ["discover"]);
        assert_eq!(output.stdout, [expected]);
        assert!(output.stderr.is_empty());
    }

    #[tokio::test]
    async fn discover_without_a_provider_preserves_the_existing_rank_warning() {
        let mut service = FakeDiscoverService::new(TargetLanguage::C, Vec::new());
        service.provider_available = false;
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::C,
            true,
            AiOption::Auto,
            false,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(service.event_names(), ["discover"]);
        assert_eq!(
            output.stderr,
            ["warning: --rank requested but HF_PROVIDER_API_KEY not set; using heuristic scores only"]
        );
    }

    #[tokio::test]
    async fn discover_ranks_before_semgrep_and_prints_the_exact_service_result() {
        let operation_id = Uuid::from_u128(0x1234);
        let exact_result = result(operation_id);
        let mut done = operation(SemgrepOperationState::Done);
        done.active = false;
        done.result = Some(exact_result.clone());
        let service = FakeDiscoverService::new(
            TargetLanguage::C,
            vec![
                StatusStep::View(Box::new(operation(SemgrepOperationState::Scanning))),
                StatusStep::View(Box::new(done)),
            ],
        );
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::C,
            true,
            AiOption::Auto,
            true,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(
            service.event_names(),
            ["discover", "rank", "start:c", "status", "status"]
        );
        assert_eq!(
            output.stdout,
            [serde_json::to_string_pretty(&exact_result).unwrap()]
        );
        assert_eq!(
            output.stderr.last().map(String::as_str),
            Some("Semgrep static-analysis signals")
        );
    }

    #[tokio::test]
    async fn semgrep_language_validation_runs_after_discovery_and_optional_ranking() {
        let service = FakeDiscoverService::new(TargetLanguage::Rust, Vec::new());
        let mut output = RecordingOutput::default();

        let error = run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::Rust,
            true,
            AiOption::Auto,
            true,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("only C and C++"));
        assert_eq!(service.event_names(), ["discover", "rank"]);
        assert!(output.stdout.is_empty());
    }

    #[tokio::test]
    async fn semgrep_language_validation_accepts_cpp_after_discovery() {
        let mut done = operation(SemgrepOperationState::Done);
        done.active = false;
        done.result = Some(result(Uuid::from_u128(0x1234)));
        let service =
            FakeDiscoverService::new(TargetLanguage::Cpp, vec![StatusStep::View(Box::new(done))]);
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::Cpp,
            false,
            AiOption::Auto,
            true,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(service.event_names(), ["discover", "start:cpp", "status"]);
    }

    #[tokio::test]
    async fn semgrep_signal_cancels_the_exact_uuid_while_status_is_pending() {
        let mut cancelled = operation(SemgrepOperationState::Cancelled);
        cancelled.active = false;
        cancelled.failure_message = Some("cancelled by test".to_owned());
        let service = FakeDiscoverService::new(
            TargetLanguage::C,
            vec![StatusStep::Pending, StatusStep::View(Box::new(cancelled))],
        );
        let pending_status_entered = Arc::clone(&service.pending_status_entered);
        let signal = async move {
            pending_status_entered.notified().await;
            Ok(())
        };
        let mut output = RecordingOutput::default();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_discover_command(
                &service,
                PathBuf::from("/tmp/project"),
                TargetLanguage::C,
                false,
                AiOption::Auto,
                true,
                &mut output,
                signal,
                immediate_delay,
            ),
        )
        .await
        .expect("Ctrl-C must be observed while status retrieval is pending")
        .unwrap_err();

        assert_eq!(error.to_string(), "cancelled by test");
        assert_eq!(service.cancelled_ids(), [service.operation_id]);
        assert_eq!(
            service.event_names(),
            ["discover", "start:c", "status", "cancel", "status"]
        );
    }

    #[tokio::test]
    async fn semgrep_signal_cancels_the_exact_uuid_while_poll_delay_is_pending() {
        let mut cancelled = operation(SemgrepOperationState::Cancelled);
        cancelled.active = false;
        cancelled.failure_message = Some("cancelled during delay".to_owned());
        let service = FakeDiscoverService::new(
            TargetLanguage::C,
            vec![
                StatusStep::View(Box::new(operation(SemgrepOperationState::Scanning))),
                StatusStep::View(Box::new(cancelled)),
            ],
        );
        let delay_started = Arc::new(tokio::sync::Notify::new());
        let signal_started = Arc::clone(&delay_started);
        let delay_notifier = Arc::clone(&delay_started);
        let signal = async move {
            signal_started.notified().await;
            Ok(())
        };
        let delay = move || {
            delay_notifier.notify_one();
            std::future::pending::<()>()
        };
        let mut output = RecordingOutput::default();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_discover_command(
                &service,
                PathBuf::from("/tmp/project"),
                TargetLanguage::C,
                false,
                AiOption::Auto,
                true,
                &mut output,
                signal,
                delay,
            ),
        )
        .await
        .expect("Ctrl-C must be observed while the poll delay is pending")
        .unwrap_err();

        assert_eq!(error.to_string(), "cancelled during delay");
        assert_eq!(service.cancelled_ids(), [service.operation_id]);
    }

    #[test]
    fn semgrep_polling_uses_exact_results_and_fails_closed_at_terminals() {
        for state in [
            SemgrepOperationState::Staging,
            SemgrepOperationState::Scanning,
            SemgrepOperationState::Validating,
            SemgrepOperationState::Persisting,
        ] {
            assert!(matches!(
                semgrep_poll_action(operation(state)),
                SemgrepPollAction::Continue
            ));
        }

        let mut done = operation(SemgrepOperationState::Done);
        done.result = Some(SemgrepInventoryView {
            project_root: PathBuf::from("/tmp/project"),
            language: TargetLanguage::C,
            scan_id: Some(Uuid::nil()),
            source_sha256: Some("1".repeat(64)),
            overlay_state: SemgrepOverlayState::Current,
            candidates: Vec::new(),
            findings: Vec::new(),
            call_graph: HashMap::new(),
        });
        let SemgrepPollAction::Complete(result) = semgrep_poll_action(done) else {
            panic!("done operation must return its exact result");
        };
        assert_eq!(result.scan_id, Some(Uuid::nil()));

        let missing = semgrep_poll_action(operation(SemgrepOperationState::Done));
        let SemgrepPollAction::Fail(message) = missing else {
            panic!("done operation without a result must fail closed");
        };
        assert!(message.contains("completed without an exact result"));

        let mut failed = operation(SemgrepOperationState::Failed);
        failed.failure_message = Some("bounded service failure".to_owned());
        let SemgrepPollAction::Fail(message) = semgrep_poll_action(failed) else {
            panic!("failed operation must return an error");
        };
        assert_eq!(message, "bounded service failure");

        assert!(matches!(
            semgrep_poll_action(operation(SemgrepOperationState::Cancelled)),
            SemgrepPollAction::Fail(message) if message.contains("cancelled")
        ));
    }

    #[test]
    fn semgrep_state_labels_are_canonical_lowercase() {
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Staging),
            "staging"
        );
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Scanning),
            "scanning"
        );
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Validating),
            "validating"
        );
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Persisting),
            "persisting"
        );
        assert_eq!(semgrep_state_name(SemgrepOperationState::Done), "done");
        assert_eq!(semgrep_state_name(SemgrepOperationState::Failed), "failed");
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Cancelled),
            "cancelled"
        );
    }
}
