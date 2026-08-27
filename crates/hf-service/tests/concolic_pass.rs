//! What one concolic enrichment pass actually did, as opposed to what it set
//! out to do.
//!
//! Every assertion here is about the gap between intent and fact: the pass
//! reports the inputs it explored rather than the inputs it selected, the
//! corpus size it measured rather than one it derived, and the bound that
//! genuinely stopped it rather than one that merely truncated a collection.
//! `docs/design/concolic-enrichment-design.md` sections 4, 5, and 6.

#![cfg(feature = "concolic-enrichment")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::runtime::{CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{ConcolicStopReason, ServiceContainer};
use hf_storage::{HarnessApprovalKind, Store};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Process-wide fixture
// ---------------------------------------------------------------------------

/// The bounds every test in this binary runs under.
///
/// `HF_CONFIG_DIR` and `HF_WORKSPACE_DIR` are process-global and each
/// `tests/*.rs` file is its own process, so one set of bounds is shared here
/// and chosen to suit every test below: a one-second total budget a scripted
/// delay can exceed, and a solved-input cap low enough to reach.
const BOUNDS: &str = "[concolic]\n\
     max_inputs = 25\n\
     per_input_timeout_secs = 5\n\
     max_solved_inputs = 2\n\
     total_timeout_secs = 1\n";

fn fixture_base() -> &'static Path {
    static BASE: OnceLock<PathBuf> = OnceLock::new();
    BASE.get_or_init(|| {
        let base = std::env::temp_dir().join(format!(
            "oxfuzz_concolic_pass_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let config = base.join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("oxfuzz.toml"), BOUNDS).unwrap();
        std::env::set_var("HF_CONFIG_DIR", &config);
        std::env::set_var("HF_WORKSPACE_DIR", base.join("workspaces"));
        hf_service::initialize_workspace_root().unwrap();
        base
    })
}

/// A project directory, a store holding a promoted harness for `parse_packet`,
/// and a workspace whose corpus holds `seeds`.
///
/// The promoted harness is not optional scenery: spec section 4 step 1 makes a
/// promoted harness the precondition for instrumenting anything at all.
struct Fixture {
    project: PathBuf,
    workspace: PathBuf,
    store: Arc<Store>,
}

impl Fixture {
    async fn new(name: &str, seeds: &[&[u8]]) -> Self {
        let fixture = Self::without_corpus(name).await;
        let corpus = fixture.workspace.join("corpus");
        std::fs::create_dir_all(&corpus).unwrap();
        for (index, seed) in seeds.iter().enumerate() {
            std::fs::write(corpus.join(format!("seed{index}.bin")), seed).unwrap();
        }
        fixture
    }

    async fn without_corpus(name: &str) -> Self {
        let base = fixture_base();
        let project = base.join("projects").join(name);
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("parser.c"), b"int parse_packet(void);\n").unwrap();

        let store = Arc::new(
            Store::connect(base.join(format!("{name}.db")))
                .await
                .unwrap(),
        );
        let target = target_record(&project);
        store
            .upsert_target(&target, chrono::Utc::now())
            .await
            .unwrap();

        let workspace = hf_service::workspace_dir(&project, "parse_packet");
        std::fs::create_dir_all(&workspace).unwrap();

        Self {
            project,
            workspace,
            store,
        }
    }

    /// Stage the harness source the pass instruments and record the human
    /// promotion of exactly that revision.
    async fn with_promoted_harness(self) -> Self {
        let source = harness_source();
        std::fs::write(self.workspace.join("harness.c"), &source).unwrap();
        std::fs::write(self.workspace.join("harness.source"), &source).unwrap();
        self.persist_harness(HarnessStatus::Promoted, &source).await;
        self
    }

    async fn persist_harness(&self, status: HarnessStatus, source: &str) {
        let target_id = self.target_id().await;
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id,
            engine: EngineKind::LibFuzzer,
            source: source.to_owned(),
            language: TargetLanguage::C,
            build_cmd: BuildCommand {
                compiler: "clang".to_owned(),
                args: Vec::new(),
                output: PathBuf::from("fuzz_parse_packet"),
                extra_flags: Vec::new(),
            },
            sanitizer: Sanitizer::Address,
            status,
            smoke_run: None,
        };
        if status == HarnessStatus::Promoted {
            self.store
                .promote_harness_with_approval(
                    &harness,
                    HarnessApprovalKind::CleanSmoke,
                    &"a".repeat(64),
                    &"b".repeat(64),
                    chrono::Utc::now(),
                )
                .await
                .unwrap();
        } else {
            self.store.upsert_harness(&harness).await.unwrap();
        }
    }

    async fn target_id(&self) -> Uuid {
        self.store
            .list_all_targets()
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.symbol == "parse_packet")
            .unwrap()
            .id
    }

    fn container(&self, runtime: Arc<dyn RuntimeAdapter>) -> ServiceContainer {
        ServiceContainer::new(runtime, None).with_store(Arc::clone(&self.store))
    }

    fn corpus_dir(&self) -> PathBuf {
        self.workspace.join("corpus")
    }
}

fn harness_source() -> String {
    "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}".to_owned()
}

fn target_record(project: &Path) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.to_path_buf(),
        symbol: "parse_packet".to_owned(),
        language: TargetLanguage::C,
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: project.join("parser.c"),
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
    }
}

// ---------------------------------------------------------------------------
// A scripted sandbox
// ---------------------------------------------------------------------------

/// A sandbox stand-in that answers the availability probe, then behaves for the
/// build and each exploration as the test script says.
struct ScriptedRuntime {
    /// Files the first exploration writes into `SYMCC_OUTPUT_DIR`.
    solved_on_first_explore: Vec<Vec<u8>>,
    build_delay: Duration,
    explore_delay: Duration,
    /// Every working directory the runtime was handed, in order.
    cwds: Mutex<Vec<PathBuf>>,
    /// Every command the runtime was handed, in order.
    commands: Mutex<Vec<Vec<String>>>,
    explores: Mutex<usize>,
}

impl ScriptedRuntime {
    fn new() -> Self {
        Self {
            solved_on_first_explore: Vec::new(),
            build_delay: Duration::ZERO,
            explore_delay: Duration::ZERO,
            cwds: Mutex::new(Vec::new()),
            commands: Mutex::new(Vec::new()),
            explores: Mutex::new(0),
        }
    }

    fn solving(mut self, solved: Vec<Vec<u8>>) -> Self {
        self.solved_on_first_explore = solved;
        self
    }

    fn with_build_delay(mut self, delay: Duration) -> Self {
        self.build_delay = delay;
        self
    }

    fn with_explore_delay(mut self, delay: Duration) -> Self {
        self.explore_delay = delay;
        self
    }

    fn explore_count(&self) -> usize {
        *self.explores.lock().unwrap()
    }

    fn first_cwd(&self) -> PathBuf {
        self.cwds.lock().unwrap().first().cloned().unwrap()
    }

    /// The `sh -c` script of the instrumented build, i.e. the one command that
    /// actually invokes `symcc` to compile -- distinct from the availability
    /// probe, which also mentions `symcc` but never compiles anything.
    fn build_script(&self) -> String {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .find(|cmd| cmd.iter().any(|arg| arg.contains("symcc -O1")))
            .and_then(|cmd| cmd.last().cloned())
            .expect("a symcc build command was run")
    }
}

fn completed(cwd: &Path) -> CommandResult {
    CommandResult {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        workspace: cwd.to_path_buf(),
        termination: CommandTermination::Completed,
    }
}

#[async_trait]
impl RuntimeAdapter for ScriptedRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.cwds.lock().unwrap().push(cwd.to_path_buf());
        self.commands.lock().unwrap().push(cmd.to_vec());
        if cmd.iter().any(|arg| arg.contains("command -v symcc")) {
            return Ok(completed(cwd));
        }
        if cmd.iter().any(|arg| arg.contains("symcc ")) {
            tokio::time::sleep(self.build_delay).await;
            return Ok(completed(cwd));
        }
        let first = {
            let mut explores = self.explores.lock().unwrap();
            *explores += 1;
            *explores == 1
        };
        if first {
            let out = cwd.join(
                limits
                    .env
                    .get("SYMCC_OUTPUT_DIR")
                    .cloned()
                    .unwrap_or_else(|| "concolic-out".to_owned()),
            );
            std::fs::create_dir_all(&out).unwrap();
            for (index, bytes) in self.solved_on_first_explore.iter().enumerate() {
                std::fs::write(out.join(format!("solved{index}")), bytes).unwrap();
            }
        }
        tokio::time::sleep(self.explore_delay).await;
        Ok(completed(cwd))
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        unreachable!("the concolic pass does not write files through the runtime")
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        unreachable!("the concolic pass does not read files through the runtime")
    }
}

// ---------------------------------------------------------------------------
// 1. The availability probe
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_availability_probe_runs_inside_the_approved_workspace_root() {
    // A relative cwd is resolved against the process directory, which the
    // Docker runtime then rejects as outside its approved root -- so the probe
    // would report `Unavailable` on a correctly built image and the whole
    // subsystem would be dead on the only runtime that carries SymCC.
    fixture_base();
    let runtime = Arc::new(ScriptedRuntime::new());
    let container = ServiceContainer::new(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>, None);

    let availability = container.concolic_availability().await;

    assert_eq!(
        availability,
        hf_service::ConcolicAvailability::Available,
        "a sandbox that answers the wrapper probe is available"
    );
    let cwd = runtime.first_cwd();
    assert!(cwd.is_absolute(), "the probe cwd must be absolute: {cwd:?}");
    assert_eq!(
        std::fs::canonicalize(&cwd).unwrap(),
        std::fs::canonicalize(hf_service::workspace_root()).unwrap(),
        "the probe must run in the approved workspace root, not the process directory"
    );
}

// ---------------------------------------------------------------------------
// 2. A promoted harness is the precondition (spec section 4 step 1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_draft_harness_is_not_instrumented_in_place_of_a_promoted_one() {
    let fixture = Fixture::new("draft_only", &[b"AAAA"]).await;
    let source = harness_source();
    std::fs::write(fixture.workspace.join("harness.c"), &source).unwrap();
    std::fs::write(fixture.workspace.join("harness.source"), &source).unwrap();
    fixture.persist_harness(HarnessStatus::Draft, &source).await;
    let runtime = Arc::new(ScriptedRuntime::new());
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    let error = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect_err("a draft harness has no human promotion behind it");

    assert!(
        matches!(&error, ClassifiedError::Validation(message) if message.contains("promoted")),
        "the pass must name the missing promotion, got: {error}"
    );
    assert_eq!(
        runtime.explore_count(),
        0,
        "a concolic pass is not a way around human promotion"
    );
}

#[tokio::test]
async fn an_unharnessed_target_is_diagnosed_rather_than_read_as_a_failed_build() {
    // Promotion is persisted state; the C source the build compiles is a
    // workspace file. A promoted record with no `harness.c` staged must be
    // diagnosed as the missing source rather than surfacing as "instrumented
    // build did not complete".
    let fixture = Fixture::new("no_c_source", &[b"AAAA"]).await;
    let source = harness_source();
    std::fs::write(fixture.workspace.join("harness.source"), &source).unwrap();
    fixture
        .persist_harness(HarnessStatus::Promoted, &source)
        .await;
    let runtime = Arc::new(ScriptedRuntime::new());
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    let error = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect_err("there is nothing to instrument without a harness source");

    assert!(
        matches!(&error, ClassifiedError::Validation(message) if message.contains("harness.c")),
        "the pass must name the missing harness source, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// 3. A build that never produced a binary is an error
// ---------------------------------------------------------------------------

/// Answers the availability probe as present, then fails every other command --
/// standing in for a sandbox image that has `SymCC` but whose instrumented
/// build does not succeed.
struct BuildFailsRuntime;

#[async_trait]
impl RuntimeAdapter for BuildFailsRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        if cmd.iter().any(|arg| arg.contains("command -v symcc")) {
            return Ok(completed(cwd));
        }
        Err(ClassifiedError::Sandbox(
            "symcc: no such target harness.c".to_owned(),
        ))
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        unreachable!("the concolic pass does not write files through the runtime")
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        unreachable!("the concolic pass does not read files through the runtime")
    }
}

#[tokio::test]
async fn a_build_failure_is_reported_as_an_error_never_as_an_empty_success() {
    let fixture = Fixture::new("build_failure", &[b"AAAA"])
        .await
        .with_promoted_harness()
        .await;
    let container = fixture.container(Arc::new(BuildFailsRuntime));

    let error = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect_err(
            "a build that never produced an instrumented binary must not be reported as a \
             completed pass that solved nothing -- that is indistinguishable from a pass that \
             legitimately solved nothing",
        );

    assert!(
        matches!(error, ClassifiedError::Sandbox(_)),
        "a build failure is a sandbox error, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// 4. Explored means explored
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inputs_the_deadline_dropped_are_never_reported_as_explored() {
    // The build consumes the whole pass budget, so the explore loop never runs
    // a single input. A pass that explored nothing must not report as a full
    // pass over every selected input.
    let fixture = Fixture::new("deadline_before_loop", &[b"A", b"B", b"C"])
        .await
        .with_promoted_harness()
        .await;
    let runtime = Arc::new(ScriptedRuntime::new().with_build_delay(Duration::from_millis(1400)));
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    let outcome = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect("a build that completed is a pass that ran");

    assert_eq!(
        runtime.explore_count(),
        0,
        "the scripted build ate the budget"
    );
    assert_eq!(
        outcome.inputs_explored, 0,
        "inputs_explored counts what ran, not what was selected"
    );
    assert_eq!(
        outcome.inputs_skipped, 3,
        "every selected input the deadline dropped is reported as skipped"
    );
    assert_eq!(outcome.stop_reason, ConcolicStopReason::TotalTimeout);
}

// ---------------------------------------------------------------------------
// 5. The corpus size is measured
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_corpus_size_after_a_fold_is_measured_not_derived() {
    // Two byte-identical solved inputs each count as novel, but they collapse
    // onto one `concolic-<digest>.bin` path. Deriving the post-fold size from
    // `before + inputs_novel` would report growth that did not happen.
    let fixture = Fixture::new("identical_solutions", &[b"AAAA"])
        .await
        .with_promoted_harness()
        .await;
    let runtime = Arc::new(
        ScriptedRuntime::new().solving(vec![b"solved-twice".to_vec(), b"solved-twice".to_vec()]),
    );
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    let outcome = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect("the pass ran");

    let on_disk = std::fs::read_dir(fixture.corpus_dir()).unwrap().count();
    assert_eq!(outcome.inputs_solved, 2);
    assert_eq!(outcome.corpus_size_before, 1);
    assert_eq!(
        outcome.corpus_size_after, on_disk,
        "the reported size must match the corpus that is actually there"
    );
    assert_eq!(
        outcome.corpus_size_after, 2,
        "two identical solutions occupy one corpus entry"
    );
}

// ---------------------------------------------------------------------------
// 6. The stop reason names the bound that stopped the pass
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_total_timeout_is_not_relabelled_as_the_solved_input_cap() {
    // The first exploration solves more than `max_solved_inputs` and runs past
    // the pass deadline. The cap truncated a collection; the deadline stopped
    // the pass, and that is what section 6 asks the reason to name.
    let fixture = Fixture::new("timeout_over_cap", &[b"A", b"B", b"C"])
        .await
        .with_promoted_harness()
        .await;
    let runtime = Arc::new(
        ScriptedRuntime::new()
            .solving(vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()])
            .with_explore_delay(Duration::from_millis(1400)),
    );
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    let outcome = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect("the pass ran");

    assert_eq!(runtime.explore_count(), 1, "the deadline ended the loop");
    assert_eq!(
        outcome.inputs_solved, 3,
        "more solutions than the cap holds"
    );
    assert_eq!(
        outcome.stop_reason,
        ConcolicStopReason::TotalTimeout,
        "a real total timeout must not be overwritten by a cap that only truncated"
    );
}

#[tokio::test]
async fn the_solved_input_cap_is_reported_when_it_is_what_stopped_the_pass() {
    let fixture = Fixture::new("cap_stops_pass", &[b"A", b"B", b"C"])
        .await
        .with_promoted_harness()
        .await;
    let runtime = Arc::new(ScriptedRuntime::new().solving(vec![
        b"one".to_vec(),
        b"two".to_vec(),
        b"three".to_vec(),
    ]));
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    let outcome = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect("the pass ran");

    assert_eq!(
        runtime.explore_count(),
        1,
        "the cap stops exploration rather than truncating afterwards"
    );
    assert_eq!(outcome.stop_reason, ConcolicStopReason::SolvedInputCap);
    assert_eq!(
        outcome.inputs_explored + outcome.inputs_skipped,
        3,
        "explored plus skipped still accounts for the whole corpus"
    );
}

// ---------------------------------------------------------------------------
// 7. The output directory belongs to one pass
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_previous_passes_solved_inputs_are_not_counted_again() {
    let fixture = Fixture::new("stale_output", &[b"AAAA"])
        .await
        .with_promoted_harness()
        .await;
    let stale = fixture.workspace.join("concolic-out");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("from-an-earlier-pass"), b"stale").unwrap();
    let runtime = Arc::new(ScriptedRuntime::new());
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    let outcome = container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect("the pass ran");

    assert_eq!(
        outcome.inputs_solved, 0,
        "a pass that solved nothing must not inherit an earlier pass's output"
    );
    assert_eq!(outcome.inputs_novel, 0);
    assert_eq!(outcome.corpus_size_after, outcome.corpus_size_before);
}

// ---------------------------------------------------------------------------
// 8. The instrumented build links the staged target sources
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_instrumented_build_links_staged_target_sources() {
    // The harness only declares `extern int parse_packet(...)`; the real
    // definition lives in the project source `copy_project_sources` stages
    // into the workspace, preserving the project's directory layout. Leaving
    // it off the `symcc` link line is exactly the bug this test guards: the
    // build fails on an undefined reference to the very function the harness
    // was written to fuzz.
    let fixture = Fixture::new("nested_source", &[b"AAAA"])
        .await
        .with_promoted_harness()
        .await;
    std::fs::create_dir_all(fixture.workspace.join("src")).unwrap();
    std::fs::write(
        fixture.workspace.join("src/parser.c"),
        "int parse_packet(void){return 0;}",
    )
    .unwrap();
    let runtime = Arc::new(ScriptedRuntime::new());
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect("the pass ran");

    let build = runtime.build_script();
    assert!(
        build.contains("src/parser.c"),
        "the staged target source must be on the symcc link line: {build}"
    );
    assert!(
        build.contains("harness.c") && build.contains("symcc_driver.c"),
        "the harness and driver must still be compiled too: {build}"
    );
}

#[tokio::test]
async fn a_malicious_staged_filename_is_quoted_not_executed() {
    // Staged filenames come from the untrusted project under test. A name
    // carrying a shell-injection payload must land in the build script as an
    // inert, single-quoted argument rather than breaking out of the command.
    let fixture = Fixture::new("malicious_filename", &[b"AAAA"])
        .await
        .with_promoted_harness()
        .await;
    let evil = "evil; touch pwned.c";
    std::fs::write(fixture.workspace.join(evil), "int x;").unwrap();
    let runtime = Arc::new(ScriptedRuntime::new());
    let container = fixture.container(Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>);

    container
        .corpus_concolic(&fixture.project, "parse_packet")
        .await
        .expect("the pass ran");

    let build = runtime.build_script();
    assert!(
        build.contains("'evil; touch pwned.c'"),
        "the malicious filename must be single-quoted: {build}"
    );
    assert!(
        !fixture.workspace.join("pwned.c").exists(),
        "the payload must never execute"
    );
}
