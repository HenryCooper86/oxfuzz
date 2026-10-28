//! Integration tests for coverage-aware, retained LLM seed drafting: the
//! prompt is retained before dispatch and carries the context sections the
//! service could read, its raw reply is completed once, and a prompt that
//! cannot be retained is never dispatched -- the initial path falls back to
//! heuristic seeds and the regenerate path reports zero replacements
//! (Engineering Protocol 2.13).

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
use hf_storage::{SeedDraftPurpose, SeedLlmDraftRecord, Store};

/// The seed-array reply the capturing pool serves; its two hex entries decode
/// to the PNG magic (4 bytes) and "{}" (2 bytes).
const SEED_REPLY: &str = r#"["89504e47", "7b7d"]"#;

/// A canned `llvm-cov export` in which `parse_entry` is covered and
/// `parse_header` is uncovered at `src/parse.c:7`, so the measured view has
/// exactly one blocker.
const MEASURED_EXPORT: &str = r#"{"data":[{"functions":[
  {"name":"parse_entry","count":5,"filenames":["src/parse.c"],"regions":[[3,1,5,2,5,0,0,0]]},
  {"name":"parse_header","count":0,"filenames":["src/parse.c"],"regions":[[7,1,8,2,0,0,0,0]]}
]}],"type":"llvm.coverage.json.export"}"#;

/// A runtime that answers the source-coverage pipeline with the canned
/// measurement and reports every other command as a clean success.
struct CoverageRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for CoverageRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let is_coverage_pipeline = cmd.first().is_some_and(|command| command == "sh")
            && cmd.get(1).is_some_and(|flag| flag == "-c")
            && cmd
                .last()
                .is_some_and(|pipeline| pipeline.contains("llvm-cov export"));
        let stdout = if is_coverage_pipeline {
            MEASURED_EXPORT.to_owned()
        } else {
            "DONE exec/s: 64".to_owned()
        };
        std::fs::create_dir_all(cwd).unwrap();
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout,
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        path: &Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, content)
            .map_err(|e| hf_core::error::ClassifiedError::Internal(e.to_string()))
    }

    async fn read_file(&self, path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        std::fs::read_to_string(path)
            .map_err(|e| hf_core::error::ClassifiedError::Internal(e.to_string()))
    }
}

/// A capturing provider pool: answers the seed prompt with a fixed seed array
/// while checking that the exact prompt is already retained as a pending
/// draft (the dispatch happens after persistence, never before), approves
/// harness reviews, and answers every other prompt with a harness code block.
struct CapturingSeedPool {
    store: Arc<Store>,
    project_root: String,
    target: &'static str,
    seed_calls: AtomicUsize,
    prompt_was_pending: AtomicBool,
}

impl CapturingSeedPool {
    fn seed_calls(&self) -> usize {
        self.seed_calls.load(Ordering::SeqCst)
    }

    fn prompt_was_pending(&self) -> bool {
        self.prompt_was_pending.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for CapturingSeedPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        let prompt = request
            .messages
            .last()
            .map(|message| message.content.clone())
            .expect("the seed request carries a prompt");
        if prompt.contains("seed-corpus author") {
            self.seed_calls.fetch_add(1, Ordering::SeqCst);
            let pending = self
                .store
                .seed_llm_drafts_for(&self.project_root, self.target)
                .await
                .expect("drafts readable at dispatch time")
                .iter()
                .any(|draft| draft.response.is_none() && draft.prompt == prompt);
            self.prompt_was_pending.store(pending, Ordering::SeqCst);
            return Ok(hf_test_utils::fixtures::make_chat_response(SEED_REPLY));
        }
        if hf_test_utils::is_harness_review_request(request) {
            return Ok(hf_test_utils::approving_harness_review_response());
        }
        Ok(hf_test_utils::fixtures::make_chat_response(
            "```c\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ return 0; }\n```",
        ))
    }

    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "streaming is not used by the seed fixture".to_owned(),
        })
    }

    fn report_error(
        &self,
        _provider_id: &hf_core::types::ProviderId,
        _error: &hf_core::provider::ProviderError,
    ) {
    }

    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}

    async fn thaw(
        &self,
        _provider_id: &hf_core::types::ProviderId,
    ) -> Result<(), hf_core::provider::ProviderError> {
        Ok(())
    }
}

fn write_sample_project(project: &Path) {
    std::fs::create_dir_all(project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_header(const uint8_t *data, size_t size) {\n\
         \x20 if (size > 2 && data[0] == 'P') { return 1; }\n\
         \x20 return 0;\n}\n\
         int parse_entry(const uint8_t *data, size_t size) {\n\
         \x20 return parse_header(data, size);\n}\n",
    )
    .unwrap();
}

struct SeedFixture {
    _directory: tempfile::TempDir,
    project: PathBuf,
    canonical_root: String,
    store: Arc<Store>,
    pool: Arc<CapturingSeedPool>,
}

impl SeedFixture {
    async fn new(_runtime: Arc<dyn hf_core::runtime::RuntimeAdapter>) -> Self {
        common::install_managed_workspace("oxfuzz_seed_llm_it");
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("seedproj");
        write_sample_project(&project);
        let store = Arc::new(
            Store::connect(directory.path().join("seed.db"))
                .await
                .unwrap(),
        );
        let canonical_root = std::fs::canonicalize(&project)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let pool = Arc::new(CapturingSeedPool {
            store: Arc::clone(&store),
            project_root: canonical_root.clone(),
            target: "parse_entry",
            seed_calls: AtomicUsize::new(0),
            prompt_was_pending: AtomicBool::new(false),
        });
        Self {
            _directory: directory,
            project,
            canonical_root,
            store,
            pool,
        }
    }

    fn container(&self, runtime: Arc<dyn hf_core::runtime::RuntimeAdapter>) -> ServiceContainer {
        ServiceContainer::new(
            runtime,
            Some(Arc::clone(&self.pool) as Arc<dyn hf_core::provider::ProviderPool>),
        )
        .with_store(Arc::clone(&self.store))
    }

    async fn drafts(&self) -> Vec<SeedLlmDraftRecord> {
        self.store
            .seed_llm_drafts_for(&self.canonical_root, "parse_entry")
            .await
            .unwrap()
    }
}

/// Stage a harness source for a target workspace, so the seed prompt's
/// harness-entry section has a recognizable marker (or, for the oversize
/// variant, an unretainable prompt). The coverage pipeline requires the
/// staged C harness filename, so both it and the canonical marker are
/// written.
fn stage_harness(project: &Path, source: &str) {
    let workspace = hf_service::workspace_dir(project, "parse_entry");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("harness.c"), source).unwrap();
    std::fs::write(workspace.join("harness.source"), source).unwrap();
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
}

const PLAIN_HARNESS: &str = "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n\
     \x20 if (n < 4) { return 0; }\n\
     \x20 return parse_entry(d, n);\n}\n";

/// The harness the regenerate fixture promotes: a plain AFL++ driver entry.
const PROMOTED_HARNESS: &str =
    "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n\
     \x20 return size && data[0];\n}";
#[tokio::test]
async fn the_seed_prompt_is_retained_before_dispatch_and_carries_its_context_sections() {
    let fixture = SeedFixture::new(Arc::new(hf_runtime::StubRuntime)).await;
    stage_harness(&fixture.project, PLAIN_HARNESS);
    std::fs::write(
        hf_service::workspace_dir(&fixture.project, "parse_entry")
            .join("corpus")
            .join("llmseed_0"),
        b"already",
    )
    .unwrap();

    let entries = fixture
        .container(Arc::new(hf_runtime::StubRuntime))
        .generate_seeds_llm(&fixture.project, "parse_entry", TargetLanguage::C, 8)
        .await
        .expect("seed generation should succeed");

    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(fixture.pool.seed_calls(), 1);
    assert!(
        fixture.pool.prompt_was_pending(),
        "the prompt row exists before the dispatch"
    );
    let drafts = fixture.drafts().await;
    assert_eq!(drafts.len(), 1, "{drafts:?}");
    let draft = &drafts[0];
    assert_eq!(draft.purpose, SeedDraftPurpose::Initial);
    assert_eq!(draft.prompt_version, hf_prompt::SEED_PROMPT_VERSION);
    assert_eq!(draft.response.as_deref(), Some(SEED_REPLY));
    assert!(
        draft.completed_at.is_some(),
        "the response is completed once"
    );

    let prompt = &draft.prompt;
    assert!(
        prompt.contains("Target definition (parse.c, line 7"),
        "the prompt names the target's own definition: {prompt}"
    );
    assert!(prompt.contains("Harness entry"), "{prompt}");
    assert!(prompt.contains("LLVMFuzzerTestOneInput"), "{prompt}");
    assert!(
        prompt.contains("Existing corpus seeds"),
        "the prompt names the corpus that already exists: {prompt}"
    );
    assert!(
        prompt.contains("\"616c7265616479\""),
        "the existing seed renders as hex: {prompt}"
    );
    assert!(!prompt.contains("Dead seeds"), "{prompt}");
    assert!(
        !prompt.contains("Coverage frontier"),
        "no measurement backs a frontier section here: {prompt}"
    );
}

#[tokio::test]
async fn the_frontier_section_renders_only_when_a_measurement_backs_it() {
    let fixture = SeedFixture::new(Arc::new(CoverageRuntime)).await;
    stage_harness(&fixture.project, PLAIN_HARNESS);
    let container = fixture.container(Arc::new(CoverageRuntime));
    // Warm the measurement the frontier conditions on: an earlier coverage
    // read computed and cached the export for this harness-plus-corpus
    // signature; seeding itself must not dispatch the coverage pipeline.
    assert_eq!(
        container
            .coverage_functions(&fixture.project, "parse_entry")
            .await,
        vec!["parse_entry".to_owned()],
        "the fixture runtime's canned measurement is cached"
    );

    let entries = container
        .generate_seeds_llm(&fixture.project, "parse_entry", TargetLanguage::C, 8)
        .await
        .expect("seed generation should succeed");
    assert_eq!(entries.len(), 2, "{entries:?}");

    let drafts = fixture.drafts().await;
    let prompt = drafts
        .first()
        .expect("the seed prompt was retained")
        .prompt
        .as_str();
    assert!(prompt.contains("Coverage frontier"), "{prompt}");
    assert!(
        prompt.contains("parse_header"),
        "the measured blocker is named: {prompt}"
    );
    assert!(
        prompt.contains("src/parse.c:7"),
        "the blocker's first uncovered location is named: {prompt}"
    );
}

#[tokio::test]
async fn an_unretainable_prompt_dispatches_nothing_and_falls_back_to_heuristic_seeds() {
    let fixture = SeedFixture::new(Arc::new(hf_runtime::StubRuntime)).await;
    // One entry-function comment line larger than the retained-prompt cap:
    // the prompt cannot be retained, so nothing may be dispatched.
    let oversized = format!(
        "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {{\n\
         \x20 /* {} */\n\
         \x20 return parse_entry(d, n);\n}}\n",
        "A".repeat(70 * 1024)
    );
    stage_harness(&fixture.project, &oversized);

    let entries = fixture
        .container(Arc::new(hf_runtime::StubRuntime))
        .generate_seeds_llm(&fixture.project, "parse_entry", TargetLanguage::C, 8)
        .await
        .expect("seed generation still succeeds");

    assert!(
        !entries.is_empty(),
        "the initial path falls back to the heuristic seeds: {entries:?}"
    );
    assert_eq!(fixture.pool.seed_calls(), 0, "no prompt was dispatched");
    assert!(
        fixture.drafts().await.is_empty(),
        "no row was retained for a prompt that was never sent"
    );
}

/// Canned `afl-showmap` output keyed on the input basename, mirroring the
/// seed-survival fixture: the empty-input baseline and `shallow` cover only
/// entry edges, anything named `regen_` (or `deep`) covers one more, and the
/// coverage pipeline reports an export no parser accepts (so no frontier
/// section competes with the assertions below).
struct SurvivalRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for SurvivalRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &hf_core::runtime::ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        if hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(cmd, opts, 64) {
            return Ok(hf_core::runtime::CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: hf_core::runtime::CommandTermination::Completed,
            });
        }
        self.run_command_streaming(cmd, cwd, limits, cancel, on_line)
            .await
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        let is_showmap = cmd.first().is_some_and(|command| command == "afl-showmap");
        if !is_showmap {
            return Ok(hf_core::runtime::CommandResult {
                exit_code: 0,
                stdout: "DONE exec/s: 64".to_owned(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: hf_core::runtime::CommandTermination::Completed,
            });
        }
        let input = cmd.last().cloned().unwrap_or_default();
        let (stdout, exit_code) = if input.contains("regen_") || input.ends_with("deep") {
            ("1:1\n2:1\n3:1\n".to_owned(), 0)
        } else {
            // The empty baseline and the shallow seed share the entry edges.
            ("1:1\n2:1\n".to_owned(), 0)
        };
        Ok(hf_core::runtime::CommandResult {
            exit_code,
            stdout,
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

/// A promoted-AFL-harness workspace with the capturing seed pool attached:
/// the shape `regenerate_dead_seeds` requires (a promoted harness the
/// survival measurement can run against).
struct RegenerateFixture {
    _directory: tempfile::TempDir,
    project: PathBuf,
    canonical_root: String,
    store: Arc<Store>,
    pool: Arc<CapturingSeedPool>,
    container: ServiceContainer,
}

impl RegenerateFixture {
    async fn new(target: &'static str, harness_source: &str) -> Self {
        common::install_managed_workspace("oxfuzz_seed_llm_it");
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("regenproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parse.c"),
            format!(
                "#include <stddef.h>\n\
                 int {target}(const unsigned char *data, size_t size) {{ return size && data[0]; }}\n"
            ),
        )
        .unwrap();
        let store = Arc::new(
            Store::connect(directory.path().join("regen.db"))
                .await
                .unwrap(),
        );
        let canonical_root = std::fs::canonicalize(&project)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let pool = Arc::new(CapturingSeedPool {
            store: Arc::clone(&store),
            project_root: canonical_root.clone(),
            target,
            seed_calls: AtomicUsize::new(0),
            prompt_was_pending: AtomicBool::new(false),
        });
        let container = ServiceContainer::new(
            Arc::new(SurvivalRuntime),
            Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
        )
        .with_store(Arc::clone(&store));
        container
            .harness_compile(
                harness_source.to_owned(),
                &project,
                hf_core::engine::EngineKind::AflPlusPlus,
                target,
                TargetLanguage::C,
                None,
                false,
            )
            .await
            .unwrap();
        let workspace = hf_service::workspace_dir(&project, target);
        std::fs::create_dir_all(workspace.join("corpus")).unwrap();
        std::fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();
        container
            .harness_smoke(
                &project,
                target,
                hf_core::engine::EngineKind::AflPlusPlus,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        container
            .harness_promote(&project, target, hf_core::engine::EngineKind::AflPlusPlus)
            .await
            .unwrap();
        Self {
            _directory: directory,
            project,
            canonical_root,
            store,
            pool,
            container,
        }
    }

    async fn drafts(&self) -> Vec<SeedLlmDraftRecord> {
        self.store
            .seed_llm_drafts_for(&self.canonical_root, "parse_regen")
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn the_regenerate_prompt_names_the_dead_seeds_and_is_retained_once() {
    let fixture = RegenerateFixture::new("parse_regen", PROMOTED_HARNESS).await;
    let corpus = hf_service::workspace_dir(&fixture.project, "parse_regen").join("corpus");
    // Generated seeds (reserved namespace): one dies at entry, one survives.
    hf_corpus::seed(
        uuid::Uuid::new_v4(),
        &corpus,
        vec![
            (b"shallow-bytes".to_vec(), "seed_shallow".to_owned()),
            (b"deep-bytes".to_vec(), "seed_deep".to_owned()),
        ],
    )
    .await
    .unwrap();
    // An earned input the fuzzer found: never part of a regeneration.
    std::fs::write(corpus.join("earned"), b"fuzzer found me").unwrap();

    let outcome = fixture
        .container
        .regenerate_dead_seeds(&fixture.project, "parse_regen", TargetLanguage::C)
        .await
        .expect("regeneration should run");

    assert_eq!(outcome.removed_dead, 1, "{outcome:?}");
    assert_eq!(outcome.replacements_requested, 1, "{outcome:?}");
    // One dead seed requests exactly one replacement (the existing clamp).
    assert_eq!(outcome.replacements_added, 1, "{outcome:?}");
    assert_eq!(outcome.replacement_survives, 1, "{outcome:?}");
    assert!(
        fixture.pool.prompt_was_pending(),
        "the regenerate prompt row exists before the dispatch"
    );
    let drafts = fixture.drafts().await;
    assert_eq!(drafts.len(), 1, "{drafts:?}");
    let draft = &drafts[0];
    assert_eq!(draft.purpose, SeedDraftPurpose::Regenerate);
    assert_eq!(draft.response.as_deref(), Some(SEED_REPLY));
    let prompt = &draft.prompt;
    assert!(prompt.contains("Dead seeds"), "{prompt}");
    assert!(
        prompt.contains("\"7368616c6c6f772d6279746573\""),
        "the dead seed's bytes render as hex: {prompt}"
    );
    assert!(prompt.contains("Existing corpus seeds"), "{prompt}");
    assert!(
        prompt.contains("\"646565702d6279746573\""),
        "the surviving seed is part of the corpus sample: {prompt}"
    );
    assert!(prompt.contains("Harness entry"), "{prompt}");
    assert!(prompt.contains("Target definition (parse.c"), "{prompt}");
    assert!(corpus.join("earned").exists(), "earned inputs stay");
}

#[tokio::test]
async fn an_unretainable_regeneration_prompt_reports_zero_replacements() {
    // An entry-function comment line sized so the promoted harness stays
    // under the 64 KiB review-source cap while the assembled prompt (base +
    // definition + entry excerpt + seed samples) crosses the retained-prompt
    // cap: the regenerate prompt cannot be retained, so nothing may be
    // dispatched.
    let oversized = format!(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) {{\n\
         \x20 /* {} */\n\
         \x20 return n && d[0];\n}}\n",
        "A".repeat(65200)
    );
    let fixture = RegenerateFixture::new("parse_regen", &oversized).await;
    let corpus = hf_service::workspace_dir(&fixture.project, "parse_regen").join("corpus");
    hf_corpus::seed(
        uuid::Uuid::new_v4(),
        &corpus,
        vec![(b"shallow-bytes".to_vec(), "seed_shallow".to_owned())],
    )
    .await
    .unwrap();

    let outcome = fixture
        .container
        .regenerate_dead_seeds(&fixture.project, "parse_regen", TargetLanguage::C)
        .await
        .expect("regeneration should run");

    assert_eq!(outcome.removed_dead, 1, "{outcome:?}");
    assert_eq!(
        outcome.replacements_added, 0,
        "zero replacements come back from an unretained prompt: {outcome:?}"
    );
    assert_eq!(
        outcome.replacement_dies_at_entry + outcome.replacement_survives,
        0,
        "{outcome:?}"
    );
    assert_eq!(fixture.pool.seed_calls(), 0, "no prompt was dispatched");
    assert!(
        fixture.drafts().await.is_empty(),
        "no row was retained for a prompt that was never sent"
    );
}
