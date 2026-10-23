//! Stable-id saved report publication regressions.
//!
//! A saved report draft is published through its *stored* identity: the
//! service resolves the draft by id once, and that resolved snapshot's saved
//! project/target is what gets published -- never a presentation-layer copy
//! (the HTTP DTO redacts `project`) and never a re-read after authorization.
//! A transport whose authorization resolves the owner to a canonical path
//! binds that canonical owner into the same snapshot before executing it.
//!
//! The test process runs with its own isolated `HF_REPORTS_DIR` and
//! `HF_CONFIG_DIR` (unique directories under the system temp dir, the
//! `DefectDojo` integration pointed at a process-local stub), installed once
//! before any test body runs, so no real report data or integration is ever
//! touched. Each test uses a uniquely named project directory so its
//! captured import is identifiable regardless of parallel test execution.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use chrono::{Duration, Utc};
use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::ServiceContainer;
use hf_storage::{RunRecord, RunStatus, Store};
use hf_test_utils::defectdojo_stub::DefectDojoStub;
use uuid::Uuid;

struct FixtureEnv {
    reports_dir: PathBuf,
    stub: DefectDojoStub,
}

/// The isolated directories and stub integration for this test process.
static ENV: LazyLock<FixtureEnv> = LazyLock::new(|| {
    let stub = DefectDojoStub::start();
    let unique = format!("{}_{}", std::process::id(), Uuid::new_v4());
    let config_dir = std::env::temp_dir().join(format!("oxfuzz_report_push_config_{unique}"));
    let reports_dir = std::env::temp_dir().join(format!("oxfuzz_report_push_reports_{unique}"));
    std::fs::create_dir_all(&config_dir).expect("create isolated config dir");
    std::fs::create_dir_all(&reports_dir).expect("create isolated reports dir");
    std::fs::write(
        config_dir.join("defectdojo.toml"),
        format!("url = \"{}\"\napi_token = \"stub-token\"\n", stub.url()),
    )
    .expect("write stub defectdojo config");
    // This test binary owns these variables for the whole process and sets
    // each exactly once (lazy initialization before any test body reads
    // them), so no concurrent mutation can race the override.
    std::env::set_var("HF_CONFIG_DIR", &config_dir);
    std::env::set_var("HF_REPORTS_DIR", &reports_dir);
    FixtureEnv { reports_dir, stub }
});

/// Imports captured for `product`, the requesting test's unique project name.
fn imports_for(product: &str) -> Vec<hf_test_utils::defectdojo_stub::CapturedImport> {
    ENV.stub.imports_for(product)
}

// ---------------------------------------------------------------------------
// Store-backed project fixture (the in-crate pattern of `finding_review`)
// ---------------------------------------------------------------------------

struct ProjectFixture {
    container: ServiceContainer,
    directory: tempfile::TempDir,
    /// Unique directory basename: doubles as the `DefectDojo` product name.
    product: String,
    symbol: String,
}

/// One project directory whose latest retained run has exactly one triaged
/// crash on `symbol`. `label` must be unique per test.
async fn project(label: &str, symbol: &str) -> ProjectFixture {
    let _env = &*ENV;
    let directory = tempfile::tempdir().expect("project directory");
    let product = format!("owner-{label}");
    let project_dir = directory.path().join(&product);
    std::fs::create_dir_all(&project_dir).expect("create project root");
    std::fs::write(
        project_dir.join("target.c"),
        "int symbol_under_test(void);\n",
    )
    .expect("seed source");

    let store = Arc::new(
        Store::connect(directory.path().join("reports.db"))
            .await
            .expect("connect store"),
    );
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project_dir.clone(),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("target.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 3,
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
        source: "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_bin"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
        custom_mutator: None,
        cmplog: None,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();

    let older = run(&project_dir, harness.id, -10);
    let latest = run(&project_dir, harness.id, 0);
    store.insert_run(&older).await.unwrap();
    store.insert_run(&latest).await.unwrap();
    // Only the latest retained run carries a crash, so a correct push carries
    // exactly one finding.
    store
        .upsert_crash(&Crash {
            reproduction: None,
            id: Uuid::new_v4(),
            run_id: latest.id,
            target_id: target.id,
            input_path: PathBuf::from(format!("runs/{}/crashes/input", latest.id)),
            stack_signature: "sigma-latest".to_owned(),
            kind: CrashKind::Asan,
            summary: "heap-buffer-overflow".to_owned(),
            minimized: true,
            bug_report: None,
            casr: None,
            origin: CrashOrigin::Target,
        })
        .await
        .unwrap();

    let container = ServiceContainer::stubbed().with_store(store);
    ProjectFixture {
        container,
        directory,
        product,
        symbol: symbol.to_owned(),
    }
}

fn run(project_dir: &Path, harness_id: Uuid, offset_minutes: i64) -> RunRecord {
    let mut run = RunRecord::new(
        project_dir.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id,
            engine: EngineKind::LibFuzzer,
            duration: None,
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
            input_timeout: None,
            resume: false,
            cmplog: false,
        }),
        Utc::now() + Duration::minutes(offset_minutes),
    );
    run.status = RunStatus::Done;
    run.ended_at = Some(run.started_at + Duration::seconds(30));
    run
}

fn project_root(fixture: &ProjectFixture) -> PathBuf {
    fixture.directory.path().join(&fixture.product)
}

// ---------------------------------------------------------------------------
// Regressions
// ---------------------------------------------------------------------------

/// A saved report publishes through its stored identity: resolving by id
/// yields the saved owner/target, and the push carries exactly that owner's
/// product and target -- the *other* active project's evidence is irrelevant.
#[tokio::test]
async fn saved_report_push_publishes_its_resolved_owner_and_saved_target() {
    let alpha = project("alpha", "parse_alpha").await;
    let beta = project("beta", "parse_beta").await;
    // The report belongs to alpha, even though beta is equally active.
    let saved = alpha
        .container
        .save_report_draft(
            None,
            "Alpha campaign",
            &project_root(&alpha).to_string_lossy(),
            Some(&alpha.symbol),
            "Approved",
            "# Alpha campaign",
        )
        .unwrap();

    let publication = alpha
        .container
        .resolve_report_publication(&saved.id)
        .expect("resolve saved report by stable id");
    assert_eq!(publication.project(), project_root(&alpha));
    assert_eq!(publication.target(), Some(alpha.symbol.as_str()));

    let outcome = alpha
        .container
        .push_report_to_defectdojo(&publication)
        .await
        .expect("push saved report");

    assert_eq!(outcome.findings_pushed, 1);
    let captured = imports_for(&alpha.product);
    assert_eq!(
        captured.len(),
        1,
        "exactly one import for the saved owner's product"
    );
    assert_eq!(
        captured[0].field("product_name"),
        Some(alpha.product.as_str())
    );
    assert_eq!(
        captured[0].field("test_title"),
        Some(format!("oxfuzz: {}", alpha.symbol).as_str()),
        "the saved target names the DefectDojo test"
    );
    assert_eq!(captured[0].findings_count(), 1);
    assert_eq!(captured[0].authorization, "Token stub-token");
    assert!(
        captured[0].path.contains("import-scan"),
        "the push went through the DefectDojo import endpoint: {}",
        captured[0].path
    );
    assert!(
        imports_for(&beta.product).is_empty(),
        "the other active project's product is never published"
    );
}

/// A draft save atomically replaces the stored file, possibly repointing the
/// same report id at a different project. Authorization and execution must
/// consume the SAME resolved snapshot: after resolving alpha's report, an
/// overwrite to beta on disk cannot change what the push publishes.
#[tokio::test]
async fn concurrent_draft_repoint_cannot_change_the_published_owner() {
    let alpha = project("repoint-a", "parse_repoint_a").await;
    let beta = project("repoint-b", "parse_repoint_b").await;
    let saved = alpha
        .container
        .save_report_draft(
            None,
            "Alpha campaign",
            &project_root(&alpha).to_string_lossy(),
            Some(&alpha.symbol),
            "Approved",
            "# Alpha campaign",
        )
        .unwrap();

    let publication = alpha
        .container
        .resolve_report_publication(&saved.id)
        .expect("resolve the pre-edit snapshot");

    // Concurrent draft edit: the same report id is repointed at beta.
    alpha
        .container
        .save_report_draft(
            Some(saved.id.clone()),
            "Hijacked",
            &project_root(&beta).to_string_lossy(),
            Some(&beta.symbol),
            "Approved",
            "# Hijacked",
        )
        .unwrap();
    let repointed = alpha
        .container
        .resolve_report_publication(&saved.id)
        .expect("the stored file really did change");
    assert_eq!(repointed.project(), project_root(&beta));

    // The already-resolved snapshot still publishes alpha + its saved target.
    alpha
        .container
        .push_report_to_defectdojo(&publication)
        .await
        .expect("push the resolved snapshot");

    let captured = imports_for(&alpha.product);
    assert_eq!(
        captured.len(),
        1,
        "the resolved snapshot published its own owner"
    );
    assert_eq!(
        captured[0].field("test_title"),
        Some(format!("oxfuzz: {}", alpha.symbol).as_str()),
        "and its own saved target"
    );
    assert!(
        imports_for(&beta.product).is_empty(),
        "the concurrent repoint never reached the sink"
    );
}

/// A transport whose authorization resolves the saved owner to a canonical
/// path (e.g. a symlinked alias inside the approved roots) binds that
/// canonical owner into the snapshot: execution publishes the canonical
/// directory while the saved target still names the test.
#[cfg(unix)]
#[tokio::test]
async fn canonical_owner_binding_executes_the_approved_canonical_path() {
    let fixture = project("canonical", "parse_canonical").await;
    let real_root = project_root(&fixture);
    let alias = fixture.directory.path().join("alias-to-owner");
    std::os::unix::fs::symlink(&real_root, &alias).expect("symlink the saved owner alias");
    let saved = fixture
        .container
        .save_report_draft(
            None,
            "Aliased campaign",
            &alias.to_string_lossy(),
            Some(&fixture.symbol),
            "Approved",
            "# Aliased campaign",
        )
        .unwrap();

    let publication = fixture
        .container
        .resolve_report_publication(&saved.id)
        .expect("resolve the alias-saved report");
    assert_eq!(publication.project(), alias);
    // The transport binds the authorization resolver's canonical result into
    // the same snapshot, preserving the saved target.
    let bound =
        publication.with_canonical_project(alias.canonicalize().expect("canonicalize the alias"));
    assert_eq!(
        bound.project(),
        real_root.canonicalize().expect("canonical real root"),
        "the bound owner is the canonical directory the resolver returns"
    );
    assert_eq!(bound.target(), Some(fixture.symbol.as_str()));

    fixture
        .container
        .push_report_to_defectdojo(&bound)
        .await
        .expect("push the canonically-bound snapshot");

    let captured = imports_for(&fixture.product);
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].field("product_name"),
        Some(fixture.product.as_str()),
        "the canonical directory names the product, not the alias"
    );
    assert_eq!(
        captured[0].field("test_title"),
        Some(format!("oxfuzz: {}", fixture.symbol).as_str())
    );
    assert!(
        imports_for("alias-to-owner").is_empty(),
        "the raw alias spelling never names the published product"
    );
}

/// An unknown or malformed report id refuses at resolution, before any
/// downstream transport is attempted, without disclosing stored paths.
#[tokio::test]
async fn missing_report_id_refuses_before_downstream_transport() {
    let fixture = project("missing", "parse_missing").await;

    let missing = fixture
        .container
        .resolve_report_publication("no-such-report")
        .expect_err("unknown report id must refuse");
    let message = missing.to_string();
    assert!(
        message.contains("not found"),
        "error names the refusal: {message}"
    );
    assert!(
        !message.contains("owner-"),
        "error discloses no stored owner path: {message}"
    );

    let malformed = fixture
        .container
        .resolve_report_publication("../escape")
        .expect_err("unsafe report id must refuse");
    assert!(malformed.to_string().contains("report id"));

    assert!(
        imports_for(&fixture.product).is_empty(),
        "no transport happened for this test's product"
    );
}

/// An undecodable stored draft refuses with bounded error text: decode
/// failures never echo file contents (which carry the saved owner path).
#[tokio::test]
async fn undecodable_draft_refuses_with_bounded_error_text() {
    let fixture = project("undecodable", "parse_undecodable").await;
    let secret_owner = "/very/secret/stored-owner";
    std::fs::write(
        ENV.reports_dir.join("undecodable-draft.json"),
        format!(r#"{{"id":"undecodable-draft","title":"t","project":"{secret_owner}","target":null,"status":"Draft","updated_at":"now","content":7}}"#),
    )
    .unwrap();

    let error = fixture
        .container
        .resolve_report_publication("undecodable-draft")
        .expect_err("undecodable draft must refuse");
    assert!(
        !error.to_string().contains(secret_owner),
        "decode error is bounded and never echoes stored content: {error}"
    );
    assert!(
        imports_for(&fixture.product).is_empty(),
        "no transport happened for this test's product"
    );
}

/// The existing project-scoped publication entry point is unaffected: it
/// still publishes the requested project's own latest evidence.
#[tokio::test]
async fn existing_project_publication_is_unaffected() {
    let fixture = project("legacy", "parse_legacy").await;

    let outcome = fixture
        .container
        .push_to_defectdojo(&project_root(&fixture), Some(&fixture.symbol))
        .await
        .expect("project-scoped push still works");

    assert_eq!(outcome.findings_pushed, 1);
    let captured = imports_for(&fixture.product);
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].field("product_name"),
        Some(fixture.product.as_str())
    );
    assert_eq!(
        captured[0].field("test_title"),
        Some(format!("oxfuzz: {}", fixture.symbol).as_str())
    );
}
