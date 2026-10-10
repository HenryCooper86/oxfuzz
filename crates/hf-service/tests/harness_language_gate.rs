//! Harness authoring refuses languages with no harness build path yet
//! (Go, Python): the denial is enforced inside the operations that would
//! draft, compile, generate, or refine the harness (Engineering Protocol
//! 2.19), with one message naming the language and the harnessable set from
//! the single `TargetLanguage::harnessable` predicate. No Docker, no
//! providers: the gate fires before either is consulted.

mod common;

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::{AiPolicy, FuzzRequest, ServiceContainer};

/// Pin this suite to a private config with the admission-gated go-native
/// engine enabled: it is the one configuration under which
/// `engine.supports_language(Go)` is true, so the harnessability predicate
/// (not engine support) is what must keep Go out of the pipeline.
fn install_go_native_config() {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "oxfuzz-lang-gate-config-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("oxfuzz.toml"),
            "[fuzzing]\n\
             collect_function_coverage = false\n\
             enabled_engines = [\"libfuzzer\", \"go-native\"]\n\
             default_engine = \"libfuzzer\"\n",
        )
        .unwrap();
        dir
    });
    // HF_CONFIG_DIR is process-global; every test in this binary calls this
    // installer so no test observes a different configuration.
    std::env::set_var("HF_CONFIG_DIR", dir);
}

/// A project with one exported, parameter-bearing Go function (a real
/// discovery result the harness pipeline cannot build yet).
fn go_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("goproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parser.go"),
        "package parser\n\nfunc ParsePacket(data []byte, offset int) bool {\n\treturn len(data) > offset\n}\n",
    )
    .unwrap();
    project
}

/// A project with one parameter-bearing Python function.
fn python_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("pyproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("codec.py"),
        "def decode_frame(data):\n    if data:\n        return data[1:]\n    return data\n",
    )
    .unwrap();
    project
}

fn gate_container(store: &Arc<hf_storage::Store>) -> ServiceContainer {
    ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(Arc::clone(store))
}

fn noop_stage() -> impl Fn(hf_service::FuzzStage) + Send + Sync {
    |_| {}
}

fn noop_progress() -> impl Fn(hf_service::FuzzProgress) + Send + Sync {
    |_| {}
}

fn assert_not_yet_harnessable(error: &hf_core::error::ClassifiedError, language: &str) {
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "harness generation is not yet available for {language} targets"
        )),
        "the language is named: {message}"
    );
    assert!(
        message.contains("harnessable languages: c, cpp, rust"),
        "the supported set is named: {message}"
    );
}

#[tokio::test]
async fn harness_draft_refuses_go_and_python_with_the_supported_set() {
    install_go_native_config();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("gate.db"))
            .await
            .unwrap(),
    );
    let container = gate_container(&store);

    for (project, target, language, id) in [
        (go_project(&dir), "ParsePacket", TargetLanguage::Go, "go"),
        (
            python_project(&dir),
            "decode_frame",
            TargetLanguage::Python,
            "python",
        ),
    ] {
        let error = container
            .harness_draft_with_policy(
                &project,
                target,
                EngineKind::LibFuzzer,
                language,
                AiPolicy::Off,
                None,
            )
            .await
            .expect_err("a discovery-only language must not be drafted");
        assert_not_yet_harnessable(&error, id);
    }
}

#[tokio::test]
async fn harness_compile_generate_and_refine_refuse_go_through_the_operations() {
    install_go_native_config();
    let _workspace_root = common::install_managed_workspace("oxfuzz_lang_gate_it");
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("gate.db"))
            .await
            .unwrap(),
    );
    let container = gate_container(&store);
    let project = go_project(&dir);

    let error = container
        .harness_compile(
            "// not a real harness".to_owned(),
            &project,
            EngineKind::LibFuzzer,
            "ParsePacket",
            TargetLanguage::Go,
            None,
        )
        .await
        .expect_err("a discovery-only language must not be compiled");
    assert_not_yet_harnessable(&error, "go");

    let error = container
        .harness_generate(
            &project,
            "ParsePacket",
            EngineKind::LibFuzzer,
            TargetLanguage::Go,
            0,
            None,
        )
        .await
        .expect_err("a discovery-only language must not be generated");
    assert_not_yet_harnessable(&error, "go");

    let error = container
        .harness_refine(
            &project,
            "ParsePacket",
            EngineKind::LibFuzzer,
            TargetLanguage::Go,
            1,
        )
        .await
        .expect_err("a discovery-only language must not be refined");
    assert_not_yet_harnessable(&error, "go");
}

#[tokio::test]
async fn fuzz_auto_pick_excludes_go_even_with_the_go_native_engine_enabled() {
    install_go_native_config();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("gate.db"))
            .await
            .unwrap(),
    );
    let container = gate_container(&store);
    let project = go_project(&dir);

    // `GoNative.supports_language(Go)` is true, so engine support alone would
    // auto-pick the Go target and fail later at the unimplemented build; the
    // harnessability predicate must exclude it at the pick.
    let error = container
        .fuzz_onboard(
            FuzzRequest {
                project: &project,
                target: None,
                engine: EngineKind::GoNative,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
            },
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .expect_err("a Go-only project cannot be auto-picked for fuzzing");

    let message = error.to_string();
    assert!(
        message.contains("discovered 1 candidate(s)"),
        "the discovery result is reported, not hidden: {message}"
    );
    assert!(
        message.contains("not yet available for their language(s) (go)"),
        "the capability gap is named: {message}"
    );
    assert!(
        message.contains("harnessable languages: c, cpp, rust"),
        "the supported set is named: {message}"
    );
}

#[tokio::test]
async fn fuzz_with_an_explicit_go_target_fails_naming_the_language() {
    install_go_native_config();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("gate.db"))
            .await
            .unwrap(),
    );
    let container = gate_container(&store);
    let project = go_project(&dir);

    let error = container
        .fuzz_onboard(
            FuzzRequest {
                project: &project,
                target: Some("ParsePacket"),
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
            },
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .expect_err("an explicit discovery-only target is refused");

    assert_not_yet_harnessable(&error, "go");
}

#[tokio::test]
async fn campaign_refuses_a_discovery_only_language_before_picking_a_target() {
    install_go_native_config();
    let _workspace_root = common::install_managed_workspace("oxfuzz_lang_gate_it");
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("gate.db"))
            .await
            .unwrap(),
    );
    let container = gate_container(&store);
    let project = python_project(&dir);

    let error = container
        .run_campaign(
            &project,
            None,
            EngineKind::LibFuzzer,
            TargetLanguage::Python,
            1,
            None,
            None,
            None,
            1,
        )
        .await
        .expect_err("a campaign over a discovery-only language fails before auto-pick");
    assert_not_yet_harnessable(&error, "python");
}
