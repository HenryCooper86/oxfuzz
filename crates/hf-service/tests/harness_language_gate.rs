//! Go, Python, Java, and JavaScript are harnessable only under the engine
//! that runs each (go-native, atheris, jazzer, jazzer-js). A request that pairs one with another
//! engine is refused inside the operations that would draft, compile,
//! generate, refine, fuzz, or campaign (Engineering Protocol 2.19), naming
//! the language and the engine. No Docker, no providers: the gate fires
//! before either is consulted.

mod common;

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::{AiPolicy, FuzzRequest, ServiceContainer};

/// Pin this suite to a private config with the admission-gated go-native
/// engine enabled beside libFuzzer, so a Go target can be requested under
/// either.
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

/// A project with one exported Go function that takes a struct: a real
/// discovery result outside the supported Go target class.
fn go_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("goproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parser.go"),
        "package parser\n\ntype Options struct{ Offset int }\n\nfunc ParsePacket(data []byte, options Options) bool {\n\treturn len(data) > options.Offset\n}\n",
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

/// A project with one public static Java method.
fn java_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("javaproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("Frames.java"),
        "public final class Frames {\n    public static int parse(byte[] data) {\n        return data.length;\n    }\n}\n",
    )
    .unwrap();
    project
}

/// A Node.js project with one exported, documented JavaScript function.
fn javascript_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("jsproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("package.json"), "{ \"name\": \"frames\" }\n").unwrap();
    std::fs::write(
        project.join("frames.js"),
        "/** @param {Buffer} data */\nfunction parseFrame(data) {\n  return data.length;\n}\nmodule.exports = { parseFrame };\n",
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

/// The refusal for a language requested under an engine that does not run it.
fn assert_engine_does_not_run(error: &hf_core::error::ClassifiedError, language: &str) {
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "{language} harnesses are not supported by fuzzing engine 'libfuzzer'"
        )),
        "the language and the engine are named: {message}"
    );
}

fn fuzz_request<'a>(
    project: &'a std::path::Path,
    target: Option<&'a str>,
    engine: EngineKind,
) -> FuzzRequest<'a> {
    FuzzRequest {
        prepared_harness: None,
        project,
        target,
        engine,
        lang: None,
        duration_secs: 1,
        iterations: 1,
        timeout_ms: None,
        resume: None,
        review_bypass: hf_service::HarnessReviewBypass::NotRequested,
        fresh: false,
        sanitizer: None,
        cmplog: false,
        seed: None,
    }
}

#[tokio::test]
async fn harness_draft_refuses_a_managed_language_under_another_engine() {
    install_go_native_config();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("gate.db"))
            .await
            .unwrap(),
    );
    let container = gate_container(&store);

    for (project, target, language, name) in [
        (go_project(&dir), "ParsePacket", TargetLanguage::Go, "Go"),
        (
            python_project(&dir),
            "decode_frame",
            TargetLanguage::Python,
            "Python",
        ),
        (
            java_project(&dir),
            "Frames.parse",
            TargetLanguage::Java,
            "Java",
        ),
        (
            javascript_project(&dir),
            "parseFrame",
            TargetLanguage::JavaScript,
            "JavaScript",
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
                false,
            )
            .await
            .expect_err("libFuzzer does not run this language");
        assert_engine_does_not_run(&error, name);
    }
}

#[tokio::test]
async fn harness_compile_generate_and_refine_refuse_go_under_another_engine() {
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
            false,
        )
        .await
        .expect_err("libFuzzer does not compile a Go harness");
    assert_engine_does_not_run(&error, "Go");

    let error = container
        .harness_generate(
            &project,
            "ParsePacket",
            EngineKind::LibFuzzer,
            TargetLanguage::Go,
            0,
            None,
            false,
            false,
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect_err("libFuzzer does not generate a Go harness");
    assert_engine_does_not_run(&error, "Go");

    let error = container
        .harness_refine(
            &project,
            "ParsePacket",
            EngineKind::LibFuzzer,
            TargetLanguage::Go,
            1,
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect_err("libFuzzer does not refine a Go harness");
    assert_engine_does_not_run(&error, "Go");
}

#[tokio::test]
async fn fuzz_auto_pick_takes_a_go_target_under_go_native_and_names_the_supported_class() {
    install_go_native_config();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("gate.db"))
            .await
            .unwrap(),
    );
    let container = gate_container(&store);
    let project = go_project(&dir);

    // Under go-native the Go target is picked and reaches the harness stage.
    // This one takes a struct, so the template refuses it by its signature
    // instead of the pick hiding it.
    let error = container
        .fuzz_onboard(
            fuzz_request(&project, None, EngineKind::GoNative),
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .expect_err("a Go function taking a struct is outside the supported class");

    let message = error.to_string();
    assert!(message.contains("fuzz harness failed"), "{message}");
    assert!(
        message.contains("'ParsePacket' is not in the supported Go target class"),
        "the target and the class are named: {message}"
    );
    assert!(
        message.contains("found: func ParsePacket(data []byte, options Options) bool"),
        "the signature that was found is quoted: {message}"
    );
}

#[tokio::test]
async fn fuzz_with_an_explicit_go_target_under_another_engine_names_the_engine() {
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
            fuzz_request(&project, Some("ParsePacket"), EngineKind::LibFuzzer),
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .expect_err("libFuzzer does not run a Go target");

    let message = error.to_string();
    assert!(
        message.contains("engine 'libfuzzer' cannot drive a Go harness for 'ParsePacket'"),
        "{message}"
    );
}

#[tokio::test]
async fn campaign_refuses_a_language_its_engine_cannot_drive_before_picking_a_target() {
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
            None,
            None,
            1,
        )
        .await
        .expect_err("a campaign names the engine mismatch, not a missing harness");
    let message = error.to_string();
    assert!(
        message.contains(
            "engine 'libfuzzer' cannot drive python targets (python targets run under --engine \
             atheris)"
        ),
        "{message}"
    );
    assert!(!message.contains("compile the harness first"), "{message}");
}
