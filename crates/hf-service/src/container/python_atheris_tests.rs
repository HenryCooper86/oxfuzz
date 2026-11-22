//! Python fuzzing through the service's own building blocks: the template
//! draft, module staging, the syntax-only build, the bounded Atheris run,
//! artifact collection, replay, classification, and the retained sources a
//! run imports from.
//!
//! The live test needs the pinned sandbox image; the rest runs anywhere.

use std::path::Path;

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use uuid::Uuid;

use super::harness_workspace::copy_project_sources;

/// A table lookup that trusts an input byte as its index.
const FRAMES_PY: &str = "TABLE = [1, 2, 3]\n\n\ndef parse(data):\n    if len(data) > 3 and data[0] == 0x4D and data[1] == 0x5A:\n        return TABLE[data[2]]\n    return 0\n";

/// The same lookup with the index checked.
const FRAMES_PY_FIXED: &str = "TABLE = [1, 2, 3]\n\n\ndef parse(data):\n    if len(data) > 3 and data[0] == 0x4D and data[1] == 0x5A:\n        if data[2] < len(TABLE):\n            return TABLE[data[2]]\n    return 0\n";

fn python_project(root: &Path, frames: &str) -> TargetCandidate {
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(root.join("pkg/__init__.py"), "").unwrap();
    std::fs::write(root.join("pkg/frames.py"), frames).unwrap();
    // A project file with the harness's own name must not replace it.
    std::fs::write(root.join("harness.py"), "raise SystemExit(3)\n").unwrap();
    std::fs::write(root.join("README.md"), "not staged\n").unwrap();
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: root.to_path_buf(),
        language: TargetLanguage::Python,
        symbol: "parse".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: root.join("pkg/frames.py"),
            line: 4,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("def parse(data)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 3,
        fit_score: 1.0,
        sanitizers: Vec::new(),
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 3,
    }
}

#[test]
fn a_python_draft_is_the_fixed_script_for_the_atheris_engine_only() {
    let project = tempfile::tempdir().unwrap();
    let candidate = python_project(project.path(), FRAMES_PY);
    let draft =
        super::heuristic_draft(&candidate, EngineKind::Atheris, Sanitizer::Address, false).unwrap();
    assert!(draft
        .source
        .starts_with("#!/usr/bin/python3 -I\n# oxfuzz:python-target . pkg.frames:parse bytes\n"));
    assert_eq!(draft.build_cmd.compiler, "python3");
    assert_eq!(
        &draft.build_cmd.args[3..],
        ["harness.py", "fuzz_parse", "pkg/frames"]
    );
    assert_eq!(draft.generator, hf_core::harness::DraftGenerator::Heuristic);
    assert!(hf_harness::lint_harness_source(&draft.source, TargetLanguage::Python).is_empty());

    for engine in [EngineKind::LibFuzzer, EngineKind::AflPlusPlus] {
        let wrong_engine =
            super::heuristic_draft(&candidate, engine, Sanitizer::Address, false).unwrap_err();
        assert!(
            wrong_engine
                .to_string()
                .contains("Python targets build only for the atheris engine"),
            "{wrong_engine}"
        );
    }
    let sanitizer =
        super::heuristic_draft(&candidate, EngineKind::Atheris, Sanitizer::Memory, false)
            .unwrap_err();
    assert!(
        sanitizer.to_string().contains("does not apply to Python"),
        "{sanitizer}"
    );
    let persistent =
        super::heuristic_draft(&candidate, EngineKind::Atheris, Sanitizer::Address, true);
    assert!(persistent.is_err(), "persistent mode is AFL++ C/C++ only");

    let mut method = candidate;
    method.symbol = "Codec.parse".to_owned();
    method.signature = Some("def parse(self, data)".to_owned());
    let refused = super::heuristic_draft(&method, EngineKind::Atheris, Sanitizer::Address, false)
        .unwrap_err();
    assert!(refused.to_string().contains("is a method"), "{refused}");
}

#[test]
fn python_modules_are_staged_and_retained_as_the_run_imports_them() {
    let project = tempfile::tempdir().unwrap();
    let candidate = python_project(project.path(), FRAMES_PY);
    let workspace = tempfile::tempdir().unwrap();
    copy_project_sources(project.path(), workspace.path());
    assert!(workspace.path().join("pkg/frames.py").is_file());
    assert!(workspace.path().join("pkg/__init__.py").is_file());
    assert!(!workspace.path().join("harness.py").exists());
    assert!(!workspace.path().join("README.md").exists());

    // The "binary" of a Python harness is the executable script itself.
    let source = hf_harness::python_atheris::template(&candidate).unwrap();
    let script = workspace.path().join("fuzz_parse");
    std::fs::write(&script, &source).unwrap();
    std::fs::write(workspace.path().join("harness.py"), &source).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run_id = Uuid::new_v4();
    let artifacts =
        super::staging::stage_run_artifacts(workspace.path(), run_id, &source, &script, None)
            .unwrap();
    assert_eq!(
        std::fs::read_to_string(&artifacts.binary_host).unwrap(),
        source
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&artifacts.binary_host)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "the staged script stays executable");
    }
    // The retained sources sit beside the staged script under the name the
    // script looks for, without the generated harness.
    assert_eq!(
        artifacts.source_context_host,
        artifacts
            .binary_host
            .with_file_name(hf_harness::python_atheris::RETAINED_SOURCES_DIR)
    );
    assert_eq!(
        std::fs::read_to_string(artifacts.source_context_host.join("pkg/frames.py")).unwrap(),
        FRAMES_PY
    );
    assert!(artifacts
        .source_context_host
        .join("pkg/__init__.py")
        .is_file());
    assert!(!artifacts.source_context_host.join("harness.py").exists());
}

#[test]
fn a_vendored_python_package_is_staged_and_retained_with_its_data_files() {
    let project = tempfile::tempdir().unwrap();
    let candidate = python_project(project.path(), FRAMES_PY);
    let write = |relative: &str, text: &str| {
        let path = project.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    // A pure-Python package reads the files it ships: a table, a marker, a
    // module in a directory whose name staging skips in the project's own
    // tree.
    let carried = [
        "vendor/python/tinycodec/__init__.py",
        "vendor/python/tinycodec/tables/default.json",
        "vendor/python/tinycodec/py.typed",
        "vendor/python/tinycodec/build/generated.py",
    ];
    for relative in carried {
        write(relative, "x = 1\n");
    }
    // Outside the vendored tree only Python modules are project input.
    write("docs/notes.json", "{}\n");
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "/etc/hosts",
        project.path().join("vendor/python/tinycodec/hosts"),
    )
    .unwrap();

    let workspace = tempfile::tempdir().unwrap();
    copy_project_sources(project.path(), workspace.path());
    for relative in carried {
        assert!(workspace.path().join(relative).is_file(), "{relative}");
    }
    assert!(!workspace.path().join("docs/notes.json").exists());
    assert!(!workspace
        .path()
        .join("vendor/python/tinycodec/hosts")
        .exists());

    let source = hf_harness::python_atheris::template(&candidate).unwrap();
    let script = workspace.path().join("fuzz_parse");
    std::fs::write(&script, &source).unwrap();
    let artifacts = super::staging::stage_run_artifacts(
        workspace.path(),
        Uuid::new_v4(),
        &source,
        &script,
        None,
    )
    .unwrap();
    for relative in carried {
        assert!(
            artifacts.source_context_host.join(relative).is_file(),
            "{relative}"
        );
    }
}

fn run_config(harness: &Harness, seconds: u64) -> FuzzRunConfig {
    FuzzRunConfig {
        harness_id: harness.id,
        engine: harness.engine,
        duration: Some(std::time::Duration::from_secs(seconds)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: harness.sanitizer,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: None,
        replay_of: None,
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
        cmplog: false,
    }
}

async fn check(
    runtime: &hf_runtime::docker::DockerRuntime,
    project: &Path,
    candidate: &TargetCandidate,
    workspace: &Path,
) -> hf_harness::CompileResult {
    copy_project_sources(project, workspace);
    let draft =
        super::heuristic_draft(candidate, EngineKind::Atheris, Sanitizer::Address, false).unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: candidate.id,
        engine: EngineKind::Atheris,
        source: draft.source,
        language: TargetLanguage::Python,
        build_cmd: draft.build_cmd,
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
        cmplog: None,
        custom_mutator: None,
    };
    hf_harness::try_compile_with_options(
        harness,
        runtime,
        workspace,
        &hf_core::runtime::SandboxOptions::default(),
    )
    .await
    .unwrap()
}

async fn smoke(
    runtime: &hf_runtime::docker::DockerRuntime,
    harness: Harness,
    workspace: &Path,
) -> Result<Harness, hf_core::error::ClassifiedError> {
    let config = run_config(&harness, 20);
    hf_harness::generator::smoke_fuzz_in_paths_with_config_and_sandbox_image(
        harness,
        runtime,
        workspace,
        Path::new("corpus"),
        Path::new("out"),
        &config,
        None,
    )
    .await
}

async fn replay(
    runtime: &hf_runtime::docker::DockerRuntime,
    workspace: &Path,
    script: &str,
    input: &str,
) -> (i32, String) {
    use hf_core::runtime::RuntimeAdapter as _;
    let result = runtime
        .run_command_opts(
            &[script.to_owned(), input.to_owned()],
            workspace,
            &hf_core::runtime::ResourceLimits {
                max_mem_mb: 2048,
                max_cpus: 1,
                max_duration_secs: 30,
                env: std::collections::HashMap::new(),
                ptrace: false,
            },
            &hf_core::runtime::SandboxOptions {
                workspace_read_only: true,
                ..hf_core::runtime::SandboxOptions::default()
            },
        )
        .await
        .unwrap();
    (
        result.exit_code,
        format!("{}\n{}", result.stdout, result.stderr),
    )
}

/// Replace a file with a new one under the same name. A file rewritten in
/// place can be read through the sandbox mount with its previous size for a
/// moment after a container last looked at it; a rename has no such window.
fn replace_file(path: &Path, text: &str) {
    let fresh = path.with_extension("replacement");
    std::fs::write(&fresh, text).unwrap();
    std::fs::rename(&fresh, path).unwrap();
}

/// Check, fuzz, collect, replay, and classify a planted Python defect in the
/// real sandbox; show the run's retained sources are what a staged run
/// imports; show the corrected function fuzzes clean; and show that an
/// unimportable module and a syntax error fail as such, not as findings.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_atheris_finds_replays_and_classifies_a_planted_exception() {
    assert!(hf_runtime::docker_daemon_ready());
    let project = tempfile::tempdir().unwrap();
    let candidate = python_project(project.path(), FRAMES_PY);
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    let hf_harness::CompileResult::Ok(checked) =
        check(&runtime, project.path(), &candidate, &workspace).await
    else {
        panic!("the syntax-only build failed");
    };
    assert_eq!(checked.build_cmd.output, workspace.join("fuzz_parse"));
    assert!(workspace.join("fuzz_parse").is_file());
    let source = checked.source.clone();

    let smoked = smoke(&runtime, *checked, &workspace).await.unwrap();
    let summary = smoked.smoke_run.clone().unwrap();
    println!("smoke: {summary:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(summary.crashes > 0, "the planted defect was found");

    let out = workspace.join("out");
    let ingested =
        hf_crash::ingest_for_engine(&out, EngineKind::Atheris, Uuid::new_v4(), candidate.id)
            .unwrap();
    assert_eq!(ingested.crashes.len(), 1, "{:?}", ingested.crashes);
    let input = ingested.crashes[0].input_path.clone();
    let name = input.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("crash-"), "{name}");
    let bytes = std::fs::read(&input).unwrap();
    assert!(bytes.starts_with(b"MZ") && bytes[2] > 2, "{bytes:?}");

    // Replay as triage does: the script, then the input.
    let container_input = format!("/work/out/{name}");
    let (exit_code, log) = replay(&runtime, &workspace, "/work/fuzz_parse", &container_input).await;
    assert_eq!(exit_code, 77, "{log}");
    assert!(hf_crash::looks_like_crash(&log), "{log}");
    let (kind, signature, classified) = hf_crash::classify(&log);
    println!("classified: {kind:?} {classified}");
    assert_eq!(kind, hf_core::crash::CrashKind::Panic);
    assert_eq!(classified, "IndexError: list index out of range");

    // A staged run imports the sources retained with it, not the workspace:
    // changing the workspace module does not change what the run executes,
    // and the same defect signs the same from either place.
    let run_id = Uuid::new_v4();
    let artifacts = super::staging::stage_run_artifacts(
        &workspace,
        run_id,
        &source,
        &workspace.join("fuzz_parse"),
        None,
    )
    .unwrap();
    replace_file(&workspace.join("pkg/frames.py"), FRAMES_PY_FIXED);
    let (staged_exit, staged_log) = replay(
        &runtime,
        &workspace,
        &artifacts.binary_container,
        &container_input,
    )
    .await;
    assert_eq!(staged_exit, 77, "{staged_log}");
    assert!(
        staged_log.contains(&format!(
            "/work/runs/{run_id}/input/source-context/pkg/frames.py"
        )),
        "{staged_log}"
    );
    assert_eq!(hf_crash::classify(&staged_log).1, signature);
    let (workspace_exit, workspace_log) =
        replay(&runtime, &workspace, "/work/fuzz_parse", &container_input).await;
    assert_eq!(
        workspace_exit, 0,
        "the corrected module passes: {workspace_log}"
    );
    assert!(
        !hf_crash::looks_like_crash(&workspace_log),
        "{workspace_log}"
    );

    // The corrected function: same harness, clean smoke with throughput.
    std::fs::write(project.path().join("pkg/frames.py"), FRAMES_PY_FIXED).unwrap();
    let fixed_workspace = root.path().join("fixed");
    std::fs::create_dir_all(&fixed_workspace).unwrap();
    let hf_harness::CompileResult::Ok(fixed) =
        check(&runtime, project.path(), &candidate, &fixed_workspace).await
    else {
        panic!("the syntax-only build of the corrected project failed");
    };
    let fixed = smoke(&runtime, *fixed, &fixed_workspace).await.unwrap();
    let fixed_summary = fixed.smoke_run.clone().unwrap();
    println!("fixed smoke: {fixed_summary:?}");
    assert_eq!(fixed_summary.crashes, 0);
    assert!(fixed_summary.passed && fixed_summary.execs_per_sec > 0.0);
    assert!(
        std::fs::read_dir(fixed_workspace.join("corpus"))
            .unwrap()
            .count()
            > 0,
        "the run kept the inputs that reached new code"
    );

    // A syntax error in the selected module fails the build, before any
    // import.
    std::fs::write(project.path().join("pkg/frames.py"), "def parse(data:\n").unwrap();
    let broken_workspace = root.path().join("broken");
    std::fs::create_dir_all(&broken_workspace).unwrap();
    match check(&runtime, project.path(), &candidate, &broken_workspace).await {
        hf_harness::CompileResult::Failed(failure) => {
            assert!(failure.stderr.contains("SyntaxError"), "{}", failure.stderr);
        }
        hf_harness::CompileResult::Ok(_) => panic!("a syntax error must fail the build"),
    }

    // A module that parses but cannot be imported is a failed smoke, not a
    // finding.
    std::fs::write(
        project.path().join("pkg/frames.py"),
        "import a_package_that_is_not_staged\n\n\ndef parse(data):\n    return 0\n",
    )
    .unwrap();
    let unimportable_workspace = root.path().join("unimportable");
    std::fs::create_dir_all(&unimportable_workspace).unwrap();
    let hf_harness::CompileResult::Ok(unimportable) = check(
        &runtime,
        project.path(),
        &candidate,
        &unimportable_workspace,
    )
    .await
    else {
        panic!("the module parses, so the build passes");
    };
    let error = smoke(&runtime, *unimportable, &unimportable_workspace)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("outside fuzzing"), "{error}");
    assert!(error.contains("ModuleNotFoundError"), "{error}");
    assert!(hf_crash::ingest_for_engine(
        &unimportable_workspace.join("out"),
        EngineKind::Atheris,
        Uuid::new_v4(),
        candidate.id,
    )
    .unwrap()
    .crashes
    .is_empty());
}

/// A decoder whose behavior depends on typed arguments and that leans on a
/// vendored pure-Python package: it trusts the first body byte as an index,
/// but only for kind 7 in strict mode.
const TYPED_PY: &str = "import tinycodec\n\nTABLE = [1, 2, 3]\n\n\ndef decode(kind: int, strict: bool, body: bytes):\n    if kind % 256 != 7 or not strict or len(body) < 2:\n        return 0\n    return TABLE[tinycodec.first(body)]\n";

/// A function with typed parameters, in a project that vendors the package
/// it imports, is checked, fuzzed, and its planted exception found: the data
/// provider supplies the arguments and `vendor/python` supplies the import.
/// The same project without the vendored package fails smoke on the import,
/// not as a finding.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_atheris_fuzzes_typed_parameters_with_a_vendored_package() {
    assert!(hf_runtime::docker_daemon_ready());
    let project = tempfile::tempdir().unwrap();
    let mut candidate = python_project(project.path(), FRAMES_PY);
    std::fs::write(project.path().join("pkg/typed.py"), TYPED_PY).unwrap();
    let vendored = project.path().join("vendor/python/tinycodec");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::write(
        vendored.join("__init__.py"),
        "def first(data):\n    return data[0]\n",
    )
    .unwrap();
    candidate.symbol = "decode".to_owned();
    candidate.location.file = project.path().join("pkg/typed.py");
    candidate.signature = Some("def decode(kind: int, strict: bool, body: bytes)".to_owned());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let hf_harness::CompileResult::Ok(checked) =
        check(&runtime, project.path(), &candidate, &workspace).await
    else {
        panic!("the syntax-only build failed");
    };
    assert!(checked.source.contains("provider.ConsumeBool()"));
    assert!(workspace
        .join("vendor/python/tinycodec/__init__.py")
        .is_file());
    let smoked = smoke(&runtime, *checked, &workspace).await.unwrap();
    let summary = smoked.smoke_run.clone().unwrap();
    println!("typed smoke: {summary:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(summary.crashes > 0, "the planted defect was found");
    let ingested = hf_crash::ingest_for_engine(
        &workspace.join("out"),
        EngineKind::Atheris,
        Uuid::new_v4(),
        candidate.id,
    )
    .unwrap();
    assert!(!ingested.crashes.is_empty());
    let (code, log) = replay(
        &runtime,
        &workspace,
        "/work/fuzz_decode",
        &format!(
            "/work/out/{}",
            ingested.crashes[0]
                .input_path
                .file_name()
                .unwrap()
                .to_string_lossy()
        ),
    )
    .await;
    println!("typed replay exit {code}");
    let (kind, _, crash_summary) = hf_crash::classify(&log);
    assert_eq!(kind, hf_core::crash::CrashKind::Panic, "{log}");
    assert!(crash_summary.contains("IndexError"), "{crash_summary}");

    // Without the vendored package the import fails, and that is a failed
    // smoke with the interpreter's own message.
    let bare = tempfile::tempdir().unwrap();
    let mut unvendored = python_project(bare.path(), FRAMES_PY);
    std::fs::write(bare.path().join("pkg/typed.py"), TYPED_PY).unwrap();
    unvendored.symbol = "decode".to_owned();
    unvendored.location.file = bare.path().join("pkg/typed.py");
    unvendored.signature = candidate.signature.clone();
    let bare_workspace = root.path().join("bare");
    std::fs::create_dir_all(&bare_workspace).unwrap();
    let hf_harness::CompileResult::Ok(checked) =
        check(&runtime, bare.path(), &unvendored, &bare_workspace).await
    else {
        panic!("the syntax-only build failed");
    };
    let failed = smoke(&runtime, *checked, &bare_workspace).await;
    let report = match failed {
        Ok(harness) => format!("{:?}", harness.smoke_run),
        Err(error) => error.to_string(),
    };
    println!("unvendored: {report}");
    assert!(
        report.contains("tinycodec") || report.contains("ModuleNotFoundError"),
        "{report}"
    );
}
