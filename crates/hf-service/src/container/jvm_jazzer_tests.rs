//! JVM fuzzing through the service's own building blocks: the template
//! draft, source staging, the sandboxed `javac` build of the self-starting
//! jar, the bounded Jazzer run, artifact collection, replay, and
//! classification.
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

const FRAMES_FILE: &str = "src/main/java/com/example/Frames.java";

/// A table lookup that trusts an input byte as its index.
const FRAMES_JAVA: &str = "package com.example;\n\npublic final class Frames {\n    private static final int[] TABLE = {1, 2, 3};\n\n    public static int parse(byte[] data) {\n        if (data.length > 3 && data[0] == 'M' && data[1] == 'Z') {\n            return TABLE[data[2] & 0xff];\n        }\n        return 0;\n    }\n}\n";

/// The same lookup with the index checked.
const FRAMES_JAVA_FIXED: &str = "package com.example;\n\npublic final class Frames {\n    private static final int[] TABLE = {1, 2, 3};\n\n    public static int parse(byte[] data) {\n        if (data.length > 3 && data[0] == 'M' && data[1] == 'Z') {\n            int at = data[2] & 0xff;\n            if (at < TABLE.length) {\n                return TABLE[at];\n            }\n        }\n        return 0;\n    }\n}\n";

fn java_project(root: &Path, frames: &str) -> TargetCandidate {
    let file = root.join(FRAMES_FILE);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, frames).unwrap();
    // A test source that needs a library the sandbox does not have: the
    // build must leave it out.
    let test = root.join("src/test/java/com/example/FramesTest.java");
    std::fs::create_dir_all(test.parent().unwrap()).unwrap();
    std::fs::write(
        &test,
        "package com.example;\n\nimport org.junit.jupiter.api.Test;\n\nclass FramesTest {\n    @Test\n    void parses() {}\n}\n",
    )
    .unwrap();
    // A project file with the harness's own name must not replace it.
    std::fs::write(
        root.join("OxfuzzFuzzTarget.java"),
        "public class OxfuzzFuzzTarget { static { System.exit(3); } }\n",
    )
    .unwrap();
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: root.to_path_buf(),
        language: TargetLanguage::Java,
        symbol: "Frames.parse".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file,
            line: 6,
            col: 5,
            end_line: None,
            end_col: None,
        },
        signature: Some("public static int parse(byte[] data)".to_owned()),
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
fn a_java_draft_is_the_fixed_class_for_the_jazzer_engine_only() {
    let project = tempfile::tempdir().unwrap();
    let candidate = java_project(project.path(), FRAMES_JAVA);
    let draft =
        super::heuristic_draft(&candidate, EngineKind::Jazzer, Sanitizer::Address, false).unwrap();
    assert!(draft
        .source
        .starts_with("// oxfuzz:java-target com.example.Frames#parse bytes\n"));
    assert!(draft
        .source
        .contains("        com.example.Frames.parse(data);\n"));
    assert_eq!(draft.build_cmd.compiler, "javac");
    assert_eq!(
        draft.build_cmd.output,
        std::path::PathBuf::from(super::harness_binary_name("Frames.parse"))
    );
    assert_eq!(draft.generator, hf_core::harness::DraftGenerator::Heuristic);
    assert!(hf_harness::lint_harness_source(&draft.source, TargetLanguage::Java).is_empty());

    for engine in [EngineKind::LibFuzzer, EngineKind::Atheris] {
        let wrong_engine =
            super::heuristic_draft(&candidate, engine, Sanitizer::Address, false).unwrap_err();
        assert!(
            wrong_engine
                .to_string()
                .contains("Java targets build only for the jazzer engine"),
            "{wrong_engine}"
        );
    }
    let sanitizer =
        super::heuristic_draft(&candidate, EngineKind::Jazzer, Sanitizer::Undefined, false)
            .unwrap_err();
    assert!(
        sanitizer.to_string().contains("does not apply to Java"),
        "{sanitizer}"
    );

    let mut instance = candidate;
    instance.signature = Some("public int parse(byte[] data)".to_owned());
    let refused = super::heuristic_draft(&instance, EngineKind::Jazzer, Sanitizer::Address, false)
        .unwrap_err();
    assert!(refused.to_string().contains("is not static"), "{refused}");
}

#[test]
fn java_sources_are_staged_without_the_projects_own_harness_named_class() {
    let project = tempfile::tempdir().unwrap();
    java_project(project.path(), FRAMES_JAVA);
    let workspace = tempfile::tempdir().unwrap();
    copy_project_sources(project.path(), workspace.path());
    assert!(workspace.path().join(FRAMES_FILE).is_file());
    assert!(workspace
        .path()
        .join("src/test/java/com/example/FramesTest.java")
        .is_file());
    assert!(!workspace.path().join("OxfuzzFuzzTarget.java").exists());
}

#[test]
fn only_jars_directly_inside_lib_or_libs_are_staged() {
    let project = tempfile::tempdir().unwrap();
    java_project(project.path(), FRAMES_JAVA);
    for jar in [
        "lib/codec.jar",
        "libs/util.jar",
        "lib/deep/skipped.jar",
        "stray.jar",
        "build/out.jar",
    ] {
        let path = project.path().join(jar);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"PK").unwrap();
    }
    let workspace = tempfile::tempdir().unwrap();
    copy_project_sources(project.path(), workspace.path());
    assert!(workspace.path().join("lib/codec.jar").is_file());
    assert!(workspace.path().join("libs/util.jar").is_file());
    for skipped in ["lib/deep/skipped.jar", "stray.jar", "build/out.jar"] {
        assert!(!workspace.path().join(skipped).exists(), "{skipped}");
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

async fn build(
    runtime: &hf_runtime::docker::DockerRuntime,
    project: &Path,
    candidate: &TargetCandidate,
    workspace: &Path,
) -> hf_harness::CompileResult {
    copy_project_sources(project, workspace);
    let draft =
        super::heuristic_draft(candidate, EngineKind::Jazzer, Sanitizer::Address, false).unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: candidate.id,
        engine: EngineKind::Jazzer,
        source: draft.source,
        language: TargetLanguage::Java,
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
    let config = run_config(&harness, 30);
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
    artifact: &str,
    input: &str,
) -> (i32, String) {
    use hf_core::runtime::RuntimeAdapter as _;
    let result = runtime
        .run_command_opts(
            &[artifact.to_owned(), input.to_owned()],
            workspace,
            &hf_core::runtime::ResourceLimits {
                max_mem_mb: 2048,
                max_cpus: 1,
                max_duration_secs: 60,
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

/// Build, fuzz, collect, replay, and classify a planted Java defect in the
/// real sandbox; show a staged run executes the classes in its own artifact;
/// show the corrected method fuzzes clean; and show a source that does not
/// compile fails the build.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_jazzer_finds_replays_and_classifies_a_planted_exception() {
    assert!(hf_runtime::docker_daemon_ready());
    let project = tempfile::tempdir().unwrap();
    let candidate = java_project(project.path(), FRAMES_JAVA);
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    let artifact_name = super::harness_binary_name("Frames.parse");
    let built = match build(&runtime, project.path(), &candidate, &workspace).await {
        hf_harness::CompileResult::Ok(harness) => *harness,
        hf_harness::CompileResult::Failed(failure) => {
            panic!("javac failed: {}\n{}", failure.stdout, failure.stderr)
        }
    };
    assert_eq!(built.build_cmd.output, workspace.join(&artifact_name));
    let artifact = std::fs::read(workspace.join(&artifact_name)).unwrap();
    assert!(artifact.starts_with(b"#!/bin/sh\nexec jazzer --cp=\"$0\""));
    let source = built.source.clone();

    let smoked = smoke(&runtime, built, &workspace).await.unwrap();
    let summary = smoked.smoke_run.clone().unwrap();
    println!("smoke: {summary:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(summary.crashes > 0, "the planted defect was found");

    let out = workspace.join("out");
    let ingested =
        hf_crash::ingest_for_engine(&out, EngineKind::Jazzer, Uuid::new_v4(), candidate.id)
            .unwrap();
    assert_eq!(ingested.crashes.len(), 1, "{:?}", ingested.crashes);
    let input = ingested.crashes[0].input_path.clone();
    let name = input.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("crash-"), "{name}");
    let bytes = std::fs::read(&input).unwrap();
    assert!(bytes.starts_with(b"MZ") && bytes[2] > 2, "{bytes:?}");
    // Jazzer's generated reproducer source went to scratch, not the output.
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);

    // Replay as triage does: the artifact, then the input.
    let container_input = format!("/work/out/{name}");
    let container_artifact = format!("/work/{artifact_name}");
    let (exit_code, log) =
        replay(&runtime, &workspace, &container_artifact, &container_input).await;
    assert_eq!(exit_code, 77, "{log}");
    assert!(hf_crash::looks_like_crash(&log), "{log}");
    let (kind, signature, classified) = hf_crash::classify(&log);
    println!("classified: {kind:?} {classified}");
    assert_eq!(kind, hf_core::crash::CrashKind::Panic);
    assert!(
        classified.starts_with("java.lang.ArrayIndexOutOfBoundsException: Index "),
        "{classified}"
    );
    assert!(!signature.is_empty());

    // A staged run executes the classes inside its own artifact: the
    // workspace sources can change without changing what the run executes.
    let run_id = Uuid::new_v4();
    let artifacts = super::staging::stage_run_artifacts(
        &workspace,
        run_id,
        &source,
        &workspace.join(&artifact_name),
        None,
    )
    .unwrap();
    assert!(artifacts.source_context_host.join(FRAMES_FILE).is_file());
    assert!(!artifacts
        .source_context_host
        .join("OxfuzzFuzzTarget.java")
        .exists());
    let (staged_exit, staged_log) = replay(
        &runtime,
        &workspace,
        &artifacts.binary_container,
        &container_input,
    )
    .await;
    assert_eq!(staged_exit, 77, "{staged_log}");
    assert_eq!(hf_crash::classify(&staged_log).1, signature);

    // The corrected method: same harness, clean smoke with throughput, and
    // the saved input no longer fails.
    std::fs::write(project.path().join(FRAMES_FILE), FRAMES_JAVA_FIXED).unwrap();
    let fixed_workspace = root.path().join("fixed");
    std::fs::create_dir_all(&fixed_workspace).unwrap();
    let hf_harness::CompileResult::Ok(fixed) =
        build(&runtime, project.path(), &candidate, &fixed_workspace).await
    else {
        panic!("the corrected project failed to build");
    };
    let fixed = smoke(&runtime, *fixed, &fixed_workspace).await.unwrap();
    let fixed_summary = fixed.smoke_run.clone().unwrap();
    println!("fixed smoke: {fixed_summary:?}");
    assert_eq!(fixed_summary.crashes, 0);
    assert!(fixed_summary.passed && fixed_summary.execs_per_sec > 0.0);
    std::fs::copy(
        fixed_workspace.join(&artifact_name),
        workspace.join("fuzz_fixed"),
    )
    .unwrap();
    let (fixed_exit, fixed_log) =
        replay(&runtime, &workspace, "/work/fuzz_fixed", &container_input).await;
    assert_eq!(fixed_exit, 0, "{fixed_log}");
    assert!(!hf_crash::looks_like_crash(&fixed_log), "{fixed_log}");

    // A source that does not compile fails the build with javac's report.
    std::fs::write(
        project.path().join(FRAMES_FILE),
        FRAMES_JAVA.replace("return 0;", "return missing;"),
    )
    .unwrap();
    let broken_workspace = root.path().join("broken");
    std::fs::create_dir_all(&broken_workspace).unwrap();
    match build(&runtime, project.path(), &candidate, &broken_workspace).await {
        hf_harness::CompileResult::Failed(failure) => {
            let output = format!("{}{}", failure.stdout, failure.stderr);
            assert!(output.contains("cannot find symbol"), "{output}");
        }
        hf_harness::CompileResult::Ok(_) => panic!("a compile error must fail the build"),
    }
}

/// A dependency the project carries as a jar, and a target that calls it
/// with an index it does not check.
const TABLES_JAVA: &str = "package org.vendor;\n\npublic final class Tables {\n    private static final int[] TABLE = {1, 2, 3};\n\n    public static int at(int index) {\n        return TABLE[index];\n    }\n}\n";
const LOOKUP_JAVA: &str = "package com.example;\n\nimport org.vendor.Tables;\n\npublic final class Lookup {\n    public static int find(byte[] data) {\n        if (data.length > 2 && data[0] == 'L') {\n            return Tables.at(data[1] & 0xff);\n        }\n        return 0;\n    }\n}\n";

/// A project that imports a class from a jar under `lib/` builds against
/// that jar, carries it inside the one-file artifact, and its planted
/// exception is found inside the vendored class. The same project without
/// the jar fails the build with the compiler's message.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_jazzer_builds_against_a_vendored_jar() {
    use hf_core::runtime::RuntimeAdapter as _;
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    // Build the dependency jar in the sandbox, as its vendor would have.
    let vendor = root.path().join("vendor");
    std::fs::create_dir_all(vendor.join("org/vendor")).unwrap();
    std::fs::write(vendor.join("org/vendor/Tables.java"), TABLES_JAVA).unwrap();
    let packed = runtime
        .run_command_opts(
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                "cd /work && javac -d classes org/vendor/Tables.java && \
                 jar --create --file tables.jar -C classes ."
                    .to_owned(),
            ],
            &vendor,
            &hf_core::runtime::ResourceLimits {
                max_mem_mb: 2048,
                max_cpus: 1,
                max_duration_secs: 120,
                env: std::collections::HashMap::new(),
                ptrace: false,
            },
            &hf_core::runtime::SandboxOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(packed.exit_code, 0, "{}", packed.stderr);

    let project = tempfile::tempdir().unwrap();
    let mut candidate = java_project(project.path(), FRAMES_JAVA);
    let lookup = project.path().join("src/main/java/com/example/Lookup.java");
    std::fs::write(&lookup, LOOKUP_JAVA).unwrap();
    candidate.symbol = "Lookup.find".to_owned();
    candidate.location.file = lookup;
    candidate.signature = Some("public static int find(byte[] data)".to_owned());

    // Without the jar the import does not resolve.
    let bare = root.path().join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    let hf_harness::CompileResult::Failed(failure) =
        build(&runtime, project.path(), &candidate, &bare).await
    else {
        panic!("the build must fail without the vendored jar");
    };
    let message = format!("{}{}", failure.stdout, failure.stderr);
    assert!(message.contains("org.vendor"), "{message}");

    std::fs::create_dir_all(project.path().join("lib")).unwrap();
    std::fs::copy(
        vendor.join("tables.jar"),
        project.path().join("lib/tables.jar"),
    )
    .unwrap();
    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let built = match build(&runtime, project.path(), &candidate, &workspace).await {
        hf_harness::CompileResult::Ok(harness) => *harness,
        hf_harness::CompileResult::Failed(failure) => {
            panic!("javac failed: {}\n{}", failure.stdout, failure.stderr)
        }
    };
    let smoked = smoke(&runtime, built, &workspace).await.unwrap();
    let summary = smoked.smoke_run.clone().unwrap();
    println!("vendored smoke: {summary:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(summary.crashes > 0, "the planted defect was found");
}

/// A method whose arguments are decoded from the input: the index reaches
/// the table only when the flag is set and the payload starts with `S`.
const STEPS_JAVA: &str = "package com.example;\n\npublic final class Steps {\n    private static final int[] TABLE = {1, 2, 3};\n\n    public static int run(int index, boolean strict, byte[] data) {\n        if (strict && data.length > 0 && data[0] == 'S') {\n            return TABLE[index & 0x7];\n        }\n        return 0;\n    }\n}\n";

/// A method with typed parameters compiles against Jazzer's data provider,
/// runs, and its planted exception is found and replays.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_jazzer_fuzzes_a_method_with_typed_parameters() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
    let project = tempfile::tempdir().unwrap();
    let mut candidate = java_project(project.path(), FRAMES_JAVA);
    let steps = project.path().join("src/main/java/com/example/Steps.java");
    std::fs::write(&steps, STEPS_JAVA).unwrap();
    candidate.symbol = "Steps.run".to_owned();
    candidate.location.file = steps;
    candidate.signature =
        Some("public static int run(int index, boolean strict, byte[] data) {".to_owned());

    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let built = match build(&runtime, project.path(), &candidate, &workspace).await {
        hf_harness::CompileResult::Ok(harness) => *harness,
        hf_harness::CompileResult::Failed(failure) => {
            panic!("javac failed: {}\n{}", failure.stdout, failure.stderr)
        }
    };
    assert!(built.source.contains("FuzzedDataProvider data"));
    let artifact = built.build_cmd.output.clone();
    let smoked = smoke(&runtime, built, &workspace).await.unwrap();
    let summary = smoked.smoke_run.clone().unwrap();
    println!("typed smoke: {summary:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(summary.crashes > 0, "the planted defect was found");

    let saved = std::fs::read_dir(workspace.join("out"))
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("crash-"))
        .expect("a saved finding");
    let container_artifact = format!("/work/{}", artifact.file_name().unwrap().to_string_lossy());
    let (code, report) = replay(
        &runtime,
        &workspace,
        &container_artifact,
        &format!("/work/out/{saved}"),
    )
    .await;
    println!("typed replay exit {code}");
    assert_eq!(code, 77, "{report}");
    assert!(
        report.contains("ArrayIndexOutOfBoundsException"),
        "{report}"
    );
    assert!(report.contains("com.example.Steps.run"), "{report}");
}
