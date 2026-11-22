//! Go native fuzzing through the service's own building blocks: the template
//! draft, module staging, the sandboxed `go test -c` build, the bounded fuzz
//! run, failing-input collection, replay, and classification.
//!
//! The live test needs the pinned sandbox image; the rest runs anywhere.

use std::path::{Path, PathBuf};

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use uuid::Uuid;

use super::harness_workspace::copy_project_sources;

const GO_MOD: &str = "module example.com/frame\n\ngo 1.22\n";

/// A length-prefixed reader that trusts the length byte.
const FRAME_GO: &str = "package wire\n\n// Parse reads one length-prefixed frame.\nfunc Parse(data []byte) int {\n\tif len(data) < 4 || data[0] != 'F' || data[1] != 'R' {\n\t\treturn 0\n\t}\n\treturn int(data[4+int(data[2])])\n}\n";

/// The same reader with the length checked.
const FRAME_GO_FIXED: &str = "package wire\n\n// Parse reads one length-prefixed frame.\nfunc Parse(data []byte) int {\n\tif len(data) < 4 || data[0] != 'F' || data[1] != 'R' {\n\t\treturn 0\n\t}\n\tat := 4 + int(data[2])\n\tif at >= len(data) {\n\t\treturn 0\n\t}\n\treturn int(data[at])\n}\n";

fn go_project(root: &Path, frame: &str) -> TargetCandidate {
    std::fs::create_dir_all(root.join("wire")).unwrap();
    std::fs::write(root.join("go.mod"), GO_MOD).unwrap();
    std::fs::write(root.join("wire/frame.go"), frame).unwrap();
    // A project test that must not reach the harness binary.
    std::fs::write(
        root.join("wire/frame_test.go"),
        "package wire\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(3) }\n",
    )
    .unwrap();
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: root.to_path_buf(),
        language: TargetLanguage::Go,
        symbol: "Parse".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: root.join("wire/frame.go"),
            line: 4,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("func Parse(data []byte) int".to_owned()),
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
fn a_go_draft_is_the_template_for_the_go_native_engine_only() {
    let project = tempfile::tempdir().unwrap();
    let candidate = go_project(project.path(), FRAME_GO);
    let draft = super::heuristic_draft(&candidate, EngineKind::GoNative, Sanitizer::Address, false)
        .unwrap();
    assert!(draft
        .source
        .starts_with("// oxfuzz:package-dir wire\npackage wire\n"));
    assert!(draft.source.contains("func FuzzParse(f *testing.F)"));
    assert_eq!(draft.build_cmd.compiler, "go");
    assert_eq!(
        draft.build_cmd.args,
        [
            "test",
            "-c",
            "-fuzz=^FuzzParse$",
            "-o",
            "/work/fuzz_Parse",
            "./wire"
        ]
    );
    assert_eq!(draft.generator, hf_core::harness::DraftGenerator::Heuristic);
    let wrong_engine =
        super::heuristic_draft(&candidate, EngineKind::LibFuzzer, Sanitizer::Address, false)
            .unwrap_err();
    assert!(
        wrong_engine
            .to_string()
            .contains("Go targets build only for the go-native engine"),
        "{wrong_engine}"
    );
    let persistent =
        super::heuristic_draft(&candidate, EngineKind::GoNative, Sanitizer::Address, true);
    assert!(persistent.is_err(), "persistent mode is AFL++ C/C++ only");

    // A typed parameter list is a template too: the arguments are decoded
    // from the one []byte the fuzz callback takes.
    let mut typed = candidate.clone();
    typed.signature = Some("func Parse(data []byte, strict bool) int".to_owned());
    let draft =
        super::heuristic_draft(&typed, EngineKind::GoNative, Sanitizer::Address, false).unwrap();
    assert!(
        draft.source.contains("\t\tParse(a0, a1)\n"),
        "{}",
        draft.source
    );

    let mut outside = candidate;
    outside.signature = Some("func Parse(data []byte, options Options) int".to_owned());
    let refused = super::heuristic_draft(&outside, EngineKind::GoNative, Sanitizer::Address, false)
        .unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("not in the supported Go target class"),
        "{refused}"
    );
}

/// A record reader whose layout depends on typed arguments: it trusts the
/// first body byte as an offset, but only for kind 7 in strict mode.
const TYPED_GO: &str = "package wire\n\n// Decode reads one record.\nfunc Decode(kind uint8, strict bool, body []byte) int {\n\tif kind != 7 || !strict || len(body) < 2 {\n\t\treturn 0\n\t}\n\treturn int(body[2+int(body[0])])\n}\n";

/// A function with three typed parameters is built, fuzzed, and its planted
/// panic found, with the failing input stored as one `[]byte` like any other
/// Go finding: the first byte is the kind, the second the flag, the rest the
/// body.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_go_native_fuzzes_a_function_with_typed_parameters() {
    assert!(hf_runtime::docker_daemon_ready());
    let project = tempfile::tempdir().unwrap();
    let mut candidate = go_project(project.path(), FRAME_GO);
    std::fs::write(project.path().join("wire/decode.go"), TYPED_GO).unwrap();
    candidate.symbol = "Decode".to_owned();
    candidate.location.file = project.path().join("wire/decode.go");
    candidate.signature = Some("func Decode(kind uint8, strict bool, body []byte) int".to_owned());
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    let smoked = build_and_smoke(&runtime, project.path(), &candidate, &workspace).await;
    let smoke = smoked.smoke_run.clone().unwrap();
    println!("typed smoke: {smoke:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(smoke.crashes > 0, "the planted defect was found");

    let out = workspace.join("out");
    let ingested =
        hf_crash::ingest_for_engine(&out, EngineKind::GoNative, Uuid::new_v4(), candidate.id)
            .unwrap();
    assert_eq!(ingested.crashes.len(), 1, "{:?}", ingested.crashes);
    let input = &ingested.crashes[0].input_path;
    assert!(input.starts_with(out.join("testdata/fuzz/FuzzDecode")));
    let (kind, bytes) = hf_crash::go_corpus::decode(&std::fs::read(input).unwrap()).unwrap();
    println!("typed failing input: {bytes:?}");
    assert_eq!(kind, hf_crash::go_corpus::GoInputKind::Bytes);
    assert_eq!(bytes[0], 7, "the kind argument");
    assert_eq!(bytes[1] & 1, 1, "the strict argument");
    assert!(bytes.len() >= 4, "a body of at least two bytes");
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

async fn build_and_smoke(
    runtime: &hf_runtime::docker::DockerRuntime,
    project: &Path,
    candidate: &TargetCandidate,
    workspace: &Path,
) -> Harness {
    copy_project_sources(project, workspace);
    assert!(!workspace.join("wire/frame_test.go").exists());
    let draft =
        super::heuristic_draft(candidate, EngineKind::GoNative, Sanitizer::Address, false).unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: candidate.id,
        engine: EngineKind::GoNative,
        source: draft.source,
        language: TargetLanguage::Go,
        build_cmd: draft.build_cmd,
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
        cmplog: None,
        custom_mutator: None,
    };
    let compiled = match hf_harness::try_compile_with_options(
        harness,
        runtime,
        workspace,
        &hf_core::runtime::SandboxOptions::default(),
    )
    .await
    .unwrap()
    {
        hf_harness::CompileResult::Ok(harness) => *harness,
        hf_harness::CompileResult::Failed(failure) => {
            panic!("go test -c failed: {}\n{}", failure.stdout, failure.stderr)
        }
    };
    assert_eq!(
        compiled.build_cmd.output,
        workspace.join(format!("fuzz_{}", candidate.symbol))
    );
    assert!(workspace.join("wire/oxfuzz_fuzz_test.go").is_file());
    let config = run_config(&compiled, 20);
    hf_harness::generator::smoke_fuzz_in_paths_with_config_and_sandbox_image(
        compiled,
        runtime,
        workspace,
        Path::new("corpus"),
        Path::new("out"),
        &config,
        None,
    )
    .await
    .unwrap()
}

/// Build, fuzz, collect, replay, and classify a planted Go defect in the
/// real sandbox, then show the corrected function fuzzes clean and no longer
/// fails on the saved input.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_go_native_finds_replays_and_classifies_a_planted_panic() {
    assert!(hf_runtime::docker_daemon_ready());
    let project = tempfile::tempdir().unwrap();
    let candidate = go_project(project.path(), FRAME_GO);
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    let smoked = build_and_smoke(&runtime, project.path(), &candidate, &workspace).await;
    let smoke = smoked.smoke_run.clone().unwrap();
    println!("smoke: {smoke:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(smoke.crashes > 0, "the planted defect was found");

    // The failing input is where the crash scan looks, in Go's encoding.
    let out = workspace.join("out");
    let ingested =
        hf_crash::ingest_for_engine(&out, EngineKind::GoNative, Uuid::new_v4(), candidate.id)
            .unwrap();
    assert_eq!(ingested.crashes.len(), 1, "{:?}", ingested.crashes);
    let input: PathBuf = ingested.crashes[0].input_path.clone();
    assert!(input.starts_with(out.join("testdata/fuzz/FuzzParse")));
    let (_, bytes) = hf_crash::go_corpus::decode(&std::fs::read(&input).unwrap()).unwrap();
    assert!(bytes.starts_with(b"FR"), "{bytes:?}");
    // Go kept its corpus in its own cache under the output directory; the
    // run corpus stays flat and gains the decoded inputs on collection.
    assert!(out.join("go-fuzz-cache/FuzzParse").is_dir());
    assert!(!workspace.join("testdata").exists());
    let corpus = workspace.join("corpus");
    assert_eq!(std::fs::read_dir(&corpus).unwrap().count(), 0);
    super::go_corpus::collect_discoveries(&corpus, &out).unwrap();
    let discovered = hf_corpus::list(&corpus).unwrap();
    println!("discovered inputs: {}", discovered.entries.len());
    assert!(!discovered.entries.is_empty());

    // Replay by name, as triage does, and classify the Go runtime's report.
    let replay = super::triage::go_failing_input(&workspace, &input).unwrap();
    assert_eq!(replay.working_directory, "/work/out");
    let replay_log = |binary: &'static str| {
        let command =
            hf_engine::go_native::build_replay_args(binary, &replay.fuzz_test, &replay.name);
        let runtime = &runtime;
        let workspace = &workspace;
        let workdir = replay.working_directory.clone();
        async move {
            use hf_core::runtime::RuntimeAdapter as _;
            let result = runtime
                .run_command_opts(
                    &command,
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
                        workdir: Some(workdir),
                        ..hf_core::runtime::SandboxOptions::default()
                    },
                )
                .await
                .unwrap();
            format!("{}\n{}", result.stdout, result.stderr)
        }
    };
    let log = replay_log("/work/fuzz_Parse").await;
    assert!(hf_crash::looks_like_crash(&log), "{log}");
    let (kind, signature, summary) = hf_crash::classify(&log);
    println!("classified: {kind:?} {summary}");
    assert_eq!(kind, hf_core::crash::CrashKind::Panic);
    assert!(summary.starts_with("panic: runtime error: index out of range"));
    assert!(!signature.is_empty());

    // The corrected function: same harness, same saved input, no failure.
    std::fs::write(project.path().join("wire/frame.go"), FRAME_GO_FIXED).unwrap();
    let fixed_workspace = root.path().join("fixed");
    std::fs::create_dir_all(&fixed_workspace).unwrap();
    let fixed = build_and_smoke(&runtime, project.path(), &candidate, &fixed_workspace).await;
    let fixed_smoke = fixed.smoke_run.clone().unwrap();
    println!("fixed smoke: {fixed_smoke:?}");
    assert_eq!(fixed_smoke.crashes, 0);
    assert!(fixed_smoke.passed && fixed_smoke.execs_per_sec > 0.0);
    std::fs::copy(
        fixed_workspace.join("fuzz_Parse"),
        workspace.join("fuzz_Parse_fixed"),
    )
    .unwrap();
    let fixed_log = replay_log("/work/fuzz_Parse_fixed").await;
    assert!(!hf_crash::looks_like_crash(&fixed_log), "{fixed_log}");
    assert!(fixed_log.contains("PASS"), "{fixed_log}");

    // Seeds: two raw corpus files reach Go through its cache, are run as the
    // baseline, and the run's discoveries come back as raw inputs.
    let seeded_corpus = fixed_workspace.join("seeded-corpus");
    let seeded_out = fixed_workspace.join("seeded-out");
    std::fs::create_dir_all(&seeded_corpus).unwrap();
    std::fs::create_dir_all(&seeded_out).unwrap();
    std::fs::write(seeded_corpus.join("a"), b"FR\x00\x00\x07").unwrap();
    std::fs::write(seeded_corpus.join("b"), b"\xff\x00not a frame").unwrap();
    assert_eq!(
        super::go_corpus::stage_seeds(&seeded_corpus, &seeded_out, &fixed.source).unwrap(),
        2
    );
    let command = hf_engine::go_native::build_run_args(
        &run_config(&fixed, 5),
        "/work/fuzz_Parse",
        "/work/seeded-corpus",
        "/work/seeded-out",
    )
    .unwrap();
    let seeded = {
        use hf_core::runtime::RuntimeAdapter as _;
        runtime
            .run_command_opts(
                &command,
                &fixed_workspace,
                &hf_core::runtime::ResourceLimits {
                    max_mem_mb: 2048,
                    max_cpus: 1,
                    max_duration_secs: 60,
                    env: std::collections::HashMap::new(),
                    ptrace: false,
                },
                &hf_core::runtime::SandboxOptions {
                    workspace_read_only: true,
                    workdir: Some("/work/seeded-out".to_owned()),
                    extra_mounts: vec![hf_core::runtime::SandboxMount::writable(
                        seeded_out.clone(),
                        "/work/seeded-out".to_owned(),
                    )],
                    max_file_size_bytes: Some(hf_engine::runner::run_file_size_limit_bytes(
                        EngineKind::GoNative,
                    )),
                    ..hf_core::runtime::SandboxOptions::default()
                },
            )
            .await
            .unwrap()
    };
    let seeded_log = format!("{}\n{}", seeded.stdout, seeded.stderr);
    assert!(
        seeded_log.contains("gathering baseline coverage: 0/2 completed"),
        "{seeded_log}"
    );
    assert!(seeded_log.contains("PASS"), "{seeded_log}");
    super::go_corpus::collect_discoveries(&seeded_corpus, &seeded_out).unwrap();
    let grown = hf_corpus::list(&seeded_corpus).unwrap();
    println!("seeded corpus after the run: {}", grown.entries.len());
    assert!(grown.entries.len() > 2, "the run added its own inputs");
}

#[test]
fn only_a_go_corpus_file_at_gos_own_path_is_replayed_by_name() {
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path();
    let directory = workspace.join("runs/r1/out/testdata/fuzz/FuzzParse");
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("4f85edf10c3c3e2c");
    std::fs::write(&input, "go test fuzz v1\n[]byte(\"FR\")\n").unwrap();
    assert_eq!(
        super::triage::go_failing_input(workspace, &input),
        Some(super::triage::GoFailingInput {
            fuzz_test: "FuzzParse".to_owned(),
            name: "4f85edf10c3c3e2c".to_owned(),
            working_directory: "/work/runs/r1/out".to_owned(),
        })
    );
    // The right shape with other content, and a libFuzzer artifact.
    let raw = directory.join("0123456789abcdef");
    std::fs::write(&raw, b"\x00\x01raw bytes that are long enough").unwrap();
    assert_eq!(super::triage::go_failing_input(workspace, &raw), None);
    let libfuzzer = workspace.join("runs/r1/out/crash-0123");
    std::fs::write(&libfuzzer, "go test fuzz v1\n").unwrap();
    assert_eq!(super::triage::go_failing_input(workspace, &libfuzzer), None);
    // Outside the workspace there is no container path to replay from.
    let elsewhere = tempfile::tempdir().unwrap();
    let outside = elsewhere.path().join("testdata/fuzz/FuzzParse");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("abcdef0123456789"), "go test fuzz v1\n").unwrap();
    assert_eq!(
        super::triage::go_failing_input(workspace, &outside.join("abcdef0123456789")),
        None
    );
}

#[test]
fn seeds_reach_gos_fuzz_cache_and_its_discoveries_return_as_raw_inputs() {
    let root = tempfile::tempdir().unwrap();
    let corpus = root.path().join("corpus");
    let out = root.path().join("out");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(corpus.join("seed"), b"FR\x00\xff").unwrap();
    let source = "// oxfuzz:package-dir wire\npackage wire\n\nimport \"testing\"\n\nfunc \
                  FuzzParse(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, data []byte) \
                  {\n\t\tParse(data)\n\t})\n}\n";

    assert_eq!(
        super::go_corpus::stage_seeds(&corpus, &out, source).unwrap(),
        1
    );
    let cache = out.join("go-fuzz-cache/FuzzParse");
    let staged: Vec<PathBuf> = std::fs::read_dir(&cache)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(staged.len(), 1);
    assert_eq!(
        std::fs::read_to_string(&staged[0]).unwrap(),
        "go test fuzz v1\n[]byte(\"FR\\x00\\xff\")\n"
    );

    // Go keeps one new input; the run corpus gains exactly its raw bytes.
    std::fs::write(
        cache.join("c4fabdc68b3cc54d"),
        "go test fuzz v1\n[]byte(\"FR\\x01new\")\n",
    )
    .unwrap();
    // A directory that is not a fuzz test's cache is ignored.
    std::fs::create_dir_all(out.join("go-fuzz-cache/other")).unwrap();
    std::fs::write(
        out.join("go-fuzz-cache/other/x"),
        "go test fuzz v1\n[]byte(\"skipped\")\n",
    )
    .unwrap();
    super::go_corpus::collect_discoveries(&corpus, &out).unwrap();
    let mut contents: Vec<Vec<u8>> = std::fs::read_dir(&corpus)
        .unwrap()
        .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
        .collect();
    contents.sort();
    assert_eq!(contents, [b"FR\x00\xff".to_vec(), b"FR\x01new".to_vec()]);

    // A harness whose callback is not the supported shape is refused before
    // anything is written: a seed of the wrong type fails the Go run.
    let other = tempfile::tempdir().unwrap();
    let wrong = source.replace("data []byte", "n int");
    assert!(super::go_corpus::stage_seeds(&corpus, other.path(), &wrong).is_err());
    assert_eq!(std::fs::read_dir(other.path()).unwrap().count(), 0);
    // A run that kept nothing has no cache directory.
    super::go_corpus::collect_discoveries(&corpus, other.path()).unwrap();
}
