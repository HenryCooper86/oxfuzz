//! JavaScript fuzzing through the service's own building blocks: discovery,
//! the template draft, project staging, the syntax-only build, the bounded
//! Jazzer.js run, artifact collection, replay, classification, and the
//! retained sources a run loads from.
//!
//! The live tests need the pinned sandbox image; the rest runs anywhere.

use std::path::Path;

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::target::{Sanitizer, TargetCandidate, TargetLanguage};
use uuid::Uuid;

use super::harness_workspace::copy_project_sources;

/// A table lookup that trusts an input byte as its index. The table comes
/// from a package the project carries in `node_modules`, which reads it from
/// a data file.
const FRAMES_JS: &str = "'use strict';\n\
const { TABLE } = require('tablekit');\n\
\n\
/**\n\
\x20* Look up the entry a frame names.\n\
\x20* @param {Buffer} data the frame\n\
\x20* @returns {string}\n\
\x20*/\n\
function parse(data) {\n\
\x20 if (data.length > 3 && data[0] === 0x4d && data[1] === 0x5a) {\n\
\x20   return TABLE[data[2]].toString();\n\
\x20 }\n\
\x20 return '';\n\
}\n\
\n\
module.exports = { parse };\n";

/// The same lookup with the index checked.
const FRAMES_JS_FIXED: &str = "'use strict';\n\
const { TABLE } = require('tablekit');\n\
\n\
/**\n\
\x20* Look up the entry a frame names.\n\
\x20* @param {Buffer} data the frame\n\
\x20* @returns {string}\n\
\x20*/\n\
function parse(data) {\n\
\x20 if (data.length > 3 && data[0] === 0x4d && data[1] === 0x5a) {\n\
\x20   if (data[2] < TABLE.length) {\n\
\x20     return TABLE[data[2]].toString();\n\
\x20   }\n\
\x20 }\n\
\x20 return '';\n\
}\n\
\n\
module.exports = { parse };\n";

/// An ES module whose asynchronous function takes two documented parameters
/// and rejects on one combination of them.
const CODEC_MJS: &str = "/**\n\
\x20* @param {number} depth\n\
\x20* @param {string} text\n\
\x20* @returns {Promise<string>}\n\
\x20*/\n\
export async function decode(depth, text) {\n\
\x20 await Promise.resolve();\n\
\x20 if (text.length > 2 && text[0] === 'a') {\n\
\x20   if (text[1] === 'b' && Number.isFinite(depth)) {\n\
\x20     throw new RangeError('unbalanced frame of ' + text.length);\n\
\x20   }\n\
\x20 }\n\
\x20 return text;\n\
}\n";

const MANIFEST: &str =
    "{\n  \"name\": \"frames\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": { \"tablekit\": \"1.0.0\" }\n}\n";

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn node_project(root: &Path, frames: &str) {
    write(root, "package.json", MANIFEST);
    write(root, "lib/frames.js", frames);
    write(root, "lib/codec.mjs", CODEC_MJS);
    write(
        root,
        "node_modules/tablekit/package.json",
        "{ \"name\": \"tablekit\", \"version\": \"1.0.0\", \"main\": \"index.js\" }\n",
    );
    write(
        root,
        "node_modules/tablekit/index.js",
        "module.exports = { TABLE: require('./build/table.json') };\n",
    );
    // A package is staged as it is: a data file, in a directory whose name
    // staging skips in the project's own tree.
    write(
        root,
        "node_modules/tablekit/build/table.json",
        "[1, 2, 3]\n",
    );
    write(root, "node_modules/tablekit/LICENSE", "x\n");
    // A project file with the harness's own name must not replace it.
    write(root, "harness.mjs", "process.exit(3);\n");
    write(root, "README.md", "not staged\n");
}

/// The candidate discovery reports for `symbol`, so the draft is exercised
/// on what the scanner really records.
async fn discovered(root: &Path, symbol: &str) -> TargetCandidate {
    let inventory = hf_discovery::discover(root, TargetLanguage::JavaScript)
        .await
        .unwrap();
    inventory
        .candidates
        .into_iter()
        .find(|candidate| candidate.symbol == symbol)
        .unwrap_or_else(|| panic!("discovery did not report {symbol}"))
}

#[tokio::test]
async fn a_javascript_draft_is_the_fixed_module_for_the_jazzer_js_engine_only() {
    let project = tempfile::tempdir().unwrap();
    node_project(project.path(), FRAMES_JS);
    let candidate = discovered(project.path(), "parse").await;
    // Compared as a path: discovery reports the host's separator.
    assert_eq!(
        Path::new(&candidate.relative_file()),
        Path::new("lib/frames.js")
    );
    assert_eq!(candidate.signature.as_deref(), Some("function parse(data)"));
    let draft = super::heuristic_draft(&candidate, EngineKind::JazzerJs, Sanitizer::Address, false)
        .unwrap();
    let mut lines = draft.source.lines();
    assert_eq!(lines.next(), Some("#!/bin/sh"));
    assert!(lines.next().unwrap().contains("exec jazzer-js "));
    assert_eq!(
        lines.next(),
        Some("// oxfuzz:js-target lib/frames.js parse buffer")
    );
    assert_eq!(draft.build_cmd.compiler, "sh");
    assert_eq!(
        &draft.build_cmd.args[2..],
        [
            "/opt/node/bin/node",
            "harness.mjs",
            "lib/frames.js",
            "fuzz_parse"
        ]
    );
    assert_eq!(draft.generator, hf_core::harness::DraftGenerator::Heuristic);
    assert!(hf_harness::lint_harness_source(&draft.source, TargetLanguage::JavaScript).is_empty());

    // The typed, asynchronous ES module function drafts from its
    // documentation.
    let decode = discovered(project.path(), "decode").await;
    assert_eq!(
        decode.signature.as_deref(),
        Some("async function decode(depth, text)")
    );
    let typed =
        super::heuristic_draft(&decode, EngineKind::JazzerJs, Sanitizer::Address, false).unwrap();
    assert!(typed
        .source
        .contains("// oxfuzz:js-target lib/codec.mjs decode number,string\n"));

    for engine in [EngineKind::LibFuzzer, EngineKind::AflPlusPlus] {
        let wrong_engine =
            super::heuristic_draft(&candidate, engine, Sanitizer::Address, false).unwrap_err();
        assert!(
            wrong_engine
                .to_string()
                .contains("JavaScript targets build only for the jazzer-js engine"),
            "{wrong_engine}"
        );
    }
    let sanitizer =
        super::heuristic_draft(&candidate, EngineKind::JazzerJs, Sanitizer::Memory, false)
            .unwrap_err();
    assert!(
        sanitizer
            .to_string()
            .contains("does not apply to JavaScript"),
        "{sanitizer}"
    );
    let persistent =
        super::heuristic_draft(&candidate, EngineKind::JazzerJs, Sanitizer::Address, true);
    assert!(persistent.is_err(), "persistent mode is AFL++ C/C++ only");

    // A function with no `@param` line at all (js-yaml's `load(input,
    // options)`) takes the input as text in its first parameter; the
    // directive records that choice for the reviewer.
    write(
        project.path(),
        "lib/plain.js",
        "function scan(input, options) {\n  return input.length;\n}\nmodule.exports = { scan };\n",
    );
    let undocumented = discovered(project.path(), "scan").await;
    let drafted = super::heuristic_draft(
        &undocumented,
        EngineKind::JazzerJs,
        Sanitizer::Address,
        false,
    )
    .unwrap();
    assert!(
        drafted
            .source
            .contains("// oxfuzz:js-target lib/plain.js scan string\n"),
        "{}",
        drafted.source
    );
    assert!(drafted
        .source
        .contains("  return target.scan(data.toString('utf-8'));\n"));
}

#[tokio::test]
async fn a_project_without_a_manifest_at_its_root_is_refused_before_a_draft() {
    let project = tempfile::tempdir().unwrap();
    write(
        project.path(),
        "frames.js",
        "/** @param {Buffer} data */\nfunction parse(data) {\n  return data.length;\n}\nmodule.exports = { parse };\n",
    );
    let candidate = discovered(project.path(), "parse").await;
    let refused =
        super::heuristic_draft(&candidate, EngineKind::JazzerJs, Sanitizer::Address, false)
            .unwrap_err()
            .to_string();
    assert!(refused.contains("package.json"), "{refused}");
    // Nothing of it is staged either: a loose script directory is not a
    // Node.js project.
    let workspace = tempfile::tempdir().unwrap();
    copy_project_sources(project.path(), workspace.path());
    assert!(!workspace.path().join("frames.js").exists());
}

#[tokio::test]
async fn a_node_project_is_staged_with_its_declared_packages_and_retained_as_the_run_loads_it() {
    let project = tempfile::tempdir().unwrap();
    node_project(project.path(), FRAMES_JS);
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "/etc/hosts",
        project.path().join("node_modules/tablekit/hosts"),
    )
    .unwrap();
    let candidate = discovered(project.path(), "parse").await;
    let workspace = tempfile::tempdir().unwrap();
    copy_project_sources(project.path(), workspace.path());
    for staged in [
        "package.json",
        "lib/frames.js",
        "lib/codec.mjs",
        "node_modules/tablekit/package.json",
        "node_modules/tablekit/index.js",
        "node_modules/tablekit/build/table.json",
        "node_modules/tablekit/LICENSE",
    ] {
        assert!(workspace.path().join(staged).is_file(), "{staged}");
    }
    assert!(!workspace.path().join("harness.mjs").exists());
    assert!(!workspace.path().join("README.md").exists());
    assert!(!workspace
        .path()
        .join("node_modules/tablekit/hosts")
        .exists());

    // The "binary" of a JavaScript harness is the executable module itself.
    let draft = super::heuristic_draft(&candidate, EngineKind::JazzerJs, Sanitizer::Address, false)
        .unwrap();
    let artifact = workspace.path().join("fuzz_parse");
    std::fs::write(&artifact, &draft.source).unwrap();
    std::fs::write(workspace.path().join("harness.mjs"), &draft.source).unwrap();
    // Workspace bookkeeping is not project source.
    write(workspace.path(), ".oxfuzz-workspace.json", "{}\n");
    write(workspace.path(), "out/report.json", "{}\n");
    write(workspace.path(), "semgrep/results.json", "{}\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let artifacts = super::staging::stage_run_artifacts(
        workspace.path(),
        Uuid::new_v4(),
        &draft.source,
        &artifact,
        None,
    )
    .unwrap();
    assert_eq!(
        artifacts.source_context_host,
        artifacts
            .binary_host
            .with_file_name(hf_harness::js_jazzer::RETAINED_SOURCES_DIR)
    );
    let retained = &artifacts.source_context_host;
    assert_eq!(
        std::fs::read_to_string(retained.join("lib/frames.js")).unwrap(),
        FRAMES_JS
    );
    // The manifest decides how Node.js reads the project's modules, and the
    // packages are what they load.
    for kept in [
        "package.json",
        "lib/codec.mjs",
        "node_modules/tablekit/package.json",
        "node_modules/tablekit/index.js",
        "node_modules/tablekit/build/table.json",
        "node_modules/tablekit/LICENSE",
    ] {
        assert!(retained.join(kept).is_file(), "{kept}");
    }
    for left_out in [
        "harness.mjs",
        ".oxfuzz-workspace.json",
        "out/report.json",
        "semgrep/results.json",
        "fuzz_parse",
    ] {
        assert!(!retained.join(left_out).exists(), "{left_out}");
    }
}

#[test]
fn packages_are_staged_only_when_the_manifest_declares_dependencies() {
    for (manifest, expected) in [
        ("{ \"name\": \"x\" }", false),
        ("{ \"name\": \"x\", \"dependencies\": {} }", false),
        (
            "{ \"name\": \"x\", \"devDependencies\": { \"mocha\": \"1\" } }",
            false,
        ),
        (
            "{ \"name\": \"x\", \"dependencies\": { \"a\": \"1\" } }",
            true,
        ),
        (
            "{ \"name\": \"x\", \"optionalDependencies\": { \"a\": \"1\" } }",
            true,
        ),
        (
            "{ \"name\": \"x\", \"peerDependencies\": { \"a\": \"1\" } }",
            true,
        ),
        ("not json", false),
        ("[1, 2]", false),
    ] {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "package.json", manifest);
        write(project.path(), "index.js", "module.exports = {};\n");
        write(project.path(), "data/table.json", "[]\n");
        write(
            project.path(),
            "node_modules/a/index.js",
            "module.exports = 1;\n",
        );
        let workspace = tempfile::tempdir().unwrap();
        copy_project_sources(project.path(), workspace.path());
        assert!(workspace.path().join("index.js").is_file(), "{manifest}");
        assert!(
            workspace.path().join("data/table.json").is_file(),
            "{manifest}"
        );
        assert_eq!(
            workspace.path().join("node_modules/a/index.js").is_file(),
            expected,
            "{manifest}"
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
    symbol: &str,
    workspace: &Path,
) -> hf_harness::CompileResult {
    copy_project_sources(project, workspace);
    let candidate = discovered(project, symbol).await;
    let draft = super::heuristic_draft(&candidate, EngineKind::JazzerJs, Sanitizer::Address, false)
        .unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: candidate.id,
        engine: EngineKind::JazzerJs,
        source: draft.source,
        language: TargetLanguage::JavaScript,
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
    smoke_seeded(runtime, harness, workspace, None).await
}

async fn smoke_seeded(
    runtime: &hf_runtime::docker::DockerRuntime,
    harness: Harness,
    workspace: &Path,
    seed: Option<u64>,
) -> Result<Harness, hf_core::error::ClassifiedError> {
    let mut config = run_config(&harness, 20);
    config.seed = seed;
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

/// Check, fuzz, collect, replay, and classify a planted JavaScript defect in
/// the real sandbox, in a project that loads a package it carries; show the
/// run's retained sources are what a staged run loads; show the corrected
/// function fuzzes clean; and show that a syntax error and a module that
/// cannot load fail as such, not as findings.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_jazzer_js_finds_replays_and_classifies_a_planted_exception() {
    assert!(hf_runtime::docker_daemon_ready());
    let project = tempfile::tempdir().unwrap();
    node_project(project.path(), FRAMES_JS);
    let candidate = discovered(project.path(), "parse").await;
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    let hf_harness::CompileResult::Ok(checked) =
        check(&runtime, project.path(), "parse", &workspace).await
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
        hf_crash::ingest_for_engine(&out, EngineKind::JazzerJs, Uuid::new_v4(), candidate.id)
            .unwrap();
    assert_eq!(ingested.crashes.len(), 1, "{:?}", ingested.crashes);
    let input = ingested.crashes[0].input_path.clone();
    let name = input.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("crash-"), "{name}");
    let bytes = std::fs::read(&input).unwrap();
    assert!(bytes.starts_with(b"MZ") && bytes[2] > 2, "{bytes:?}");

    // Replay as triage does: the artifact, then the input.
    let container_input = format!("/work/out/{name}");
    let (exit_code, log) = replay(&runtime, &workspace, "/work/fuzz_parse", &container_input).await;
    assert_eq!(exit_code, 77, "{log}");
    assert!(hf_crash::looks_like_crash(&log), "{log}");
    let (kind, signature, classified) = hf_crash::classify(&log);
    println!("classified: {kind:?} {classified}");
    assert_eq!(kind, hf_core::crash::CrashKind::Panic);
    assert_eq!(
        classified,
        "TypeError: Cannot read properties of undefined (reading 'toString')"
    );

    // A staged run loads the sources retained with it, not the workspace:
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
    replace_file(&workspace.join("lib/frames.js"), FRAMES_JS_FIXED);
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
            "/work/runs/{run_id}/input/source-context/lib/frames.js"
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
    write(project.path(), "lib/frames.js", FRAMES_JS_FIXED);
    let fixed_workspace = root.path().join("fixed");
    std::fs::create_dir_all(&fixed_workspace).unwrap();
    let hf_harness::CompileResult::Ok(fixed) =
        check(&runtime, project.path(), "parse", &fixed_workspace).await
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

    // A module that parses but cannot load is a failed smoke, not a finding.
    write(
        project.path(),
        "lib/frames.js",
        &FRAMES_JS_FIXED.replace(
            "require('tablekit')",
            "require('a-package-that-is-not-staged')",
        ),
    );
    let unloadable_workspace = root.path().join("unloadable");
    std::fs::create_dir_all(&unloadable_workspace).unwrap();
    let hf_harness::CompileResult::Ok(unloadable) =
        check(&runtime, project.path(), "parse", &unloadable_workspace).await
    else {
        panic!("the module parses, so the build passes");
    };
    let error = smoke(&runtime, *unloadable, &unloadable_workspace)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("outside fuzzing"), "{error}");
    assert!(error.contains("a-package-that-is-not-staged"), "{error}");
    assert!(hf_crash::ingest_for_engine(
        &unloadable_workspace.join("out"),
        EngineKind::JazzerJs,
        Uuid::new_v4(),
        candidate.id,
    )
    .unwrap()
    .crashes
    .is_empty());

    // A syntax error in the selected module fails the build, before anything
    // is loaded. The declaration line still parses, so discovery reports it.
    write(
        project.path(),
        "lib/frames.js",
        &FRAMES_JS_FIXED.replace("return '';", "return ';"),
    );
    let broken_workspace = root.path().join("broken");
    std::fs::create_dir_all(&broken_workspace).unwrap();
    match check(&runtime, project.path(), "parse", &broken_workspace).await {
        hf_harness::CompileResult::Failed(failure) => {
            assert!(failure.stderr.contains("SyntaxError"), "{}", failure.stderr);
        }
        hf_harness::CompileResult::Ok(_) => panic!("a syntax error must fail the build"),
    }
}

/// An asynchronous function of an ES module with two documented parameters:
/// the arguments come from the data provider, the module is instrumented
/// through `import`, the rejected promise is the finding, and its replay
/// classifies by the function under test.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_jazzer_js_fuzzes_an_async_es_module_function_with_typed_parameters() {
    assert!(hf_runtime::docker_daemon_ready());
    let project = tempfile::tempdir().unwrap();
    node_project(project.path(), FRAMES_JS);
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());

    let hf_harness::CompileResult::Ok(checked) =
        check(&runtime, project.path(), "decode", &workspace).await
    else {
        panic!("the syntax-only build failed");
    };
    assert!(checked.source.contains("provider.consumeNumber()"));
    // The seed is fixed because the search is not reliably short: the string
    // follows the number in the input, the fuzzer lengthens its inputs, and
    // the two bytes that matter must land at the start. With random seeds,
    // 8 of 40 twenty-second runs did not reach the rejection (2026-11-22);
    // with this one the run is repeatable and reaches it after 70,422 inputs.
    let smoked = smoke_seeded(&runtime, *checked, &workspace, Some(4))
        .await
        .unwrap();
    let summary = smoked.smoke_run.clone().unwrap();
    println!("smoke: {summary:?}");
    assert!(summary.crashes > 0, "the planted rejection was found");

    let ingested = hf_crash::ingest_for_engine(
        &workspace.join("out"),
        EngineKind::JazzerJs,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .unwrap();
    assert_eq!(ingested.crashes.len(), 1, "{:?}", ingested.crashes);
    let name = ingested.crashes[0]
        .input_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let (exit_code, log) = replay(
        &runtime,
        &workspace,
        "/work/fuzz_decode",
        &format!("/work/out/{name}"),
    )
    .await;
    assert_eq!(exit_code, 77, "{log}");
    let (kind, _, classified) = hf_crash::classify(&log);
    println!("classified: {kind:?} {classified}");
    assert_eq!(kind, hf_core::crash::CrashKind::Panic);
    assert!(
        classified.starts_with("RangeError: unbalanced frame of "),
        "{classified}"
    );
    assert!(log.contains("decode (file:///work/lib/codec.mjs"), "{log}");
}
