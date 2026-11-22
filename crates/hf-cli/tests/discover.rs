//! Binary-level tests for `oxfuzz discover` harnessability reporting and the
//! `oxfuzz fuzz` auto-pick gate. No Docker, no providers: discovery is a pure
//! scan, and the fuzz pipeline fails at the discover stage before any sandbox
//! work.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A throwaway oxfuzz environment: config, database, workspace, and a private
/// HOME so the child process's run journal and app data stay inside it.
struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary fixture root");
        std::fs::create_dir_all(directory.path().join("home")).unwrap();
        Self { directory }
    }

    fn oxfuzz(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxfuzz"));
        command
            .args(args)
            .env("HF_CONFIG_DIR", self.directory.path().join("config"))
            .env("HF_DB_PATH", self.directory.path().join("oxfuzz.db"))
            .env("HF_WORKSPACE_DIR", self.directory.path().join("workspace"))
            .env("HOME", self.directory.path().join("home"))
            .env("HF_USE_DOCKER", "0")
            .env_remove("HF_PROVIDER_API_KEY")
            .env_remove("HF_AUTO_APPROVE")
            .env_remove("HF_GUARDRAILS");
        command
    }

    /// A project with one public static Java method: harnessable under the
    /// jazzer engine only.
    fn java_project(&self) -> PathBuf {
        let project = self.directory.path().join("javaproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("Frames.java"),
            "public final class Frames {\n    public static int parse(byte[] data) {\n        return data.length;\n    }\n}\n",
        )
        .unwrap();
        project
    }

    /// A project with one exported JavaScript function: harnessable under
    /// the jazzer-js engine only.
    fn javascript_project(&self) -> PathBuf {
        let project = self.directory.path().join("jsproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("package.json"), "{ \"name\": \"frames\" }\n").unwrap();
        std::fs::write(
            project.join("frames.js"),
            "/** @param {Buffer} data */\nfunction parseFrame(data) {\n  return data.length;\n}\nmodule.exports = { parseFrame };\n",
        )
        .unwrap();
        project
    }

    /// A project with one parameter-bearing Python function: harnessable
    /// under the atheris engine only.
    fn python_project(&self) -> PathBuf {
        let project = self.directory.path().join("pyproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parser.py"),
            "def parse_packet(data, offset):\n    return len(data) > offset\n",
        )
        .unwrap();
        project
    }

    /// A project with one exported, parameter-bearing Go function: harnessable
    /// under the go-native engine only.
    fn go_project(&self) -> PathBuf {
        let project = self.directory.path().join("goproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parser.go"),
            "package parser\n\nfunc ParsePacket(data []byte, offset int) bool {\n\treturn len(data) > offset\n}\n",
        )
        .unwrap();
        project
    }

    /// A project directory with one fuzzable C parser function.
    fn c_project(&self) -> PathBuf {
        let project = self.directory.path().join("cproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parse.c"),
            "#include <stddef.h>\n#include <stdint.h>\n\
             int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
        )
        .unwrap();
        project
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn inventory(output: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(output)).unwrap_or_else(|error| {
        panic!(
            "discover stdout must stay machine-readable: {error}; stderr={:?}",
            stderr(output)
        )
    })
}

#[test]
fn discover_python_java_and_javascript_mark_candidates_harnessable_without_a_note() {
    let fixture = Fixture::new();
    for (project, language, symbol) in [
        (fixture.python_project(), "python", "parse_packet"),
        (fixture.java_project(), "java", "Frames.parse"),
        (fixture.javascript_project(), "javascript", "parseFrame"),
        (fixture.javascript_project(), "js", "parseFrame"),
    ] {
        let run = fixture
            .oxfuzz(&["discover", &project.to_string_lossy(), "--lang", language])
            .output()
            .expect("spawn oxfuzz discover");

        assert!(run.status.success(), "{language}: {}", stderr(&run));
        let inventory = inventory(&run);
        let candidates = inventory["candidates"]
            .as_array()
            .expect("candidates array");
        assert_eq!(candidates.len(), 1, "{language}: {candidates:?}");
        assert_eq!(candidates[0]["symbol"], symbol);
        assert_eq!(candidates[0]["harnessable"], serde_json::Value::Bool(true));
        assert!(
            !stderr(&run).contains("not yet available"),
            "{language}: {}",
            stderr(&run)
        );
    }
}

#[test]
fn discover_go_marks_candidates_harnessable_without_a_note() {
    let fixture = Fixture::new();
    let project = fixture.go_project();

    let run = fixture
        .oxfuzz(&["discover", &project.to_string_lossy(), "--lang", "go"])
        .output()
        .expect("spawn oxfuzz discover");

    assert!(run.status.success(), "{}", stderr(&run));
    let inventory = inventory(&run);
    let candidates = inventory["candidates"]
        .as_array()
        .expect("candidates array");
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert_eq!(candidates[0]["symbol"], "ParsePacket");
    assert_eq!(candidates[0]["harnessable"], serde_json::Value::Bool(true));
    assert!(
        !stderr(&run).contains("not yet available"),
        "{}",
        stderr(&run)
    );
}

#[test]
fn discover_c_marks_candidates_harnessable_without_a_note() {
    let fixture = Fixture::new();
    let project = fixture.c_project();

    let run = fixture
        .oxfuzz(&["discover", &project.to_string_lossy(), "--lang", "c"])
        .output()
        .expect("spawn oxfuzz discover");

    assert!(run.status.success(), "{}", stderr(&run));
    let inventory = inventory(&run);
    let candidates = inventory["candidates"]
        .as_array()
        .expect("candidates array");
    assert!(!candidates.is_empty(), "the C scan finds the parser");
    assert_eq!(
        candidates[0]["harnessable"],
        serde_json::Value::Bool(true),
        "the candidate is marked: {candidates:?}"
    );
    assert!(
        !stderr(&run).contains("not yet available"),
        "a harnessable language gets no gating note: {}",
        stderr(&run)
    );
}

#[test]
fn fuzz_on_a_managed_language_project_under_the_default_engine_names_its_engine() {
    let fixture = Fixture::new();
    for (project, expected) in [
        (
            fixture.python_project(),
            "python targets run under --engine atheris",
        ),
        (
            fixture.java_project(),
            "java targets run under --engine jazzer",
        ),
        (
            fixture.javascript_project(),
            "javascript targets run under --engine jazzer-js",
        ),
    ] {
        let run = fixture
            .oxfuzz(&["fuzz", &project.to_string_lossy()])
            .output()
            .expect("spawn oxfuzz fuzz");

        assert!(!run.status.success(), "{}", stdout(&run));
        let err = stderr(&run);
        assert!(
            err.contains(expected),
            "the engine that drives the language is named: {err}"
        );
        assert!(
            !err.contains("[2/5] harness"),
            "the pipeline never reaches harness work: {err}"
        );
    }
}

#[test]
fn fuzz_on_a_go_only_project_under_the_default_engine_names_go_native() {
    let fixture = Fixture::new();
    let project = fixture.go_project();

    let run = fixture
        .oxfuzz(&["fuzz", &project.to_string_lossy()])
        .output()
        .expect("spawn oxfuzz fuzz");

    assert!(!run.status.success(), "{}", stdout(&run));
    let err = stderr(&run);
    assert!(
        err.contains("go targets run under --engine go-native"),
        "the engine that drives Go is named: {err}"
    );
    assert!(
        !err.contains("[2/5] harness"),
        "the pipeline never reaches harness work: {err}"
    );
}

#[test]
fn discover_json_flag_keeps_stdout_machine_readable() {
    let fixture = Fixture::new();
    let project = fixture.c_project();

    let run = fixture
        .oxfuzz(&[
            "discover",
            &project.to_string_lossy(),
            "--lang",
            "c",
            "--json",
        ])
        .output()
        .expect("spawn oxfuzz discover");

    assert!(run.status.success(), "--json is accepted: {}", stderr(&run));
    let inventory = inventory(&run);
    assert_eq!(inventory["candidates"][0]["symbol"], "parse_entry");
}
