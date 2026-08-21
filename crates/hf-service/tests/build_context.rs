//! Tests for resolving a project's compile database into compile context.
#![cfg(feature = "build-context")]

use std::sync::Arc;

use hf_service::ServiceContainer;

/// The construction every hf-service integration test uses
/// (`crates/hf-service/tests/workbench.rs`). `StubRuntime` refuses every sandbox
/// operation, which is correct here: resolving a compile database reads a
/// project file and executes nothing.
fn test_container() -> ServiceContainer {
    ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
}

/// Write a one-entry compile database whose recorded command is `arguments`.
///
/// Built with `serde_json` rather than string interpolation: a Windows
/// temporary directory is `C:\\Users\\...`, and those separators are invalid
/// JSON escapes when pasted into a string literal.
fn write_database_at(path: &std::path::Path, project: &std::path::Path, arguments: &[String]) {
    let document = serde_json::json!([{
        "directory": project,
        "file": project.join("a.c"),
        "arguments": arguments,
    }]);
    std::fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
}

fn write_database(project: &std::path::Path, arguments: &[String]) {
    write_database_at(&project.join("compile_commands.json"), project, arguments);
}

/// `-I<project>/include`, spelled the way the host spells paths.
fn include_flag(project: &std::path::Path) -> String {
    format!("-I{}", project.join("include").display())
}

fn owned(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn a_project_without_a_compile_database_resolves_to_none() {
    let project = tempfile::tempdir().unwrap();
    assert!(test_container()
        .resolve_build_context(project.path())
        .unwrap()
        .is_none());
}

#[test]
fn a_compile_database_yields_include_dirs_and_defines() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("include")).unwrap();
    std::fs::write(project.path().join("a.c"), "int a(void){return 0;}").unwrap();
    let mut arguments = owned(&["cc"]);
    arguments.push(include_flag(project.path()));
    arguments.extend(owned(&["-DA=1", "-std=c11", "-c", "a.c"]));
    write_database(project.path(), &arguments);

    let ctx = test_container()
        .resolve_build_context(project.path())
        .unwrap()
        .unwrap();

    assert_eq!(ctx.include_dirs, vec![project.path().join("include")]);
    assert_eq!(ctx.defines, vec!["-DA=1"]);
    assert_eq!(ctx.std_flag.as_deref(), Some("-std=c11"));
}

#[test]
fn a_database_in_the_build_subdirectory_is_found() {
    // CMake writes the database into its build tree, not the project root.
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("build")).unwrap();
    std::fs::create_dir_all(project.path().join("include")).unwrap();
    let mut arguments = owned(&["cc"]);
    arguments.push(include_flag(project.path()));
    arguments.extend(owned(&["-c", "a.c"]));
    write_database_at(
        &project.path().join("build/compile_commands.json"),
        project.path(),
        &arguments,
    );

    let ctx = test_container()
        .resolve_build_context(project.path())
        .unwrap()
        .unwrap();

    assert_eq!(ctx.include_dirs, vec![project.path().join("include")]);
}

#[test]
fn a_malformed_compile_database_is_an_error() {
    // A present-but-broken database is a configuration fault the operator must
    // see, not something to silently treat as absent.
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("compile_commands.json"), "{not json").unwrap();
    assert!(test_container()
        .resolve_build_context(project.path())
        .is_err());
}

#[test]
fn a_database_yielding_nothing_usable_resolves_to_none() {
    // Parsed cleanly but every argument was rejected or irrelevant: there is
    // nothing for the compiler or the prompt to use, so callers see the same
    // thing they would for a project with no database.
    let project = tempfile::tempdir().unwrap();
    write_database(project.path(), &owned(&["cc", "-Wall", "-O2", "-c", "a.c"]));
    assert!(test_container()
        .resolve_build_context(project.path())
        .unwrap()
        .is_none());
}

// Unix-only: the assertion is about refusing a symlink, so it is meaningless
// where the test cannot create one. Gating the whole test rather than the setup
// keeps it from passing vacuously on Windows.
#[cfg(unix)]
#[test]
fn a_symlinked_compile_database_is_refused() {
    // The database is read from inside an untrusted project; a symlink there
    // must not be able to redirect the read at an arbitrary host file.
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("elsewhere.json");
    std::fs::write(&target, "[]").unwrap();
    std::os::unix::fs::symlink(&target, project.path().join("compile_commands.json")).unwrap();

    assert!(test_container()
        .resolve_build_context(project.path())
        .is_err());
}
