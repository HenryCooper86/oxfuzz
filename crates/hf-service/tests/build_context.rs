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

fn write_database(project: &std::path::Path, arguments: &str) {
    let db = format!(
        r#"[{{"directory":"{root}","file":"{root}/a.c","arguments":{arguments}}}]"#,
        root = project.display()
    );
    std::fs::write(project.join("compile_commands.json"), db).unwrap();
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
    write_database(
        project.path(),
        &format!(
            r#"["cc","-I{root}/include","-DA=1","-std=c11","-c","{root}/a.c"]"#,
            root = project.path().display()
        ),
    );

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
    let db = format!(
        r#"[{{"directory":"{root}","file":"{root}/a.c",
              "arguments":["cc","-I{root}/include","-c","{root}/a.c"]}}]"#,
        root = project.path().display()
    );
    std::fs::write(project.path().join("build/compile_commands.json"), db).unwrap();

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
    write_database(project.path(), r#"["cc","-Wall","-O2","-c","a.c"]"#);
    assert!(test_container()
        .resolve_build_context(project.path())
        .unwrap()
        .is_none());
}

#[test]
fn a_symlinked_compile_database_is_refused() {
    // The database is read from inside an untrusted project; a symlink there
    // must not be able to redirect the read at an arbitrary host file.
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("elsewhere.json");
    std::fs::write(&target, "[]").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, project.path().join("compile_commands.json")).unwrap();

    assert!(test_container()
        .resolve_build_context(project.path())
        .is_err());
}
