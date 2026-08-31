//! Build Doctor detection and plan contract.
//!
//! Detection is read-only and evidence-citing; a plan is emitted only when the
//! pinned sandbox image can actually run it. Nothing here executes.

#![cfg(feature = "build-doctor")]

use std::path::Path;

use hf_service::build_doctor::{
    detect_build_systems, BuildSystem, BuildSystemStatus, MISSING_TOOL_BEAR,
};

fn project(files: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for name in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"# marker\n").unwrap();
    }
    dir
}

fn detected(root: &Path) -> Vec<(BuildSystem, BuildSystemStatus)> {
    detect_build_systems(root)
        .into_iter()
        .map(|entry| (entry.build_system, entry.status))
        .collect()
}

#[test]
fn every_marker_file_identifies_its_build_system() {
    for (marker, expected) in [
        ("CMakeLists.txt", BuildSystem::CMake),
        ("meson.build", BuildSystem::Meson),
        ("configure.ac", BuildSystem::Autotools),
        ("configure.in", BuildSystem::Autotools),
        ("Makefile.am", BuildSystem::Autotools),
        ("Makefile", BuildSystem::Make),
        ("makefile", BuildSystem::Make),
        ("GNUmakefile", BuildSystem::Make),
        ("WORKSPACE", BuildSystem::Bazel),
        ("WORKSPACE.bazel", BuildSystem::Bazel),
        ("MODULE.bazel", BuildSystem::Bazel),
        ("BUILD.bazel", BuildSystem::Bazel),
        ("Cargo.toml", BuildSystem::Cargo),
    ] {
        let dir = project(&[marker]);
        let found = detect_build_systems(dir.path());
        assert_eq!(
            found
                .iter()
                .map(|entry| entry.build_system)
                .collect::<Vec<_>>(),
            vec![expected],
            "marker {marker} identifies {expected:?}"
        );
        assert!(
            found[0].markers.iter().any(|found| found == marker),
            "the detection cites the marker it found: {found:?}"
        );
    }
}

#[test]
fn a_project_with_no_marker_is_unknown_and_never_guessed() {
    let dir = project(&["parser.c", "README.md"]);
    let found = detect_build_systems(dir.path());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].build_system, BuildSystem::Unknown);
    assert_eq!(found[0].status, BuildSystemStatus::Unknown);
    assert!(found[0].plan.is_none(), "an unknown project gets no plan");
}

#[test]
fn a_marker_in_a_subdirectory_belongs_to_a_component_not_the_project() {
    let dir = project(&["parser.c", "third_party/zlib/CMakeLists.txt"]);
    let found = detect_build_systems(dir.path());
    assert_eq!(found[0].build_system, BuildSystem::Unknown);
}

#[test]
fn several_markers_report_several_systems_in_specificity_order() {
    // A CMake project's Makefile is generated output, so CMake ranks first.
    let dir = project(&["CMakeLists.txt", "Makefile"]);
    let found = detected(dir.path());
    assert_eq!(found[0].0, BuildSystem::CMake);
    assert_eq!(found[1].0, BuildSystem::Make);
}

#[test]
fn cmake_is_supported_and_its_plan_is_a_configure_step_with_a_named_artifact() {
    let dir = project(&["CMakeLists.txt"]);
    let found = detect_build_systems(dir.path());
    assert_eq!(found[0].status, BuildSystemStatus::Supported);
    let plan = found[0]
        .plan
        .as_ref()
        .expect("a supported system has a plan");
    assert_eq!(
        plan.expected_artifact,
        ".oxfuzz-build/compile_commands.json"
    );
    assert_eq!(plan.steps.len(), 1);
    let step = &plan.steps[0];
    assert_eq!(step.argv[0], "cmake");
    assert!(step
        .argv
        .iter()
        .any(|arg| arg == "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"));
    // oxfuzz owns its build directory; a plan never clobbers the operator's.
    assert!(step.argv.iter().any(|arg| arg == ".oxfuzz-build"));
    assert!(
        !step
            .argv
            .iter()
            .any(|arg| arg.contains("&&") || arg.contains(';')),
        "steps are fixed argument vectors, never shell strings: {:?}",
        step.argv
    );
}

#[test]
fn a_detected_system_the_image_cannot_run_names_the_missing_tool_and_emits_no_plan() {
    for (marker, expected_tool) in [
        ("Makefile", MISSING_TOOL_BEAR),
        ("configure.ac", MISSING_TOOL_BEAR),
        ("meson.build", "meson"),
        ("WORKSPACE", "bazel"),
    ] {
        let dir = project(&[marker]);
        let found = detect_build_systems(dir.path());
        assert_eq!(
            found[0].status,
            BuildSystemStatus::UnsupportedInImage,
            "{marker} cannot be run by the pinned image"
        );
        assert_eq!(found[0].missing_tool.as_deref(), Some(expected_tool));
        assert!(
            found[0].plan.is_none(),
            "a plan that cannot run is worse than an honest refusal"
        );
    }
}

#[test]
fn a_rust_project_needs_no_compile_database() {
    let dir = project(&["Cargo.toml"]);
    let found = detect_build_systems(dir.path());
    assert_eq!(found[0].status, BuildSystemStatus::NotNeeded);
    assert!(found[0].plan.is_none());
}

#[test]
fn a_project_that_already_ships_a_database_is_ready_and_gets_no_plan() {
    let dir = project(&["CMakeLists.txt"]);
    let root = dir.path().to_string_lossy().into_owned();
    let source = dir.path().join("a.c").to_string_lossy().into_owned();
    let include = format!("-I{}", dir.path().join("include").to_string_lossy());
    std::fs::write(
        dir.path().join("compile_commands.json"),
        serde_json::to_vec(&serde_json::json!([{
            "directory": root,
            "file": source,
            "arguments": ["clang", include, "-c", source],
        }]))
        .unwrap(),
    )
    .unwrap();
    let found = detect_build_systems(dir.path());
    assert_eq!(found[0].status, BuildSystemStatus::Ready);
    assert!(
        found[0].plan.is_none(),
        "a project that already has usable build context needs no plan"
    );
}

#[test]
fn malformed_or_empty_compile_database_is_not_reported_as_ready() {
    for contents in ["{not json", "[]"] {
        let dir = project(&["CMakeLists.txt"]);
        std::fs::write(dir.path().join("compile_commands.json"), contents).unwrap();

        let found = detect_build_systems(dir.path());

        assert_eq!(found[0].status, BuildSystemStatus::Supported);
        assert!(found[0].plan.is_some());
    }
}

#[test]
fn validated_build_doctor_database_is_reported_as_ready() {
    let dir = project(&["CMakeLists.txt"]);
    let owned = dir.path().join(".oxfuzz-build");
    std::fs::create_dir(&owned).unwrap();
    let root = dir.path().to_string_lossy().into_owned();
    let source = dir.path().join("a.c").to_string_lossy().into_owned();
    let include = format!("-I{}", dir.path().join("include").to_string_lossy());
    std::fs::write(
        owned.join("compile_commands.json"),
        serde_json::to_vec(&serde_json::json!([{
            "directory": root,
            "file": source,
            "arguments": ["clang", include, "-c", source],
        }]))
        .unwrap(),
    )
    .unwrap();

    let found = detect_build_systems(dir.path());

    assert_eq!(found[0].status, BuildSystemStatus::Ready);
    assert!(found[0].plan.is_none());
}
