use super::*;

fn fixture() -> (tempfile::TempDir, SaveBuildProfileRequest) {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("components/parser")).unwrap();
    std::fs::write(
        project.path().join("components/parser/CMakeLists.txt"),
        "project(parser)\n",
    )
    .unwrap();
    let request = SaveBuildProfileRequest {
        project: project.path().to_str().unwrap().to_owned(),
        component_root: "components/parser".to_owned(),
        build_system: ProfileBuildSystem::CMake,
        compile_database_path: "build/parser/compile_commands.json".to_owned(),
        cmake_definitions: BTreeMap::new(),
        dependencies: Vec::new(),
    };
    (project, request)
}

fn normalize(request: &SaveBuildProfileRequest) -> Result<BuildProfileView, ClassifiedError> {
    normalize_profile(
        request,
        &BuildProfileSettings::default(),
        &ImmutableImageReference::from_sha256_id(format!("sha256:{}", "a".repeat(64))).unwrap(),
        chrono::Utc::now(),
    )
}

#[test]
fn nested_component_and_absent_output_normalize_without_injected_options() {
    let (project, mut request) = fixture();
    request.component_root = "./components//parser/".to_owned();
    request.compile_database_path = "./build//parser/compile_commands.json".to_owned();
    let profile = normalize(&request).unwrap();
    assert_eq!(
        profile.project_root,
        project.path().canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(profile.component_root, "components/parser");
    assert_eq!(
        profile.compile_database_path,
        "build/parser/compile_commands.json"
    );
    assert_eq!(profile.marker_path, "components/parser/CMakeLists.txt");
    assert!(profile.cmake_definitions.is_empty());
    assert!(!project.path().join("build").exists());
    assert_eq!(
        profile.sandbox_image_id,
        format!("sha256:{}", "a".repeat(64))
    );
}

#[test]
fn profile_rejects_absolute_parent_and_foreign_paths() {
    let (_project, request) = fixture();
    for path in [
        "",
        "..",
        "components/../components/parser",
        "/tmp",
        "C:\\project",
        "components\\parser",
        "components/pa\nrser",
    ] {
        let mut changed = request.clone();
        changed.component_root = path.to_owned();
        assert!(normalize(&changed).is_err(), "accepted component {path:?}");
    }
    for path in [
        "/tmp/compile_commands.json",
        "../compile_commands.json",
        "build/../compile_commands.json",
        "build/commands.json",
        "C:/compile_commands.json",
    ] {
        let mut changed = request.clone();
        changed.compile_database_path = path.to_owned();
        assert!(normalize(&changed).is_err(), "accepted database {path:?}");
    }
}

#[cfg(unix)]
#[test]
fn symlink_components_markers_and_output_ancestors_are_rejected() {
    use std::os::unix::fs::symlink;
    let (project, request) = fixture();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), project.path().join("build")).unwrap();
    assert!(normalize(&request).is_err());
    std::fs::remove_file(project.path().join("build")).unwrap();
    symlink(
        project.path().join("components/parser"),
        project.path().join("alias"),
    )
    .unwrap();
    let mut changed = request.clone();
    changed.component_root = "alias".to_owned();
    assert!(normalize(&changed).is_err());
    let marker = project.path().join("components/parser/CMakeLists.txt");
    std::fs::remove_file(&marker).unwrap();
    std::fs::write(outside.path().join("marker"), "project(outside)").unwrap();
    symlink(outside.path().join("marker"), marker).unwrap();
    assert!(normalize(&request).is_err());
}

#[test]
fn missing_component_marker_and_non_directory_output_parent_are_rejected() {
    let (project, mut request) = fixture();
    request.component_root = "absent".to_owned();
    assert!(normalize(&request).is_err());
    request.component_root = "components/parser".to_owned();
    request.build_system = ProfileBuildSystem::Make;
    assert!(normalize(&request).is_err());
    request.build_system = ProfileBuildSystem::CMake;
    std::fs::write(project.path().join("build"), "ordinary file").unwrap();
    assert!(normalize(&request).is_err());
}

#[test]
fn make_uses_gnu_marker_precedence_and_rejects_higher_level_systems() {
    let (project, mut request) = fixture();
    request.component_root = ".".to_owned();
    request.build_system = ProfileBuildSystem::Make;
    for marker in ["Makefile", "makefile", "GNUmakefile"] {
        std::fs::write(project.path().join(marker), "all:\n").unwrap();
    }
    assert_eq!(normalize(&request).unwrap().marker_path, "GNUmakefile");
    for marker in [
        "CMakeLists.txt",
        "configure.ac",
        "meson.build",
        "WORKSPACE",
        "Cargo.toml",
    ] {
        std::fs::write(project.path().join(marker), "# higher level").unwrap();
        assert!(normalize(&request).is_err(), "accepted Make with {marker}");
        std::fs::remove_file(project.path().join(marker)).unwrap();
    }
}

#[test]
fn options_require_allowed_names_and_safe_exact_values() {
    let (_project, mut request) = fixture();
    for (name, value) in [
        ("UNLISTED", "ON"),
        ("build_testing", "ON"),
        ("BUILD_TESTING", ""),
        ("BUILD_TESTING", "-ON"),
        ("BUILD_TESTING", "ON;OFF"),
        ("BUILD_TESTING", "a b"),
        ("BUILD_TESTING", "$HOME"),
        ("BUILD_TESTING", "é"),
    ] {
        request.cmake_definitions = [(name.to_owned(), value.to_owned())].into_iter().collect();
        assert!(normalize(&request).is_err(), "accepted {name}={value}");
    }
    request.cmake_definitions = [("BUILD_TESTING".to_owned(), "a".repeat(129))]
        .into_iter()
        .collect();
    assert!(normalize(&request).is_err());
    for value in ["ON", "OFF", "MiXeD_+.,:/-42"] {
        request
            .cmake_definitions
            .insert("BUILD_TESTING".to_owned(), value.to_owned());
        assert_eq!(
            normalize(&request).unwrap().cmake_definitions["BUILD_TESTING"],
            value
        );
    }
}

#[test]
fn make_rejects_cmake_definitions() {
    let (project, mut request) = fixture();
    request.component_root = ".".to_owned();
    request.build_system = ProfileBuildSystem::Make;
    std::fs::write(project.path().join("Makefile"), "all:\n").unwrap();
    request
        .cmake_definitions
        .insert("BUILD_TESTING".to_owned(), "OFF".to_owned());
    assert!(normalize(&request).is_err());
}

#[test]
fn dependencies_validate_normalize_and_preserve_case() {
    let (_project, mut request) = fixture();
    for name in ["", "-make", "a/b", "a:b", "x y", "é"] {
        request.dependencies = vec![BuildDependency {
            kind: BuildDependencyKind::Command,
            name: name.to_owned(),
        }];
        assert!(normalize(&request).is_err(), "accepted dependency {name}");
    }
    request.dependencies = vec![BuildDependency {
        kind: BuildDependencyKind::Command,
        name: "x".repeat(65),
    }];
    assert!(normalize(&request).is_err());
    let command = BuildDependency {
        kind: BuildDependencyKind::Command,
        name: "Make".to_owned(),
    };
    let module = BuildDependency {
        kind: BuildDependencyKind::PkgConfig,
        name: "zlib-1.2+debug".to_owned(),
    };
    request.dependencies = vec![module.clone(), command.clone(), command.clone()];
    assert_eq!(
        normalize(&request).unwrap().dependencies,
        vec![command, module]
    );
}

#[test]
fn profile_digest_is_stable_across_ordering_normalization_and_timestamps() {
    let (_project, mut request) = fixture();
    request
        .cmake_definitions
        .insert("BUILD_TESTING".to_owned(), "OFF".to_owned());
    request
        .cmake_definitions
        .insert("BUILD_SHARED_LIBS".to_owned(), "ON".to_owned());
    request.dependencies = vec![
        BuildDependency {
            kind: BuildDependencyKind::PkgConfig,
            name: "zlib".to_owned(),
        },
        BuildDependency {
            kind: BuildDependencyKind::Command,
            name: "make".to_owned(),
        },
    ];
    let first = normalize(&request).unwrap();
    request.dependencies.reverse();
    request.component_root = "./components/parser".to_owned();
    request.cmake_definitions = request.cmake_definitions.into_iter().rev().collect();
    let second = normalize(&request).unwrap();
    assert_eq!(first.profile_sha256, second.profile_sha256);
    request
        .cmake_definitions
        .insert("BUILD_TESTING".to_owned(), "ON".to_owned());
    assert_ne!(
        first.profile_sha256,
        normalize(&request).unwrap().profile_sha256
    );
}

#[test]
fn current_profile_checks_distinguish_marker_staleness_from_invalid_configuration() {
    let (project, request) = fixture();
    let profile = normalize(&request).unwrap();
    assert!(
        check_build_profile(&profile, &BuildProfileSettings::default())
            .unwrap()
            .is_empty()
    );
    std::fs::write(
        project.path().join(&profile.marker_path),
        "project(changed)\n",
    )
    .unwrap();
    assert!(
        !check_build_profile(&profile, &BuildProfileSettings::default())
            .unwrap()
            .is_empty()
    );
    std::fs::remove_file(project.path().join(&profile.marker_path)).unwrap();
    assert!(check_build_profile(&profile, &BuildProfileSettings::default()).is_err());
}

#[test]
fn current_profile_checks_enforce_current_option_allowance_and_digest_integrity() {
    let (_project, mut request) = fixture();
    request
        .cmake_definitions
        .insert("BUILD_TESTING".to_owned(), "ON".to_owned());
    let mut profile = normalize(&request).unwrap();
    let settings = BuildProfileSettings {
        allowed_cmake_options: std::collections::BTreeSet::new(),
    };
    assert!(check_build_profile(&profile, &settings).is_err());
    profile.profile_sha256 = "0".repeat(64);
    assert!(check_build_profile(&profile, &BuildProfileSettings::default()).is_err());
}

#[test]
fn required_profile_plan_and_dependency_evidence_must_fit_retained_limit() {
    let (_project, mut request) = fixture();
    request.dependencies = (0..600)
        .map(|index| BuildDependency {
            kind: BuildDependencyKind::PkgConfig,
            name: format!("module_{index:04}_{}", "x".repeat(50)),
        })
        .collect();
    assert!(normalize(&request).is_err());
}

#[test]
fn nested_cmake_and_make_plans_derive_output_from_selected_database() {
    let (project, mut request) = fixture();
    request
        .cmake_definitions
        .insert("BUILD_TESTING".to_owned(), "OFF".to_owned());
    let profile = normalize(&request).unwrap();
    let plan = profile_build_plan(&profile);
    assert_eq!(
        plan.steps[0].argv,
        [
            "cmake",
            "-S",
            ".",
            "-B",
            "../../build/parser",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DBUILD_TESTING=OFF"
        ]
    );
    assert_eq!(plan.steps[0].working_dir, "components/parser");
    std::fs::remove_file(project.path().join("components/parser/CMakeLists.txt")).unwrap();
    std::fs::write(project.path().join("components/parser/Makefile"), "all:\n").unwrap();
    request.build_system = ProfileBuildSystem::Make;
    request.cmake_definitions.clear();
    let plan = profile_build_plan(&normalize(&request).unwrap());
    assert_eq!(
        plan.steps[0].argv,
        ["mkdir", "-p", "--", "../../build/parser"]
    );
    assert_eq!(
        plan.steps[1].argv,
        [
            "bear",
            "--output",
            "../../build/parser/compile_commands.json",
            "--",
            "make",
            "-B"
        ]
    );
}

#[test]
fn output_paths_starting_with_hyphen_remain_file_arguments() {
    let (project, mut request) = fixture();
    request.component_root = ".".to_owned();
    std::fs::write(project.path().join("CMakeLists.txt"), "project(root)\n").unwrap();
    request.compile_database_path = "-build/compile_commands.json".to_owned();
    let plan = profile_build_plan(&normalize(&request).unwrap());
    assert_eq!(plan.steps[0].argv[4], "./-build");
    assert_eq!(
        normalize(&request).unwrap().compile_database_path,
        "-build/compile_commands.json"
    );
    std::fs::remove_file(project.path().join("CMakeLists.txt")).unwrap();
    std::fs::write(project.path().join("Makefile"), "all:\n").unwrap();
    request.build_system = ProfileBuildSystem::Make;
    let plan = profile_build_plan(&normalize(&request).unwrap());
    assert_eq!(plan.steps[0].argv[3], "./-build");
    assert_eq!(plan.steps[1].argv[2], "./-build/compile_commands.json");
}

#[test]
fn added_higher_priority_make_marker_changes_saved_identity() {
    let (project, mut request) = fixture();
    request.component_root = ".".to_owned();
    request.build_system = ProfileBuildSystem::Make;
    std::fs::write(project.path().join("Makefile"), "all:\n").unwrap();
    let profile = normalize(&request).unwrap();
    std::fs::write(project.path().join("GNUmakefile"), "all:\n").unwrap();
    assert!(
        !check_build_profile(&profile, &BuildProfileSettings::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn custom_allowance_accepts_explicit_options_without_inserting_other_values() {
    let (_project, mut request) = fixture();
    request
        .cmake_definitions
        .insert("WITH_ZLIB".to_owned(), "ON".to_owned());
    let settings = crate::config::parse_build_profile_settings(
        "[build_profiles]\nallowed_cmake_options = [\"WITH_ZLIB\"]",
    )
    .unwrap();
    let image =
        ImmutableImageReference::from_sha256_id(format!("sha256:{}", "a".repeat(64))).unwrap();
    let profile = normalize_profile(&request, &settings, &image, chrono::Utc::now()).unwrap();
    assert_eq!(profile.cmake_definitions.len(), 1);
    assert_eq!(profile.cmake_definitions["WITH_ZLIB"], "ON");
}

#[test]
fn every_consumed_assumption_participates_in_profile_identity() {
    let (_project, request) = fixture();
    let original = normalize(&request).unwrap();
    let mut variants = Vec::new();
    let mut changed = original.clone();
    changed.project_root.push_str("/other");
    variants.push(changed);
    let mut changed = original.clone();
    changed.component_root = ".".to_owned();
    variants.push(changed);
    let mut changed = original.clone();
    changed.build_system = ProfileBuildSystem::Make;
    variants.push(changed);
    let mut changed = original.clone();
    changed.compile_database_path = "compile_commands.json".to_owned();
    variants.push(changed);
    let mut changed = original.clone();
    changed
        .cmake_definitions
        .insert("BUILD_TESTING".to_owned(), "OFF".to_owned());
    variants.push(changed);
    let mut changed = original.clone();
    changed.dependencies.push(BuildDependency {
        kind: BuildDependencyKind::Command,
        name: "make".to_owned(),
    });
    variants.push(changed);
    let mut changed = original.clone();
    changed.sandbox_image_tag.push_str("-other");
    variants.push(changed);
    let mut changed = original.clone();
    changed.sandbox_image_id = format!("sha256:{}", "b".repeat(64));
    variants.push(changed);
    let mut changed = original.clone();
    changed.marker_path = "Makefile".to_owned();
    variants.push(changed);
    let mut changed = original.clone();
    changed.marker_sha256 = "b".repeat(64);
    variants.push(changed);
    for changed in variants {
        assert_ne!(profile_digest(&changed).unwrap(), original.profile_sha256);
    }
    let mut timestamps = original.clone();
    timestamps.created_at += chrono::Duration::days(1);
    timestamps.updated_at += chrono::Duration::days(2);
    assert_eq!(
        profile_digest(&timestamps).unwrap(),
        original.profile_sha256
    );
}

struct NoRuntime;
#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for NoRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        _cwd: &Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, ClassifiedError> {
        panic!("read-only profile check invoked runtime")
    }
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        panic!("read-only profile check resolved image")
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        panic!("read-only profile check wrote runtime file")
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        panic!("read-only profile check read runtime file")
    }
}

#[tokio::test]
async fn saved_profile_read_and_pure_checks_remain_available_without_optional_features() {
    let (project, request) = fixture();
    let profile = normalize(&request).unwrap();
    let store = std::sync::Arc::new(
        hf_storage::Store::connect(project.path().join("profile.db"))
            .await
            .unwrap(),
    );
    store.set_project_build_profile(&profile).await.unwrap();
    let service =
        crate::ServiceContainer::new(std::sync::Arc::new(NoRuntime), None).with_store(store);
    let loaded = service
        .build_profile(project.path())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded, profile);
    assert!(
        check_build_profile(&loaded, &BuildProfileSettings::default())
            .unwrap()
            .is_empty()
    );
    std::fs::write(project.path().join(&loaded.marker_path), "project(changed)").unwrap();
    assert!(
        !check_build_profile(&loaded, &BuildProfileSettings::default())
            .unwrap()
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn special_output_files_and_ancestors_are_rejected_without_opening_them() {
    use std::os::unix::net::UnixListener;
    let (project, mut request) = fixture();
    let socket_path = project.path().join("build");
    let socket = UnixListener::bind(&socket_path).unwrap();
    assert!(normalize(&request).is_err());
    drop(socket);
    std::fs::remove_file(socket_path).unwrap();
    request.compile_database_path = "compile_commands.json".to_owned();
    let _socket = UnixListener::bind(project.path().join("compile_commands.json")).unwrap();
    assert!(normalize(&request).is_err());
}

#[tokio::test]
async fn configured_resolution_without_optional_features_never_uses_legacy_or_runtime() {
    let (project, request) = fixture();
    let profile = normalize(&request).unwrap();
    let store = std::sync::Arc::new(
        hf_storage::Store::connect(project.path().join("profile.db"))
            .await
            .unwrap(),
    );
    store.set_project_build_profile(&profile).await.unwrap();
    let service = crate::ServiceContainer::new(std::sync::Arc::new(NoRuntime), None)
        .with_store(store.clone());
    let database = serde_json::json!([{"directory":profile.project_root,"file":"a.c","arguments":["cc","-DLEGACY=1","-c","a.c"]}]);
    std::fs::write(
        project.path().join("compile_commands.json"),
        database.to_string(),
    )
    .unwrap();
    assert!(service
        .resolve_build_context(project.path())
        .await
        .unwrap()
        .is_none());
    let path = project.path().join(&profile.compile_database_path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{broken").unwrap();
    assert!(service.resolve_build_context(project.path()).await.is_err());
    let database = serde_json::json!([{"directory":profile.project_root,"file":"a.c","arguments":["cc","-c","a.c"]}]);
    std::fs::write(path, database.to_string()).unwrap();
    let context = service
        .resolve_build_context(project.path())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.entry_count, 1);
    assert!(context.is_empty());
    store.pool().close().await;
    assert!(service.resolve_build_context(project.path()).await.is_err());
    let unavailable = crate::ServiceContainer::new(std::sync::Arc::new(NoRuntime), None)
        .with_unavailable_store_for_test();
    assert!(unavailable
        .resolve_build_context(project.path())
        .await
        .is_err());
}

struct AdmissionRuntime;
#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for AdmissionRuntime {
    async fn resolve_image_reference(
        &self,
        _: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        Ok(Some(ImmutableImageReference::from_sha256_id(format!(
            "sha256:{}",
            "a".repeat(64)
        ))?))
    }
    async fn run_command(
        &self,
        _: &[String],
        _: &Path,
        _: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, ClassifiedError> {
        panic!("configured admission failure dispatched runtime")
    }
    async fn write_file(&self, _: &Path, _: &str) -> Result<(), ClassifiedError> {
        panic!("configured admission failure staged runtime file")
    }
    async fn read_file(&self, _: &Path) -> Result<String, ClassifiedError> {
        panic!("configured admission failure read runtime file")
    }
}

#[tokio::test]
async fn configured_harness_admission_enforces_saved_profile_without_optional_features() {
    let (project, request) = fixture();
    let profile = normalize(&request).unwrap();
    let store = std::sync::Arc::new(
        hf_storage::Store::connect(project.path().join("state.db"))
            .await
            .unwrap(),
    );
    store.set_project_build_profile(&profile).await.unwrap();
    let service = crate::ServiceContainer::new(std::sync::Arc::new(AdmissionRuntime), None)
        .with_store(store.clone());
    let error = service
        .harness_generate(
            project.path(),
            "not_discovered",
            hf_core::engine::EngineKind::LibFuzzer,
            hf_core::target::TargetLanguage::C,
            0,
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("build_diagnosis_unavailable"),
        "{error}"
    );
    assert!(store.list_all_targets().await.unwrap().is_empty());
    std::fs::write(
        project.path().join(&profile.marker_path),
        "project(changed)\n",
    )
    .unwrap();
    let error = service
        .harness_compile(
            "source".into(),
            project.path(),
            hf_core::engine::EngineKind::LibFuzzer,
            "not_discovered",
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Stale"), "{error}");
    assert!(store.list_all_targets().await.unwrap().is_empty());
}
