//! Marker detection and profile service behavior.

#![cfg(feature = "build-doctor")]

use hf_service::build_doctor::{detect_build_systems, BuildSystem, BuildSystemStatus};

fn project(files: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for name in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"# marker\n").unwrap();
    }
    dir
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
}

#[test]
fn malformed_or_empty_compile_database_is_not_reported_as_ready() {
    for contents in ["{not json", "[]"] {
        let dir = project(&["CMakeLists.txt"]);
        std::fs::write(dir.path().join("compile_commands.json"), contents).unwrap();

        let found = detect_build_systems(dir.path());

        assert_eq!(found[0].status, BuildSystemStatus::Supported);
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
}

mod profile_service {
    use super::project;
    use async_trait::async_trait;
    use hf_core::runtime::{
        CommandResult, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
    };
    use hf_service::build_profiles::{ProfileBuildSystem, SaveBuildProfileRequest};
    use hf_service::{ClassifiedError, ServiceContainer};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    struct ImageRuntime {
        identity: Option<&'static str>,
        fail: bool,
        images: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl RuntimeAdapter for ImageRuntime {
        async fn resolve_image_reference(
            &self,
            image: &str,
        ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
            self.images.lock().unwrap().push(image.to_owned());
            if self.fail {
                return Err(ClassifiedError::Sandbox("image unavailable".to_owned()));
            }
            self.identity
                .map(|digit| {
                    ImmutableImageReference::from_sha256_id(format!("sha256:{}", digit.repeat(64)))
                })
                .transpose()
        }
        async fn run_command(
            &self,
            _cmd: &[String],
            _cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            panic!("profile save executed project code")
        }
        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            panic!("profile save wrote a runtime file")
        }
        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            panic!("profile save read a runtime file")
        }
    }

    fn request(project: &Path) -> SaveBuildProfileRequest {
        SaveBuildProfileRequest {
            project: project.to_str().unwrap().to_owned(),
            component_root: ".".to_owned(),
            build_system: ProfileBuildSystem::CMake,
            compile_database_path: "build/compile_commands.json".to_owned(),
            cmake_definitions: BTreeMap::new(),
            dependencies: Vec::new(),
        }
    }

    #[tokio::test]
    async fn profile_save_read_clear_preserve_normalized_configuration_and_identical_timestamps() {
        let project = project(&["CMakeLists.txt"]);
        let runtime = Arc::new(ImageRuntime {
            identity: Some("a"),
            fail: false,
            images: Mutex::new(Vec::new()),
        });
        let store = Arc::new(
            hf_storage::Store::connect(project.path().join("store.db"))
                .await
                .unwrap(),
        );
        let service = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
        assert!(service
            .build_profile(project.path())
            .await
            .unwrap()
            .is_none());
        let saved = service
            .save_build_profile(request(project.path()))
            .await
            .unwrap();
        assert_eq!(saved.sandbox_image_tag, hf_runtime::SANDBOX_IMAGE);
        assert_eq!(saved.sandbox_image_id, format!("sha256:{}", "a".repeat(64)));
        assert!(saved.cmake_definitions.is_empty());
        let same = service
            .save_build_profile(request(project.path()))
            .await
            .unwrap();
        assert_eq!(same, saved);
        assert_eq!(
            service.build_profile(project.path()).await.unwrap(),
            Some(saved.clone())
        );
        let mut changed = request(project.path());
        changed
            .cmake_definitions
            .insert("BUILD_TESTING".to_owned(), "OFF".to_owned());
        let changed = service.save_build_profile(changed).await.unwrap();
        assert_ne!(saved.profile_sha256, changed.profile_sha256);
        assert_eq!(saved.created_at, changed.created_at);
        assert!(changed.updated_at >= saved.updated_at);
        assert_eq!(
            runtime.images.lock().unwrap().as_slice(),
            [
                hf_runtime::SANDBOX_IMAGE,
                hf_runtime::SANDBOX_IMAGE,
                hf_runtime::SANDBOX_IMAGE
            ]
        );
        service.clear_build_profile(project.path()).await.unwrap();
        assert!(store
            .project_build_profile(&saved.project_root)
            .await
            .unwrap()
            .is_none());
        assert!(!project.path().join("build").exists());
    }

    #[tokio::test]
    async fn save_refuses_unavailable_immutable_identity_and_resolution_errors() {
        for (identity, fail) in [(None, false), (Some("a"), true)] {
            let project = project(&["CMakeLists.txt"]);
            let runtime = Arc::new(ImageRuntime {
                identity,
                fail,
                images: Mutex::new(Vec::new()),
            });
            let store = Arc::new(
                hf_storage::Store::connect(project.path().join("store.db"))
                    .await
                    .unwrap(),
            );
            let service = ServiceContainer::new(runtime, None).with_store(store);
            assert!(service
                .save_build_profile(request(project.path()))
                .await
                .is_err());
            assert!(service
                .build_profile(project.path())
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn profile_operations_surface_unavailable_storage_and_database_failures() {
        let project = project(&["CMakeLists.txt"]);
        let runtime = Arc::new(ImageRuntime {
            identity: Some("a"),
            fail: false,
            images: Mutex::new(Vec::new()),
        });
        let unavailable = ServiceContainer::new(runtime.clone(), None);
        assert!(unavailable
            .save_build_profile(request(project.path()))
            .await
            .is_err());
        assert!(unavailable.build_profile(project.path()).await.is_err());
        assert!(unavailable
            .clear_build_profile(project.path())
            .await
            .is_err());
        let store = Arc::new(
            hf_storage::Store::connect(project.path().join("store.db"))
                .await
                .unwrap(),
        );
        let service = ServiceContainer::new(runtime, None).with_store(store.clone());
        store.pool().close().await;
        assert!(service
            .save_build_profile(request(project.path()))
            .await
            .is_err());
        assert!(service.build_profile(project.path()).await.is_err());
        assert!(service.clear_build_profile(project.path()).await.is_err());
    }
    #[tokio::test]
    async fn profile_reads_remain_visible_when_allowance_narrows() {
        if std::env::var_os("HF_PROFILE_POLICY_TEST").is_none() {
            let config = tempfile::tempdir().unwrap();
            std::fs::write(
                config.path().join("oxfuzz.toml"),
                "[build_profiles]\nallowed_cmake_options = [\"BUILD_TESTING\"]",
            )
            .unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "profile_service::profile_reads_remain_visible_when_allowance_narrows",
                ])
                .env("HF_PROFILE_POLICY_TEST", "1")
                .env("HF_CONFIG_DIR", config.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated policy test failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let config = std::path::PathBuf::from(std::env::var_os("HF_CONFIG_DIR").unwrap())
            .join("oxfuzz.toml");
        let project = project(&["CMakeLists.txt"]);
        let runtime = Arc::new(ImageRuntime {
            identity: Some("a"),
            fail: false,
            images: Mutex::new(Vec::new()),
        });
        let store = Arc::new(
            hf_storage::Store::connect(project.path().join("store.db"))
                .await
                .unwrap(),
        );
        let service = ServiceContainer::new(runtime.clone(), None).with_store(store);
        let mut requested = request(project.path());
        requested
            .cmake_definitions
            .insert("BUILD_TESTING".to_owned(), "OFF".to_owned());
        let saved = service.save_build_profile(requested.clone()).await.unwrap();
        std::fs::write(&config, "[build_profiles]\nallowed_cmake_options = []").unwrap();
        let loaded = service
            .build_profile(project.path())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, saved);
        let settings = hf_service::config::effective_build_profile_settings().unwrap();
        assert!(hf_service::build_profiles::check_build_profile(&loaded, &settings).is_err());
        let before_denial = runtime.images.lock().unwrap().len();
        assert!(service.save_build_profile(requested.clone()).await.is_err());
        assert_eq!(runtime.images.lock().unwrap().len(), before_denial);
        std::fs::write(
            &config,
            "[build_profiles]\nallowed_cmake_options = [\"INVALID NAME\"]",
        )
        .unwrap();
        let image_calls = runtime.images.lock().unwrap().len();
        assert!(service.build_profile(project.path()).await.is_err());
        assert!(service.save_build_profile(requested).await.is_err());
        assert_eq!(runtime.images.lock().unwrap().len(), image_calls);
        service.clear_build_profile(project.path()).await.unwrap();
    }
}

#[test]
fn a_marker_in_a_subdirectory_belongs_to_a_component_not_the_project() {
    let dir = project(&["parser.c", "third_party/zlib/CMakeLists.txt"]);
    assert_eq!(
        detect_build_systems(dir.path())[0].build_system,
        BuildSystem::Unknown
    );
}
#[test]
fn several_markers_report_several_systems_in_specificity_order() {
    let dir = project(&["CMakeLists.txt", "Makefile"]);
    let found = detect_build_systems(dir.path());
    assert_eq!(found[0].build_system, BuildSystem::CMake);
    assert_eq!(found[1].build_system, BuildSystem::Make);
}
#[test]
fn cmake_and_plain_make_are_supported_systems() {
    for marker in ["CMakeLists.txt", "Makefile"] {
        let dir = project(&[marker]);
        assert_eq!(
            detect_build_systems(dir.path())[0].status,
            BuildSystemStatus::Supported
        );
    }
}
#[test]
fn unsupported_systems_do_not_claim_a_tool_is_missing_without_a_probe() {
    for marker in ["configure.ac", "meson.build", "WORKSPACE"] {
        let dir = project(&[marker]);
        let found = detect_build_systems(dir.path());
        assert_eq!(found[0].status, BuildSystemStatus::UnsupportedInImage);
        assert!(found[0].missing_tool.is_none());
    }
}
#[test]
fn a_rust_project_needs_no_compile_database() {
    let dir = project(&["Cargo.toml"]);
    assert_eq!(
        detect_build_systems(dir.path())[0].status,
        BuildSystemStatus::NotNeeded
    );
}
#[test]
fn a_project_that_already_ships_a_database_is_ready() {
    let dir = project(&["CMakeLists.txt"]);
    let db = serde_json::json!([{"directory": dir.path(), "file":"a.c", "arguments":["cc", "-DREADY=1", "-c", "a.c"]}]);
    std::fs::write(dir.path().join("compile_commands.json"), db.to_string()).unwrap();
    assert_eq!(
        detect_build_systems(dir.path())[0].status,
        BuildSystemStatus::Ready
    );
}

#[tokio::test]
async fn requested_build_history_limits_are_validation_errors_before_storage_access() {
    let dir = tempfile::tempdir().unwrap();
    let service = hf_service::ServiceContainer::stubbed();
    for limit in [0, 101] {
        assert!(matches!(
            service.build_diagnosis_history(dir.path(), limit).await,
            Err(hf_service::ClassifiedError::Validation(_))
        ));
    }
}
