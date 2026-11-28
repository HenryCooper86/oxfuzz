//! Operator input and output for the service-owned project build workflow.

#[cfg(feature = "build-doctor")]
use crate::args::ProfileSystemArg;
use crate::args::{BuildCommand, BuildProfileCommand};
use hf_service::ServiceContainer;
#[cfg(feature = "build-doctor")]
use hf_service::{BuildDependency, BuildDependencyKind, ProfileBuildSystem};
use serde_json::Value;

pub(crate) async fn run(command: BuildCommand) -> anyhow::Result<()> {
    let service = crate::approval::bootstrap().await;
    let (view, json) = execute(&service, command).await?;
    println!(
        "{}",
        if json {
            serde_json::to_string_pretty(&view)?
        } else {
            human_output(&view)
        }
    );
    Ok(())
}

async fn execute(
    service: &ServiceContainer,
    command: BuildCommand,
) -> anyhow::Result<(Value, bool)> {
    if let BuildCommand::Profile {
        command: BuildProfileCommand::Show { project, json },
    } = command
    {
        return Ok((
            serde_json::to_value(service.build_profile(&project).await?)?,
            json,
        ));
    }
    #[cfg(feature = "build-doctor")]
    {
        execute_operation(service, command).await
    }
    #[cfg(not(feature = "build-doctor"))]
    {
        anyhow::bail!("build diagnosis, history, profile mutation and execution are not included in this application build")
    }
}

#[cfg(feature = "build-doctor")]
async fn execute_operation(
    service: &ServiceContainer,
    command: BuildCommand,
) -> anyhow::Result<(Value, bool)> {
    match command {
        BuildCommand::Diagnose { project, json } => Ok((
            serde_json::to_value(service.diagnose_build(&project).await?)?,
            json,
        )),
        BuildCommand::History {
            project,
            limit,
            json,
        } => Ok((
            serde_json::to_value(service.build_diagnosis_history(&project, limit).await?)?,
            json,
        )),
        BuildCommand::Run {
            project,
            expected_profile_sha256,
            json,
        } => Ok((
            serde_json::to_value(
                service
                    .run_build_plan(hf_service::RunBuildPlanRequest {
                        project: project.to_string_lossy().into_owned(),
                        expected_profile_sha256,
                    })
                    .await?,
            )?,
            json,
        )),
        BuildCommand::Profile { command } => match command {
            BuildProfileCommand::Show { project, json } => Ok((
                serde_json::to_value(service.build_profile(&project).await?)?,
                json,
            )),
            BuildProfileCommand::Clear { project, json } => {
                service.clear_build_profile(&project).await?;
                Ok((Value::Null, json))
            }
            BuildProfileCommand::Set {
                project,
                component_root,
                build_system,
                compile_database_path,
                definitions,
                dependencies,
                json,
            } => {
                let mut cmake_definitions = std::collections::BTreeMap::new();
                for definition in definitions {
                    let (name, value) = definition
                        .split_once('=')
                        .ok_or_else(|| anyhow::anyhow!("definition must be NAME=VALUE"))?;
                    anyhow::ensure!(
                        cmake_definitions
                            .insert(name.to_owned(), value.to_owned())
                            .is_none(),
                        "duplicate definition: {name}"
                    );
                }
                let dependencies = dependencies
                    .into_iter()
                    .map(|value| {
                        let (kind, name) = value.split_once(':').ok_or_else(|| {
                            anyhow::anyhow!("dependency must be command:NAME or pkg_config:MODULE")
                        })?;
                        let kind = match kind {
                            "command" => BuildDependencyKind::Command,
                            "pkg_config" => BuildDependencyKind::PkgConfig,
                            _ => anyhow::bail!("unknown dependency kind: {kind}"),
                        };
                        Ok(BuildDependency {
                            kind,
                            name: name.to_owned(),
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let profile = service
                    .save_build_profile(hf_service::SaveBuildProfileRequest {
                        project: project.to_string_lossy().into_owned(),
                        component_root,
                        build_system: match build_system {
                            ProfileSystemArg::Cmake => ProfileBuildSystem::CMake,
                            ProfileSystemArg::Make => ProfileBuildSystem::Make,
                            ProfileSystemArg::Meson => ProfileBuildSystem::Meson,
                            ProfileSystemArg::Autotools => ProfileBuildSystem::Autotools,
                            ProfileSystemArg::Bazel => ProfileBuildSystem::Bazel,
                        },
                        compile_database_path,
                        cmake_definitions,
                        dependencies,
                    })
                    .await?;
                Ok((serde_json::to_value(profile)?, json))
            }
        },
    }
}

fn human_output(view: &Value) -> String {
    match view {
        Value::Null => "No saved build profile (Unconfigured).".to_owned(),
        Value::Array(records) => records
            .iter()
            .map(human_output)
            .collect::<Vec<_>>()
            .join("\n\n"),
        Value::Object(fields) => fields
            .iter()
            .map(|(name, value)| {
                let label = match name.as_str() {
                    "component_root" => "Component",
                    "compile_database_path" | "expected_artifact" => "Compile database",
                    "profile_state" => "Profile state",
                    "dependency_statuses" | "dependencies" => "Dependencies",
                    "reasons" => "Reasons",
                    "argv" => "Exact argv",
                    "sandbox_image_id" => "Immutable image",
                    "profile_sha256" => "Profile SHA-256",
                    _ => name,
                };
                if matches!(name.as_str(), "profile" | "plan" | "diagnosis" | "steps") {
                    format!("{label}:\n{}", human_output(value))
                } else if name == "terminal" && value.is_object() {
                    terminal_output(value)
                } else {
                    format!("{label}: {value}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        value => value.to_string(),
    }
}

/// Lines of build output shown per stream; the retained record keeps more
/// (`oxfuzz build history --json`).
const TERMINAL_TAIL_LINES: usize = 25;

/// A build step's terminal record as an operator reads it: the outcome, then
/// the last lines of each output stream as text, not one escaped JSON string.
fn terminal_output(terminal: &Value) -> String {
    let field = |key: &str| terminal.get(key).filter(|value| !value.is_null());
    let mut lines = vec!["Last step:".to_owned()];
    for (key, label) in [
        ("status", "status"),
        ("step_index", "step"),
        ("exit_code", "exit code"),
        ("failure_code", "failure"),
        ("failure_message", "reason"),
    ] {
        if let Some(value) = field(key) {
            let text = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            lines.push(format!("  {label}: {text}"));
        }
    }
    for stream in ["stderr", "stdout"] {
        let Some(text) = field(stream).and_then(Value::as_str) else {
            continue;
        };
        let tail: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        if tail.is_empty() {
            continue;
        }
        let start = tail.len().saturating_sub(TERMINAL_TAIL_LINES);
        lines.push(format!("  {stream} (last {} lines):", tail.len() - start));
        lines.extend(tail[start..].iter().map(|line| format!("    {line}")));
    }
    if field("output_truncated").and_then(Value::as_bool) == Some(true) {
        lines.push(
            "  (output was truncated; `oxfuzz build history --json` keeps the record)".to_owned(),
        );
    }
    lines.join("\n")
}

#[cfg(all(test, feature = "build-doctor"))]
mod tests {
    use super::*;
    use crate::args::{Cli, Commands};
    use clap::Parser;

    #[tokio::test]
    async fn build_commands_render_service_diagnosis_and_preserve_history_after_clear() {
        let dir = tempfile::tempdir().unwrap();
        let service = ServiceContainer::stubbed()
            .with_store_path(dir.path().join("store.db"))
            .await
            .unwrap();
        let project = dir.path().to_str().unwrap();
        for tail in [
            vec!["diagnose", project, "--json"],
            vec!["history", project, "--limit", "10", "--json"],
            vec!["profile", "show", project, "--json"],
            vec!["profile", "clear", project, "--json"],
        ] {
            let args = [vec!["oxfuzz", "build"], tail].concat();
            let Commands::Build(crate::args::BuildArgs { command }) =
                Cli::try_parse_from(args).unwrap().command
            else {
                panic!("wrong command")
            };
            let (value, json) = execute(&service, command).await.unwrap();
            assert!(json);
            if value.is_object() {
                assert_eq!(value["profile_state"], "unconfigured");
                assert!(human_output(&value).contains("Profile state: \"unconfigured\""));
            }
        }
        assert_eq!(
            service
                .build_diagnosis_history(dir.path(), 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    struct ImageOnly;
    #[async_trait::async_trait]
    impl hf_service::RuntimeAdapter for ImageOnly {
        async fn resolve_image_reference(
            &self,
            _: &str,
        ) -> Result<Option<hf_service::ImmutableImageReference>, hf_service::ClassifiedError>
        {
            Ok(Some(hf_service::ImmutableImageReference::from_sha256_id(
                format!("sha256:{}", "a".repeat(64)),
            )?))
        }
        async fn run_command(
            &self,
            _: &[String],
            _: &std::path::Path,
            _: &hf_service::ResourceLimits,
        ) -> Result<hf_service::CommandResult, hf_service::ClassifiedError> {
            panic!("CLI test must not execute a build")
        }
        async fn write_file(
            &self,
            _: &std::path::Path,
            _: &str,
        ) -> Result<(), hf_service::ClassifiedError> {
            panic!("no runtime write")
        }
        async fn read_file(
            &self,
            _: &std::path::Path,
        ) -> Result<String, hf_service::ClassifiedError> {
            panic!("no runtime read")
        }
    }

    #[tokio::test]
    async fn build_profile_set_forwards_definitions_dependencies_and_run_digest_to_service() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("CMakeLists.txt"), "project(p)\n").unwrap();
        let service = ServiceContainer::new(std::sync::Arc::new(ImageOnly), None)
            .with_store_path(directory.path().join("store.db"))
            .await
            .unwrap();
        let project = directory.path().to_str().unwrap();
        let args = [
            "oxfuzz",
            "build",
            "profile",
            "set",
            project,
            "--component-root",
            ".",
            "--build-system",
            "cmake",
            "--compile-database-path",
            "out/compile_commands.json",
            "--define",
            "BUILD_TESTING=OFF",
            "--define",
            "BUILD_SHARED_LIBS=ON",
            "--dependency",
            "pkg_config:zlib",
            "--dependency",
            "command:clang",
            "--json",
        ];
        let Commands::Build(crate::args::BuildArgs { command }) =
            Cli::try_parse_from(args).unwrap().command
        else {
            panic!("wrong command")
        };
        let (saved, json) = execute(&service, command).await.unwrap();
        assert!(json);
        assert_eq!(saved["compile_database_path"], "out/compile_commands.json");
        assert_eq!(
            saved["cmake_definitions"],
            serde_json::json!({"BUILD_SHARED_LIBS":"ON", "BUILD_TESTING":"OFF"})
        );
        assert_eq!(
            saved["dependencies"],
            serde_json::json!([{"kind":"command","name":"clang"},{"kind":"pkg_config","name":"zlib"}])
        );
        let Commands::Build(crate::args::BuildArgs { command }) = Cli::try_parse_from([
            "oxfuzz",
            "build",
            "run",
            project,
            "--expected-profile-sha256",
            &"b".repeat(64),
        ])
        .unwrap()
        .command
        else {
            panic!("wrong command")
        };
        assert!(execute(&service, command)
            .await
            .unwrap_err()
            .to_string()
            .contains("digest does not match"));
        assert_eq!(
            serde_json::to_value(service.build_profile(directory.path()).await.unwrap()).unwrap(),
            saved
        );
    }

    #[test]
    fn a_failed_step_reads_as_text_with_the_last_output_lines() {
        let stderr = (1..=40)
            .map(|n| format!("configure.ac:{n}: warning: obsolete macro"))
            .chain(["configure: error: cannot guess build type; you must specify one".to_owned()])
            .collect::<Vec<_>>()
            .join("\n");
        let value = serde_json::json!({"status": "step_failed", "terminal": {
            "status": "failed", "exit_code": 1, "step_index": 1,
            "failure_code": null, "stderr": stderr, "stdout": "", "output_truncated": true}});

        let rendered = human_output(&value);

        assert!(rendered.contains("  exit code: 1"), "{rendered}");
        assert!(rendered.contains("  step: 1"), "{rendered}");
        assert!(
            rendered
                .contains("    configure: error: cannot guess build type; you must specify one"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("configure.ac:1: warning"),
            "older lines are cut: {rendered}"
        );
        assert!(!rendered.contains("\\n"), "no escaped JSON: {rendered}");
        assert!(rendered.contains("build history --json"), "{rendered}");
    }

    #[test]
    fn human_output_retains_plan_tokens_and_named_prerequisites() {
        let value = serde_json::json!({"profile": {"component_root":"parser","compile_database_path":"out/compile_commands.json"}, "dependency_statuses":[{"dependency":{"kind":"pkg_config","name":"zlib"},"available":false}], "reasons":["marker changed"], "plan":{"sandbox_image_id":"sha256:abc","steps":[{"argv":["cmake","-S","path with spaces"],"working_dir":"parser"}]}});
        let rendered = human_output(&value);
        for expected in [
            "Component: \"parser\"",
            "Compile database: \"out/compile_commands.json\"",
            "zlib",
            "marker changed",
            "Exact argv: [\"cmake\",\"-S\",\"path with spaces\"]",
            "Immutable image: \"sha256:abc\"",
        ] {
            assert!(rendered.contains(expected), "{rendered}");
        }
    }
}

#[cfg(all(test, not(feature = "build-doctor")))]
mod disabled_tests {
    use super::*;
    #[tokio::test]
    async fn build_profile_read_works_and_mutation_reports_feature_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let service = ServiceContainer::stubbed()
            .with_store_path(directory.path().join("store.db"))
            .await
            .unwrap();
        let (value, json) = execute(
            &service,
            BuildCommand::Profile {
                command: BuildProfileCommand::Show {
                    project: directory.path().to_owned(),
                    json: true,
                },
            },
        )
        .await
        .unwrap();
        assert!(value.is_null());
        assert!(json);
        let error = execute(
            &service,
            BuildCommand::Profile {
                command: BuildProfileCommand::Clear {
                    project: directory.path().to_owned(),
                    json: false,
                },
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("not included"));
    }
}
