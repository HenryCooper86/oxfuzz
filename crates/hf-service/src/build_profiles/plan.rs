//! Fixed profile plans and required dependency identities shared by save and diagnosis.
use std::collections::BTreeSet;

use hf_storage::{BuildPlanEvidence, BuildPlanStepEvidence};

use super::{BuildDependency, BuildDependencyKind, BuildProfileView, ProfileBuildSystem};

/// The image's command that writes a Bazel project's compile database.
const BAZEL_COMPILE_DATABASE_TOOL: &str = "oxfuzz-bazel-compdb";

/// Merge service-required tools and saved dependencies in canonical kind/name order.
pub(crate) fn required_build_dependencies(profile: &BuildProfileView) -> Vec<BuildDependency> {
    let mut dependencies: BTreeSet<_> = profile.dependencies.iter().cloned().collect();
    let commands = match profile.build_system {
        ProfileBuildSystem::CMake => &["cmake"][..],
        ProfileBuildSystem::Make => &["mkdir", "make", "bear"][..],
        ProfileBuildSystem::Meson => &["meson"][..],
        // `find` (the object cleanup) is a base-image essential and not listed:
        // a newly required tool would invalidate every earlier diagnosis.
        ProfileBuildSystem::Autotools => &["autoreconf", "make", "bear"][..],
        ProfileBuildSystem::Bazel => &["bazel", BAZEL_COMPILE_DATABASE_TOOL][..],
    };
    let needs_pkg_config = dependencies
        .iter()
        .any(|dependency| dependency.kind == BuildDependencyKind::PkgConfig);
    for name in commands
        .iter()
        .copied()
        .chain(needs_pkg_config.then_some("pkg-config"))
    {
        dependencies.insert(BuildDependency {
            kind: BuildDependencyKind::Command,
            name: name.to_owned(),
        });
    }
    dependencies.into_iter().collect()
}

/// Construct fixed argv from a normalized profile; callers check current assumptions
/// before execution and use the captured immutable image for every step.
pub(crate) fn profile_build_plan(profile: &BuildProfileView) -> BuildPlanEvidence {
    let output = relative_to_component(&profile.component_root, &profile.compile_database_path);
    let output_dir = output.rsplit_once('/').map_or(".", |(parent, _)| parent);
    let step = |argv, purpose: &str| BuildPlanStepEvidence {
        argv,
        working_dir: profile.component_root.clone(),
        purpose: purpose.to_owned(),
    };
    let steps = match profile.build_system {
        ProfileBuildSystem::CMake => {
            let mut argv = vec![
                "cmake".to_owned(),
                "-S".to_owned(),
                ".".to_owned(),
                "-B".to_owned(),
                output_dir.to_owned(),
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON".to_owned(),
            ];
            argv.extend(
                profile
                    .cmake_definitions
                    .iter()
                    .map(|(name, value)| format!("-D{name}={value}")),
            );
            // Configuring writes the database; building writes the headers a
            // project generates with custom commands (libpng's pnglibconf.h),
            // which every harness that includes the public header needs.
            vec![
                step(
                    argv,
                    "Configure the component so CMake writes the selected compile database",
                ),
                step(
                    vec![
                        "cmake".to_owned(),
                        "--build".to_owned(),
                        output_dir.to_owned(),
                        "--parallel".to_owned(),
                        crate::build_profiles::BUILD_STEP_CPUS.to_string(),
                    ],
                    "Build the component so the headers it generates while building exist",
                ),
            ]
        }
        ProfileBuildSystem::Make => vec![
            step(
                vec![
                    "mkdir".to_owned(),
                    "-p".to_owned(),
                    "--".to_owned(),
                    output_dir.to_owned(),
                ],
                "Create the selected compile database output directory",
            ),
            step(
                vec![
                    "bear".to_owned(),
                    "--output".to_owned(),
                    output,
                    "--".to_owned(),
                    "make".to_owned(),
                    "-B".to_owned(),
                ],
                "Record the forced Make build in the selected compile database",
            ),
        ],
        // Meson writes compile_commands.json during setup.
        ProfileBuildSystem::Meson => vec![
            step(
                vec![
                    "meson".to_owned(),
                    "setup".to_owned(),
                    output_dir.to_owned(),
                ],
                "Set up the Meson build directory so Meson writes the selected compile database",
            ),
            // As for CMake: `custom_target` headers exist only once built.
            step(
                vec![
                    "meson".to_owned(),
                    "compile".to_owned(),
                    "-C".to_owned(),
                    output_dir.to_owned(),
                    "-j".to_owned(),
                    crate::build_profiles::BUILD_STEP_CPUS.to_string(),
                ],
                "Build the component so the headers it generates while building exist",
            ),
        ],
        // In-tree configure keeps the plan independent of whether the
        // component ships a generated configure script: autoreconf produces
        // one from the autoconf sources when it is absent. `-f` also replaces
        // the auxiliary scripts a project shipped: an old config.guess (LibTIFF
        // 4.0.4 carries one from 2008) cannot guess aarch64, and configure
        // stops at "cannot guess build type". The plan runs in a staging copy,
        // so the project's own files are never rewritten.
        ProfileBuildSystem::Autotools => vec![
            step(
                vec!["autoreconf".to_owned(), "-f".to_owned(), "-i".to_owned()],
                "Generate or refresh the configure script from the autoconf sources",
            ),
            step(
                vec!["./configure".to_owned()],
                "Configure the component in-tree for the recorded Make build",
            ),
            // Not `make -B`: forcing every target also re-runs the rules that
            // regenerate Makefiles and config.status, each under Bear's
            // interception, which took LibTIFF 4.0.4 past the step time limit.
            // Deleting the objects an in-tree build left in the copy makes
            // every compile happen, and be recorded, without running the
            // project's own clean rules, which can be broken (libexif 0.6.14's
            // `make clean` needs a target that exists only with its docs).
            step(
                [
                    "find", ".", "-type", "f", "(", "-name", "*.o", "-o", "-name", "*.lo", "-o",
                    "-name", "*.obj", ")", "-delete",
                ]
                .map(str::to_owned)
                .to_vec(),
                "Remove objects a previous in-tree build left, so every compile is recorded",
            ),
            step(
                vec![
                    "bear".to_owned(),
                    "--output".to_owned(),
                    output,
                    "--".to_owned(),
                    "make".to_owned(),
                    format!("-j{}", crate::build_profiles::BUILD_STEP_CPUS),
                ],
                "Record the full Make build in the selected compile database",
            ),
        ],
        // The image's tool runs one offline `bazel aquery` against the
        // dependencies the project carries in its vendor directory and writes
        // the compile commands; no action executes, so no project build runs.
        ProfileBuildSystem::Bazel => vec![step(
            vec![BAZEL_COMPILE_DATABASE_TOOL.to_owned(), output],
            "Query the compile commands of every C and C++ target offline and write the selected compile database",
        )],
    };
    BuildPlanEvidence {
        steps,
        component_root: profile.component_root.clone(),
        expected_artifact: profile.compile_database_path.clone(),
        profile_sha256: profile.profile_sha256.clone(),
        sandbox_image_tag: profile.sandbox_image_tag.clone(),
        sandbox_image_id: profile.sandbox_image_id.clone(),
    }
}

fn relative_to_component(component: &str, path: &str) -> String {
    let component: Vec<_> = component.split('/').filter(|part| *part != ".").collect();
    let path: Vec<_> = path.split('/').collect();
    let shared = component
        .iter()
        .zip(&path)
        .take_while(|(a, b)| a == b)
        .count();
    let relative = std::iter::repeat_n("..", component.len() - shared)
        .chain(path[shared..].iter().copied())
        .collect::<Vec<_>>()
        .join("/");
    if relative.starts_with('-') {
        format!("./{relative}")
    } else {
        relative
    }
}
