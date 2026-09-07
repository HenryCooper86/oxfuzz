//! Fixed profile plans and required dependency identities shared by save and diagnosis.
use std::collections::BTreeSet;

use hf_storage::{BuildPlanEvidence, BuildPlanStepEvidence};

use super::{BuildDependency, BuildDependencyKind, BuildProfileView, ProfileBuildSystem};

/// Merge service-required tools and saved dependencies in canonical kind/name order.
pub(crate) fn required_build_dependencies(profile: &BuildProfileView) -> Vec<BuildDependency> {
    let mut dependencies: BTreeSet<_> = profile.dependencies.iter().cloned().collect();
    let commands = match profile.build_system {
        ProfileBuildSystem::CMake => &["cmake"][..],
        ProfileBuildSystem::Make => &["mkdir", "make", "bear"][..],
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
            vec![step(
                argv,
                "Configure the component so CMake writes the selected compile database",
            )]
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
