//! Serialized metadata accounting shared by profile save and retained diagnosis.
use hf_core::error::ClassifiedError;
use hf_storage::{
    BuildDependencyStatus, BuildDiagnosisEvidence, BuildDiagnosisOperation, BuildProfileState,
    BuildSystemEvidence, DetectedBuildStatus, MAX_BUILD_JSON_BYTES,
};

use super::{
    component_path, invalid, profile_build_plan, required_build_dependencies, BuildProfileView,
    BUILD_SYSTEM_MARKERS,
};

/// Encoded capacity reserved for reasons, terminal metadata, stdout and stderr.
/// The operation must bound these fields together after JSON escaping; this is
/// not a raw-text output limit. Actual encoding is checked before persistence.
pub(crate) const BUILD_DIAGNOSIS_DETAIL_RESERVE_BYTES: usize = 16 * 1024;

/// Remaining encoded bytes in the exact envelope supplied by the operation.
/// Call before appending bounded output/reasons and recheck the final envelope.
pub(crate) fn build_diagnosis_remaining_bytes(
    evidence: &BuildDiagnosisEvidence,
) -> Result<usize, ClassifiedError> {
    let bytes = serde_json::to_vec(evidence).map_err(|error| {
        ClassifiedError::Internal(format!("encode build diagnosis metadata: {error}"))
    })?;
    MAX_BUILD_JSON_BYTES
        .checked_sub(bytes.len())
        .ok_or_else(|| invalid("build diagnosis metadata exceeds 65536 UTF-8 bytes"))
}

pub(crate) fn validate_profile_evidence_capacity(
    profile: &BuildProfileView,
) -> Result<(), ClassifiedError> {
    if build_diagnosis_remaining_bytes(&profile_metadata(profile))?
        < BUILD_DIAGNOSIS_DETAIL_RESERVE_BYTES
    {
        return Err(invalid("build profile leaves insufficient retained diagnosis capacity for reasons and terminal output"));
    }
    Ok(())
}

fn profile_metadata(profile: &BuildProfileView) -> BuildDiagnosisEvidence {
    // Reserve every recognized marker so a later diagnosis can report all
    // systems without losing profile/plan metadata accepted by this save.
    BuildDiagnosisEvidence {
        schema_version: 1,
        operation: BuildDiagnosisOperation::Diagnose,
        profile: Some(profile.clone()),
        detected: BUILD_SYSTEM_MARKERS
            .into_iter()
            .map(|(build_system, markers)| BuildSystemEvidence {
                build_system,
                status: DetectedBuildStatus::UnsupportedInImage,
                markers: markers
                    .iter()
                    .map(|marker| component_path(&profile.component_root, marker))
                    .collect(),
                missing_tool: Some("pkg-config".to_owned()),
            })
            .collect(),
        profile_state: BuildProfileState::Unconfigured,
        dependency_statuses: required_build_dependencies(profile)
            .into_iter()
            .map(|dependency| BuildDependencyStatus {
                dependency,
                available: false,
            })
            .collect(),
        reasons: Vec::new(),
        plan: Some(profile_build_plan(profile)),
        legacy_build_context_available: false,
        terminal: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> BuildProfileView {
        BuildProfileView {
            project_root: "/project".to_owned(),
            component_root: ".".to_owned(),
            build_system: hf_storage::ProfileBuildSystem::CMake,
            compile_database_path: "build/compile_commands.json".to_owned(),
            cmake_definitions: std::collections::BTreeMap::new(),
            dependencies: Vec::new(),
            sandbox_image_tag: hf_runtime::SANDBOX_IMAGE.to_owned(),
            sandbox_image_id: format!("sha256:{}", "a".repeat(64)),
            marker_path: "CMakeLists.txt".to_owned(),
            marker_sha256: "b".repeat(64),
            profile_sha256: "c".repeat(64),
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            updated_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    #[test]
    fn profile_capacity_reserves_encoded_details_at_exact_limit() {
        let mut profile = profile();
        let metadata = profile_metadata(&profile);
        let remaining = build_diagnosis_remaining_bytes(&metadata).unwrap();
        profile
            .project_root
            .push_str(&"x".repeat(remaining - BUILD_DIAGNOSIS_DETAIL_RESERVE_BYTES));
        assert!(validate_profile_evidence_capacity(&profile).is_ok());
        profile.project_root.push('x');
        assert!(validate_profile_evidence_capacity(&profile).is_err());
    }

    #[test]
    fn envelope_accounting_uses_json_escaping_and_rejects_overflow() {
        let mut evidence = profile_metadata(&profile());
        let before = build_diagnosis_remaining_bytes(&evidence).unwrap();
        evidence.reasons.push("\n".repeat((before - 2) / 2));
        let remaining = build_diagnosis_remaining_bytes(&evidence).unwrap();
        assert!(remaining <= 1);
        evidence.reasons[0].push('\n');
        assert!(build_diagnosis_remaining_bytes(&evidence).is_err());
    }

    #[test]
    fn retained_metadata_includes_required_and_saved_probe_records_once() {
        let mut profile = profile();
        profile.dependencies.push(hf_storage::BuildDependency {
            kind: hf_storage::BuildDependencyKind::Command,
            name: "cmake".to_owned(),
        });
        profile.dependencies.push(hf_storage::BuildDependency {
            kind: hf_storage::BuildDependencyKind::PkgConfig,
            name: "zlib".to_owned(),
        });
        let metadata = profile_metadata(&profile);
        assert_eq!(
            metadata
                .dependency_statuses
                .iter()
                .map(|status| status.dependency.name.as_str())
                .collect::<Vec<_>>(),
            ["cmake", "pkg-config", "zlib"]
        );
    }
}
