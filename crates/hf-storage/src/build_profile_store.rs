//! Optional build configuration and immutable diagnosis and compile evidence.

mod context;
pub use context::{HarnessBuildContextEvidence, HarnessBuildContextRecord};

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use hf_core::harness::Harness;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::{sqlite::SqliteRow, Row, SqliteConnection};
use uuid::Uuid;

use crate::{HarnessApprovalKind, HarnessApprovalRecord, StorageError, Store};

/// Maximum UTF-8 bytes in each retained build JSON document.
pub const MAX_BUILD_JSON_BYTES: usize = 65_536;
/// Maximum number of diagnosis records requested in one page.
pub const MAX_BUILD_DIAGNOSIS_HISTORY: usize = 100;

/// Build systems accepted in a saved profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileBuildSystem {
    #[serde(rename = "cmake")]
    CMake,
    Make,
}

/// Dependency probe kinds, ordered for canonical serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildDependencyKind {
    Command,
    PkgConfig,
}

/// A normalized dependency identifier, without probe execution policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildDependency {
    pub kind: BuildDependencyKind,
    pub name: String,
}

/// Current project configuration, also used as the retained profile snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectBuildProfileRecord {
    pub project_root: String,
    pub component_root: String,
    pub build_system: ProfileBuildSystem,
    pub compile_database_path: String,
    pub cmake_definitions: BTreeMap<String, String>,
    pub dependencies: Vec<BuildDependency>,
    pub sandbox_image_tag: String,
    pub sandbox_image_id: String,
    pub marker_path: String,
    pub marker_sha256: String,
    pub profile_sha256: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Terminal outcome of a retained operation, separate from project readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildDiagnosisStatus {
    Succeeded,
    Failed,
    Cancelled,
}

/// Operation that produced diagnosis evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildDiagnosisOperation {
    Diagnose,
    Build,
}

/// Readiness determined by the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfileState {
    Unconfigured,
    NeedsBuild,
    Ready,
    Stale,
    Invalid,
}

/// A system recognized from project markers, including unsupported systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedBuildSystem {
    #[serde(rename = "cmake")]
    CMake,
    Meson,
    Autotools,
    Make,
    Bazel,
    Cargo,
    Unknown,
}

/// Retained service assessment of a detected system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedBuildStatus {
    Ready,
    Supported,
    UnsupportedInImage,
    NotNeeded,
    Unknown,
}

/// Marker evidence for one detected build system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSystemEvidence {
    pub build_system: DetectedBuildSystem,
    pub status: DetectedBuildStatus,
    pub markers: Vec<String>,
    #[serde(deserialize_with = "deserialize_optional")]
    pub missing_tool: Option<String>,
}

/// Result of probing one dependency in the captured image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildDependencyStatus {
    pub dependency: BuildDependency,
    pub available: bool,
}

/// Exact reviewed argument vector and project-relative working directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPlanStepEvidence {
    pub argv: Vec<String>,
    pub working_dir: String,
    pub purpose: String,
}

/// Reviewed plan metadata; execution and argv policy belong to the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPlanEvidence {
    pub steps: Vec<BuildPlanStepEvidence>,
    pub component_root: String,
    pub expected_artifact: String,
    pub profile_sha256: String,
    pub sandbox_image_tag: String,
    pub sandbox_image_id: String,
}

/// Why a diagnosis or build operation terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildTerminalStatus {
    Succeeded,
    StepFailed,
    TimedOut,
    Cancelled,
    ArtifactMissing,
    ArtifactInvalid,
    RuntimeFailed,
    Denied,
    ProfileChanged,
}

/// Bounded terminal output. Truncation is recorded before JSON serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildTerminalEvidence {
    pub status: BuildTerminalStatus,
    #[serde(deserialize_with = "deserialize_optional")]
    pub step_index: Option<usize>,
    #[serde(deserialize_with = "deserialize_optional")]
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
    #[serde(deserialize_with = "deserialize_optional")]
    pub failure_code: Option<String>,
    #[serde(deserialize_with = "deserialize_optional")]
    pub failure_message: Option<String>,
}

/// Version 1 retained evidence shared with service consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildDiagnosisEvidence {
    pub schema_version: u32,
    pub operation: BuildDiagnosisOperation,
    #[serde(deserialize_with = "deserialize_optional")]
    pub profile: Option<ProjectBuildProfileRecord>,
    pub detected: Vec<BuildSystemEvidence>,
    pub profile_state: BuildProfileState,
    pub dependency_statuses: Vec<BuildDependencyStatus>,
    pub reasons: Vec<String>,
    #[serde(deserialize_with = "deserialize_optional")]
    pub plan: Option<BuildPlanEvidence>,
    pub legacy_build_context_available: bool,
    #[serde(deserialize_with = "deserialize_optional")]
    pub terminal: Option<BuildTerminalEvidence>,
}

/// Immutable retained diagnosis or project-build operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildDiagnosisRecord {
    pub id: Uuid,
    pub project_root: String,
    #[serde(deserialize_with = "deserialize_optional")]
    pub profile_sha256: Option<String>,
    pub status: BuildDiagnosisStatus,
    pub diagnosis: BuildDiagnosisEvidence,
    pub created_at: DateTime<Utc>,
}

/// Inputs captured before compiling one exact harness revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessBuildInputsRecord {
    pub harness_id: Uuid,
    pub project_root: String,
    #[serde(deserialize_with = "deserialize_optional")]
    pub profile_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_optional")]
    pub compile_database_sha256: Option<String>,
    pub compile_flags_sha256: String,
    pub sandbox_image_id: String,
    pub build_input_sha256: String,
    pub created_at: DateTime<Utc>,
}

/// Current configuration and retained input identity expected by promotion.
/// `None` means absence, never an instruction to skip comparison.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedHarnessBuildIdentity<'a> {
    pub project_root: &'a str,
    pub profile_sha256: Option<&'a str>,
    pub build_input_sha256: Option<&'a str>,
}

impl Store {
    /// Save normalized configuration, preserving first-save time.
    /// Returns the persisted record; identical assumptions preserve both timestamps.
    pub async fn set_project_build_profile(
        &self,
        record: &ProjectBuildProfileRecord,
    ) -> Result<ProjectBuildProfileRecord, StorageError> {
        validate_profile(record)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let mut saved = record.clone();
        if let Some(existing) = load_profile(&mut tx, &record.project_root).await? {
            saved.created_at = existing.created_at;
            let mut comparison = saved.clone();
            comparison.updated_at = existing.updated_at;
            if comparison == existing {
                tx.commit().await?;
                return Ok(existing);
            }
        }
        validate_profile(&saved)?;
        sqlx::query(
            "INSERT INTO project_build_profiles
             (project_root, component_root, build_system, compile_database_path,
              cmake_definitions_json, dependencies_json, sandbox_image_tag, sandbox_image_id,
              marker_path, marker_sha256, profile_sha256, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(project_root) DO UPDATE SET
              component_root=excluded.component_root, build_system=excluded.build_system,
              compile_database_path=excluded.compile_database_path,
              cmake_definitions_json=excluded.cmake_definitions_json,
              dependencies_json=excluded.dependencies_json,
              sandbox_image_tag=excluded.sandbox_image_tag, sandbox_image_id=excluded.sandbox_image_id,
              marker_path=excluded.marker_path, marker_sha256=excluded.marker_sha256,
              profile_sha256=excluded.profile_sha256, updated_at=excluded.updated_at",
        )
        .bind(&saved.project_root)
        .bind(&saved.component_root)
        .bind(enum_text(&saved.build_system)?)
        .bind(&saved.compile_database_path)
        .bind(bounded_json(&saved.cmake_definitions)?)
        .bind(bounded_json(&saved.dependencies)?)
        .bind(&saved.sandbox_image_tag)
        .bind(&saved.sandbox_image_id)
        .bind(&saved.marker_path)
        .bind(&saved.marker_sha256)
        .bind(&saved.profile_sha256)
        .bind(timestamp(saved.created_at))
        .bind(timestamp(saved.updated_at))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(saved)
    }

    /// Load current configuration, rejecting malformed durable fields.
    pub async fn project_build_profile(
        &self,
        project_root: &str,
    ) -> Result<Option<ProjectBuildProfileRecord>, StorageError> {
        load_profile(&mut *self.pool().acquire().await?, project_root).await
    }

    /// Clear configuration without changing retained operation evidence.
    pub async fn clear_project_build_profile(
        &self,
        project_root: &str,
    ) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM project_build_profiles WHERE project_root = ?1")
            .bind(project_root)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Append immutable diagnosis evidence, accepting only an exact retry.
    pub async fn append_build_diagnosis(
        &self,
        record: &BuildDiagnosisRecord,
    ) -> Result<(), StorageError> {
        validate_diagnosis(record)?;
        let encoded = bounded_json(&record.diagnosis)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        if let Some(row) = sqlx::query("SELECT * FROM build_diagnosis_runs WHERE id = ?1")
            .bind(record.id.to_string())
            .fetch_optional(&mut *tx)
            .await?
        {
            if diagnosis_from_row(&row)? != *record {
                return Err(invalid(
                    "diagnosis identifier conflicts with retained evidence",
                ));
            }
        } else {
            sqlx::query("INSERT INTO build_diagnosis_runs (id, project_root, profile_sha256, status, diagnosis_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
                .bind(record.id.to_string()).bind(&record.project_root).bind(&record.profile_sha256)
                .bind(enum_text(&record.status)?).bind(encoded).bind(timestamp(record.created_at))
                .execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Read newest-first history, with UUID descending as the stable time tie-breaker.
    pub async fn build_diagnosis_history(
        &self,
        project_root: &str,
        limit: usize,
    ) -> Result<Vec<BuildDiagnosisRecord>, StorageError> {
        if !(1..=MAX_BUILD_DIAGNOSIS_HISTORY).contains(&limit) {
            return Err(invalid("diagnosis history limit must be in 1..=100"));
        }
        let limit =
            i64::try_from(limit).map_err(|_| invalid("diagnosis history limit exceeds i64"))?;
        let rows = sqlx::query("SELECT * FROM build_diagnosis_runs WHERE project_root = ?1 ORDER BY created_at DESC, id DESC LIMIT ?2")
            .bind(project_root).bind(limit).fetch_all(self.pool()).await?;
        rows.iter().map(diagnosis_from_row).collect()
    }

    /// Insert immutable inputs for an existing harness, accepting only exact retries.
    /// Successful compile publication must use `upsert_harness_with_build_inputs`.
    pub async fn set_harness_build_inputs(
        &self,
        record: &HarnessBuildInputsRecord,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        insert_inputs(&mut tx, record).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Load immutable compile inputs, rejecting malformed durable evidence.
    pub async fn harness_build_inputs(
        &self,
        harness_id: Uuid,
    ) -> Result<Option<HarnessBuildInputsRecord>, StorageError> {
        load_inputs(&mut *self.pool().acquire().await?, harness_id).await
    }

    /// Persist harness qualification state and captured inputs in one writer transaction.
    /// A concurrent profile save does not relabel or reject an earlier capture.
    pub async fn upsert_harness_with_build_inputs(
        &self,
        harness: &Harness,
        record: &HarnessBuildInputsRecord,
    ) -> Result<(), StorageError> {
        if harness.id != record.harness_id {
            return Err(invalid(
                "build inputs do not identify the requested harness",
            ));
        }
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        Self::upsert_harness_in_transaction(&mut tx, harness).await?;
        insert_inputs(&mut tx, record).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Promote and approve the exact harness while comparing current profile and input identity.
    /// The service must also check live filesystem and image assumptions before calling.
    pub async fn promote_harness_with_approval_and_build_identity(
        &self,
        harness: &Harness,
        approval_kind: HarnessApprovalKind,
        source_sha256: &str,
        binary_sha256: &str,
        approved_at: DateTime<Utc>,
        expected: &ExpectedHarnessBuildIdentity<'_>,
    ) -> Result<HarnessApprovalRecord, StorageError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        validate_project(expected.project_root)?;
        validate_optional_digest(expected.profile_sha256)?;
        validate_optional_digest(expected.build_input_sha256)?;
        validate_harness_project(&mut tx, harness.id, expected.project_root).await?;
        let profile = load_profile(&mut tx, expected.project_root).await?;
        let inputs = load_inputs(&mut tx, harness.id).await?;
        if profile.as_ref().map(|value| value.profile_sha256.as_str()) != expected.profile_sha256
            || inputs
                .as_ref()
                .map(|value| value.build_input_sha256.as_str())
                != expected.build_input_sha256
            || (expected.profile_sha256.is_some()
                && inputs
                    .as_ref()
                    .and_then(|value| value.profile_sha256.as_deref())
                    != expected.profile_sha256)
        {
            return Err(invalid("harness promotion build identity is stale"));
        }
        let approval = Self::promote_harness_in_transaction(
            &mut tx,
            harness,
            approval_kind,
            source_sha256,
            binary_sha256,
            approved_at,
        )
        .await?;
        tx.commit().await?;
        Ok(approval)
    }
}

async fn load_profile(
    connection: &mut SqliteConnection,
    project: &str,
) -> Result<Option<ProjectBuildProfileRecord>, StorageError> {
    sqlx::query("SELECT * FROM project_build_profiles WHERE project_root = ?1")
        .bind(project)
        .fetch_optional(connection)
        .await?
        .as_ref()
        .map(profile_from_row)
        .transpose()
}

fn profile_from_row(row: &SqliteRow) -> Result<ProjectBuildProfileRecord, StorageError> {
    let record = ProjectBuildProfileRecord {
        project_root: row.try_get("project_root")?,
        component_root: row.try_get("component_root")?,
        build_system: parse_enum(row.try_get("build_system")?)?,
        compile_database_path: row.try_get("compile_database_path")?,
        cmake_definitions: decode_canonical(row.try_get("cmake_definitions_json")?)?,
        dependencies: decode_canonical(row.try_get("dependencies_json")?)?,
        sandbox_image_tag: row.try_get("sandbox_image_tag")?,
        sandbox_image_id: row.try_get("sandbox_image_id")?,
        marker_path: row.try_get("marker_path")?,
        marker_sha256: row.try_get("marker_sha256")?,
        profile_sha256: row.try_get("profile_sha256")?,
        created_at: parse_timestamp(row.try_get("created_at")?)?,
        updated_at: parse_timestamp(row.try_get("updated_at")?)?,
    };
    validate_profile(&record)?;
    Ok(record)
}

fn diagnosis_from_row(row: &SqliteRow) -> Result<BuildDiagnosisRecord, StorageError> {
    let record = BuildDiagnosisRecord {
        id: parse_uuid(row.try_get("id")?)?,
        project_root: row.try_get("project_root")?,
        profile_sha256: row.try_get("profile_sha256")?,
        status: parse_enum(row.try_get("status")?)?,
        diagnosis: decode_json(row.try_get("diagnosis_json")?)?,
        created_at: parse_timestamp(row.try_get("created_at")?)?,
    };
    validate_diagnosis(&record)?;
    Ok(record)
}

pub(crate) async fn load_inputs(
    connection: &mut SqliteConnection,
    id: Uuid,
) -> Result<Option<HarnessBuildInputsRecord>, StorageError> {
    let row = sqlx::query("SELECT * FROM harness_build_inputs WHERE harness_id = ?1")
        .bind(id.to_string())
        .fetch_optional(&mut *connection)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let record = HarnessBuildInputsRecord {
        harness_id: parse_uuid(row.try_get("harness_id")?)?,
        project_root: row.try_get("project_root")?,
        profile_sha256: row.try_get("profile_sha256")?,
        compile_database_sha256: row.try_get("compile_database_sha256")?,
        compile_flags_sha256: row.try_get("compile_flags_sha256")?,
        sandbox_image_id: row.try_get("sandbox_image_id")?,
        build_input_sha256: row.try_get("build_input_sha256")?,
        created_at: parse_timestamp(row.try_get("created_at")?)?,
    };
    validate_inputs(&record)?;
    validate_harness_project(connection, id, &record.project_root).await?;
    Ok(Some(record))
}

async fn insert_inputs(
    connection: &mut SqliteConnection,
    record: &HarnessBuildInputsRecord,
) -> Result<(), StorageError> {
    validate_inputs(record)?;
    validate_harness_project(connection, record.harness_id, &record.project_root).await?;
    if let Some(existing) = load_inputs(connection, record.harness_id).await? {
        if existing != *record {
            return Err(invalid(
                "harness build inputs conflict with retained evidence",
            ));
        }
        return Ok(());
    }
    sqlx::query("INSERT INTO harness_build_inputs (harness_id, project_root, profile_sha256, compile_database_sha256, compile_flags_sha256, sandbox_image_id, build_input_sha256, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
        .bind(record.harness_id.to_string()).bind(&record.project_root).bind(&record.profile_sha256)
        .bind(&record.compile_database_sha256).bind(&record.compile_flags_sha256).bind(&record.sandbox_image_id)
        .bind(&record.build_input_sha256).bind(timestamp(record.created_at)).execute(connection).await?;
    Ok(())
}

async fn validate_harness_project(
    connection: &mut SqliteConnection,
    harness_id: Uuid,
    project: &str,
) -> Result<(), StorageError> {
    let owner: Option<String> = sqlx::query_scalar("SELECT t.project_root FROM harnesses h JOIN targets t ON t.id = h.target_id WHERE h.id = ?1")
        .bind(harness_id.to_string()).fetch_optional(connection).await?;
    if owner.as_deref() != Some(project) {
        return Err(invalid(
            "harness build inputs require a matching harness target and project",
        ));
    }
    Ok(())
}

fn validate_profile(record: &ProjectBuildProfileRecord) -> Result<(), StorageError> {
    validate_project(&record.project_root)?;
    validate_relative_path(&record.component_root, true)?;
    validate_database_path(&record.compile_database_path)?;
    validate_relative_path(&record.marker_path, false)?;
    validate_text(&record.sandbox_image_tag)?;
    validate_image(&record.sandbox_image_id)?;
    validate_digest(&record.marker_sha256)?;
    validate_digest(&record.profile_sha256)?;
    if record.updated_at < record.created_at {
        return Err(invalid("build profile update predates creation"));
    }
    if record.build_system == ProfileBuildSystem::Make && !record.cmake_definitions.is_empty() {
        return Err(invalid("Make profile has CMake definitions"));
    }
    for (name, value) in &record.cmake_definitions {
        if name.is_empty()
            || name.len() > 64
            || !name.as_bytes()[0].is_ascii_uppercase()
            || !name
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
        {
            return Err(invalid("invalid CMake definition name"));
        }
        if value.is_empty()
            || value.len() > 128
            || value.starts_with('-')
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_+.,:/-".contains(&c))
        {
            return Err(invalid("invalid CMake definition value"));
        }
    }
    for dependency in &record.dependencies {
        validate_dependency(dependency)?;
    }
    if record
        .dependencies
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("build dependencies must be sorted and unique"));
    }
    bounded_json(&record.cmake_definitions)?;
    bounded_json(&record.dependencies)?;
    Ok(())
}

fn validate_diagnosis(record: &BuildDiagnosisRecord) -> Result<(), StorageError> {
    validate_project(&record.project_root)?;
    validate_optional_digest(record.profile_sha256.as_deref())?;
    let evidence = &record.diagnosis;
    if evidence.operation == BuildDiagnosisOperation::Build && evidence.terminal.is_none() {
        return Err(invalid("build operation requires terminal evidence"));
    }
    if evidence.schema_version != 1 {
        return Err(invalid("unsupported build diagnosis schema version"));
    }
    if evidence.profile.as_ref().map(|p| p.profile_sha256.as_str())
        != record.profile_sha256.as_deref()
    {
        return Err(invalid(
            "diagnosis profile snapshot does not match captured identity",
        ));
    }
    if let Some(profile) = &evidence.profile {
        validate_profile(profile)?;
        if profile.project_root != record.project_root {
            return Err(invalid("diagnosis profile project conflicts"));
        }
    }
    for system in &evidence.detected {
        for marker in &system.markers {
            validate_relative_path(marker, false)?;
        }
        if let Some(tool) = &system.missing_tool {
            validate_dependency_name(tool)?;
        }
    }
    for status in &evidence.dependency_statuses {
        validate_dependency(&status.dependency)?;
    }
    if let Some(plan) = &evidence.plan {
        validate_plan(plan)?;
        let profile = evidence
            .profile
            .as_ref()
            .ok_or_else(|| invalid("reviewed plan requires a captured profile"))?;
        if plan.profile_sha256 != profile.profile_sha256
            || plan.component_root != profile.component_root
            || plan.expected_artifact != profile.compile_database_path
            || plan.sandbox_image_id != profile.sandbox_image_id
            || plan.sandbox_image_tag != profile.sandbox_image_tag
        {
            return Err(invalid("reviewed plan conflicts with captured profile"));
        }
    }
    if let Some(terminal) = &evidence.terminal {
        let status = match terminal.status {
            BuildTerminalStatus::Succeeded => BuildDiagnosisStatus::Succeeded,
            BuildTerminalStatus::Cancelled => BuildDiagnosisStatus::Cancelled,
            _ => BuildDiagnosisStatus::Failed,
        };
        if status != record.status {
            return Err(invalid(
                "diagnosis outcome conflicts with terminal evidence",
            ));
        }
        if let Some(index) = terminal.step_index {
            if evidence
                .plan
                .as_ref()
                .is_none_or(|plan| index >= plan.steps.len())
            {
                return Err(invalid("terminal step index is outside the retained plan"));
            }
        }
    }
    bounded_json(evidence)?;
    Ok(())
}

fn validate_plan(plan: &BuildPlanEvidence) -> Result<(), StorageError> {
    validate_relative_path(&plan.component_root, true)?;
    validate_database_path(&plan.expected_artifact)?;
    validate_digest(&plan.profile_sha256)?;
    validate_text(&plan.sandbox_image_tag)?;
    validate_image(&plan.sandbox_image_id)?;
    if plan.steps.is_empty() {
        return Err(invalid("reviewed plan contains no steps"));
    }
    for step in &plan.steps {
        validate_relative_path(&step.working_dir, true)?;
        if step.working_dir != plan.component_root {
            return Err(invalid(
                "plan step working directory conflicts with component",
            ));
        }
        if step.argv.is_empty() {
            return Err(invalid("reviewed plan step contains no argv"));
        }
        for argument in &step.argv {
            validate_text(argument)?;
        }
        validate_text(&step.purpose)?;
    }
    Ok(())
}

fn validate_inputs(record: &HarnessBuildInputsRecord) -> Result<(), StorageError> {
    validate_project(&record.project_root)?;
    validate_optional_digest(record.profile_sha256.as_deref())?;
    validate_optional_digest(record.compile_database_sha256.as_deref())?;
    validate_digest(&record.compile_flags_sha256)?;
    validate_image(&record.sandbox_image_id)?;
    validate_digest(&record.build_input_sha256)?;
    if record.profile_sha256.is_some() && record.compile_database_sha256.is_none() {
        return Err(invalid(
            "configured harness inputs require a compile database digest",
        ));
    }
    Ok(())
}

fn validate_dependency(dependency: &BuildDependency) -> Result<(), StorageError> {
    validate_dependency_name(&dependency.name)
}

fn validate_dependency_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c))
    {
        return Err(invalid("invalid build dependency identifier"));
    }
    Ok(())
}

pub(crate) fn validate_project(path: &str) -> Result<(), StorageError> {
    if path.chars().any(char::is_control) {
        return Err(invalid("project root contains control characters"));
    }
    if let Some(relative) = path.strip_prefix('/') {
        if relative.is_empty() || normalized_parts(relative.split('/')) {
            return Ok(());
        }
    } else {
        // Canonical Windows roots may have drive, UNC, or verbatim prefixes.
        // Parse their syntax independently of the host running the database reader.
        let verbatim = path.strip_prefix(r"\\?\");
        let windows = verbatim.unwrap_or(path);
        if windows.contains('/') || windows.get(2..).is_some_and(|suffix| suffix.contains(':')) {
            return Err(invalid(
                "Windows project root contains noncanonical separators",
            ));
        }
        let unc = if verbatim.is_some() {
            windows.strip_prefix(r"UNC\")
        } else {
            windows.strip_prefix(r"\\")
        };
        if let Some(unc) = unc {
            let parts: Vec<_> = unc.split('\\').collect();
            if parts.len() >= 2 && normalized_parts(parts.into_iter()) {
                return Ok(());
            }
        } else if windows
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && windows.as_bytes().get(1) == Some(&b':')
            && windows.as_bytes().get(2) == Some(&b'\\')
        {
            let relative = &windows[3..];
            if relative.is_empty() || normalized_parts(relative.split('\\')) {
                return Ok(());
            }
        }
    }
    Err(invalid("project root is not a normalized absolute path"))
}

fn normalized_parts<'a>(parts: impl Iterator<Item = &'a str>) -> bool {
    parts
        .into_iter()
        .all(|part| !matches!(part, "" | "." | ".."))
}

fn validate_relative_path(path: &str, root_allowed: bool) -> Result<(), StorageError> {
    if root_allowed && path == "." {
        return Ok(());
    }
    if path.is_empty()
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid("build path is not normalized and project-relative"));
    }
    Ok(())
}

fn validate_database_path(path: &str) -> Result<(), StorageError> {
    validate_relative_path(path, false)?;
    if path.rsplit('/').next() != Some("compile_commands.json") {
        return Err(invalid(
            "build database filename must be compile_commands.json",
        ));
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.contains('\0') {
        return Err(invalid("build metadata must be nonempty without NUL"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), StorageError> {
    if !crate::store::is_sha256(value) {
        return Err(invalid(
            "build digest must contain 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_optional_digest(value: Option<&str>) -> Result<(), StorageError> {
    value.map(validate_digest).transpose().map(|_| ())
}

fn validate_image(value: &str) -> Result<(), StorageError> {
    validate_digest(
        value
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("build image must be an immutable sha256 reference"))?,
    )
}

fn bounded_json<T: Serialize>(value: &T) -> Result<String, StorageError> {
    let encoded = serde_json::to_string(value)?;
    validate_json_size(&encoded)?;
    Ok(encoded)
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    validate_json_size(value)?;
    Ok(serde_json::from_str(value)?)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, StorageError> {
    let decoded = decode_json(value)?;
    if serde_json::to_string(&decoded)? != value {
        return Err(invalid("build configuration JSON is not canonical"));
    }
    Ok(decoded)
}

fn validate_json_size(value: &str) -> Result<(), StorageError> {
    if value.len() > MAX_BUILD_JSON_BYTES {
        return Err(invalid("build JSON exceeds 65536 UTF-8 bytes"));
    }
    Ok(())
}

fn enum_text<T: Serialize>(value: &T) -> Result<String, StorageError> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(invalid("build enum did not serialize to text")),
    }
}

fn parse_enum<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        value.to_owned(),
    ))?)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, StorageError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| StorageError::Timestamp(value.to_owned()))?;
    if timestamp(parsed) != value {
        return Err(invalid(
            "build timestamp is not canonical UTC with nanosecond precision",
        ));
    }
    Ok(parsed)
}

fn parse_uuid(value: &str) -> Result<Uuid, StorageError> {
    let parsed = Uuid::parse_str(value).map_err(|_| invalid("invalid build record UUID"))?;
    if parsed.to_string() != value {
        return Err(invalid(
            "build record UUID is not canonical lowercase hyphenated text",
        ));
    }
    Ok(parsed)
}

fn invalid(message: &str) -> StorageError {
    StorageError::InvalidData(message.to_owned())
}

fn deserialize_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Exact Phase 6 schema-1 compact JSON bytes used to identify compilation inputs.
pub fn harness_build_input_digest_bytes(
    profile_sha256: Option<&str>,
    compile_database_sha256: Option<&str>,
    compile_flags_sha256: &str,
    sandbox_image_id: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct InputDigest<'a> {
        schema_version: u32,
        profile_sha256: Option<&'a str>,
        compile_database_sha256: Option<&'a str>,
        compile_flags_sha256: &'a str,
        sandbox_image_id: &'a str,
    }
    serde_json::to_vec(&InputDigest {
        schema_version: 1,
        profile_sha256,
        compile_database_sha256,
        compile_flags_sha256,
        sandbox_image_id,
    })
}

/// SHA-256 identity of the unchanged Phase 6 schema-1 encoding.
pub fn harness_build_input_sha256(
    profile_sha256: Option<&str>,
    compile_database_sha256: Option<&str>,
    compile_flags_sha256: &str,
    sandbox_image_id: &str,
) -> Result<String, serde_json::Error> {
    use sha2::{Digest, Sha256};
    Ok(format!(
        "{:x}",
        Sha256::digest(harness_build_input_digest_bytes(
            profile_sha256,
            compile_database_sha256,
            compile_flags_sha256,
            sandbox_image_id
        )?)
    ))
}
