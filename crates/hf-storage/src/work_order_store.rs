//! Durable Harness Work Order records.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::StorageError;

/// Maximum immutable submissions retained for one work order.
pub const MAX_WORK_ORDER_SUBMISSIONS: u32 = 20;
/// Maximum attempts that may be ranked in one request.
pub const MAX_WORK_ORDER_RANK_ATTEMPTS: usize = 5;

/// The service-owned qualification phase recorded for an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkOrderAttemptStage {
    Compile,
    Review,
    Smoke,
    Complete,
}

impl HarnessWorkOrderAttemptStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Review => "review",
            Self::Smoke => "smoke",
            Self::Complete => "complete",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "compile" => Ok(Self::Compile),
            "review" => Ok(Self::Review),
            "smoke" => Ok(Self::Smoke),
            "complete" => Ok(Self::Complete),
            _ => Err(StorageError::InvalidData(format!(
                "invalid harness work order attempt stage '{value}'"
            ))),
        }
    }
}

impl fmt::Display for HarnessWorkOrderAttemptStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HarnessWorkOrderAttemptStage {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// The durable outcome recorded for a qualification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkOrderAttemptStatus {
    Running,
    CompileFailed,
    ReviewFailed,
    SmokeFailed,
    SmokePassed,
    Interrupted,
}

impl HarnessWorkOrderAttemptStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::CompileFailed => "compile_failed",
            Self::ReviewFailed => "review_failed",
            Self::SmokeFailed => "smoke_failed",
            Self::SmokePassed => "smoke_passed",
            Self::Interrupted => "interrupted",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "running" => Ok(Self::Running),
            "compile_failed" => Ok(Self::CompileFailed),
            "review_failed" => Ok(Self::ReviewFailed),
            "smoke_failed" => Ok(Self::SmokeFailed),
            "smoke_passed" => Ok(Self::SmokePassed),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(StorageError::InvalidData(format!(
                "invalid harness work order attempt status '{value}'"
            ))),
        }
    }
}

impl fmt::Display for HarnessWorkOrderAttemptStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HarnessWorkOrderAttemptStatus {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// One immutable, canonical work-order packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderRecord {
    pub id: String,
    pub target_id: Uuid,
    pub project_root: String,
    pub schema_version: u32,
    pub packet_json: String,
    pub created_at: DateTime<Utc>,
}

/// One immutable source submission for a work order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderSubmissionRecord {
    pub id: Uuid,
    pub work_order_id: String,
    pub source: String,
    pub source_sha256: String,
    pub origin_json: String,
    pub parent_submission_id: Option<Uuid>,
    pub lint_json: String,
    pub submitted_at: DateTime<Utc>,
}

/// One durable qualification attempt for an immutable submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderAttemptRecord {
    pub id: Uuid,
    pub submission_id: Uuid,
    pub status: HarnessWorkOrderAttemptStatus,
    pub current_stage: HarnessWorkOrderAttemptStage,
    pub harness_id: Option<Uuid>,
    pub smoke_run_id: Option<Uuid>,
    pub result_json: Option<String>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// Fields published atomically when a qualification attempt reaches a terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderAttemptCompletion<'a> {
    pub expected_stage: HarnessWorkOrderAttemptStage,
    pub status: HarnessWorkOrderAttemptStatus,
    pub harness_id: Option<Uuid>,
    pub smoke_run_id: Option<Uuid>,
    pub result_json: Option<&'a str>,
    pub failure_code: Option<&'a str>,
    pub failure_message: Option<&'a str>,
    pub completed_at: DateTime<Utc>,
}
