use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Duration for which a one-time occurrence reservation remains owned.
pub const ONE_TIME_LEASE: Duration = Duration::from_secs(60);
/// Interval at which a running one-time occurrence renews its ownership lease.
pub const ONE_TIME_HEARTBEAT: Duration = Duration::from_secs(15);
/// Maximum UTF-8 byte length for persisted recovery information.
pub const MAX_RECOVERY_DETAIL_BYTES: usize = 4_096;

/// The durable state of a one-time schedule occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OneTimeOccurrenceState {
    Reserved,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl fmt::Display for OneTimeOccurrenceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self {
            Self::Reserved => "reserved",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        };
        formatter.write_str(state)
    }
}

impl FromStr for OneTimeOccurrenceState {
    type Err = OccurrenceValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(OccurrenceValidationError::UnknownState(value.to_owned())),
        }
    }
}

/// A durable one-time dispatch receipt and its lease ownership details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeOccurrence {
    pub id: String,
    pub schedule_id: String,
    pub execution_id: String,
    pub triggered_at: DateTime<Utc>,
    pub state: OneTimeOccurrenceState,
    pub owner_id: String,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub recovery_detail: Option<String>,
}

/// Result of atomically reserving a one-time occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeReservation {
    Reserved(OneTimeOccurrence),
    Existing(OneTimeOccurrence),
}

/// A requested atomic occurrence and execution transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeOccurrenceTransition {
    pub occurrence_id: String,
    pub schedule_id: String,
    pub execution_id: String,
    pub owner_id: String,
    pub from: OneTimeOccurrenceState,
    pub to: OneTimeOccurrenceState,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub recovery_detail: Option<String>,
}

/// Result of attempting an occurrence transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeTransitionResult {
    Applied(OneTimeOccurrence),
    Idempotent(OneTimeOccurrence),
    Conflict(OneTimeOccurrence),
    Missing,
}

/// Result of acknowledging a recovery-eligible occurrence as cancelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeAcknowledgement {
    Acknowledged(OneTimeOccurrence),
    AlreadyCancelled(OneTimeOccurrence),
    Conflict(OneTimeOccurrence),
    Missing,
}

/// Process-local readiness state presented for a one-time schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeRuntimeStatus {
    Ready,
    Consumed,
    RecoveryRequired { detail: String },
}

/// Validation errors for durable occurrence data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OccurrenceValidationError {
    #[error("one-time occurrence identities must not be empty")]
    EmptyIdentity,
    #[error("one-time occurrence lease does not match its state")]
    InvalidLeaseShape,
    #[error("one-time occurrence recovery detail exceeds {MAX_RECOVERY_DETAIL_BYTES} UTF-8 bytes")]
    RecoveryDetailTooLarge,
    #[error("unknown one-time occurrence state: {0}")]
    UnknownState(String),
}

/// Return whether a state transition belongs to the approved one-time graph.
#[must_use]
pub fn transition_allowed(from: OneTimeOccurrenceState, to: OneTimeOccurrenceState) -> bool {
    matches!(
        (from, to),
        (
            OneTimeOccurrenceState::Reserved,
            OneTimeOccurrenceState::Running | OneTimeOccurrenceState::Cancelled
        ) | (
            OneTimeOccurrenceState::Running,
            OneTimeOccurrenceState::Completed
                | OneTimeOccurrenceState::Failed
                | OneTimeOccurrenceState::Cancelled
        )
    )
}

impl OneTimeOccurrence {
    /// Return whether this occurrence can no longer transition.
    #[must_use]
    pub fn terminal(&self) -> bool {
        matches!(
            self.state,
            OneTimeOccurrenceState::Completed
                | OneTimeOccurrenceState::Failed
                | OneTimeOccurrenceState::Cancelled
        )
    }

    /// Return whether a non-terminal occurrence needs operator recovery.
    #[must_use]
    pub fn recovery_eligible(&self, now: DateTime<Utc>) -> bool {
        !self.terminal()
            && self
                .lease_expires_at
                .is_some_and(|lease_expires_at| lease_expires_at <= now)
    }

    /// Validate receipt identity, lease shape, and bounded recovery detail.
    pub fn validate(&self) -> Result<(), OccurrenceValidationError> {
        if self.id.is_empty()
            || self.schedule_id.is_empty()
            || self.execution_id.is_empty()
            || self.owner_id.is_empty()
        {
            return Err(OccurrenceValidationError::EmptyIdentity);
        }
        if self.terminal() != self.lease_expires_at.is_none() {
            return Err(OccurrenceValidationError::InvalidLeaseShape);
        }
        if let Some(detail) = &self.recovery_detail {
            bounded_recovery_detail(detail.clone())?;
        }
        Ok(())
    }
}

/// Validate that recovery information fits the storage byte limit.
pub fn bounded_recovery_detail(
    detail: impl Into<String>,
) -> Result<String, OccurrenceValidationError> {
    let detail = detail.into();
    if detail.len() > MAX_RECOVERY_DETAIL_BYTES {
        return Err(OccurrenceValidationError::RecoveryDetailTooLarge);
    }
    Ok(detail)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn fixture_occurrence(state: OneTimeOccurrenceState) -> OneTimeOccurrence {
        let terminal = matches!(
            state,
            OneTimeOccurrenceState::Completed
                | OneTimeOccurrenceState::Failed
                | OneTimeOccurrenceState::Cancelled
        );
        OneTimeOccurrence {
            id: "occ-1".to_owned(),
            schedule_id: "schedule-1".to_owned(),
            execution_id: "exec-1".to_owned(),
            triggered_at: Utc::now(),
            state,
            owner_id: "owner-1".to_owned(),
            lease_expires_at: (!terminal).then(|| Utc::now() + chrono::Duration::seconds(60)),
            recovery_detail: None,
        }
    }

    #[test]
    fn transition_table_allows_only_the_approved_edges() {
        use OneTimeOccurrenceState::{Cancelled, Completed, Failed, Reserved, Running};

        assert!(transition_allowed(Reserved, Running));
        assert!(transition_allowed(Reserved, Cancelled));
        assert!(transition_allowed(Running, Completed));
        assert!(transition_allowed(Running, Failed));
        assert!(transition_allowed(Running, Cancelled));
        assert!(!transition_allowed(Reserved, Completed));
        assert!(!transition_allowed(Completed, Running));
        assert!(!transition_allowed(Cancelled, Running));
    }

    #[test]
    fn recovery_requires_an_expired_non_terminal_lease() {
        let now = Utc::now();
        let mut occurrence = fixture_occurrence(OneTimeOccurrenceState::Running);
        occurrence.lease_expires_at = Some(now + chrono::Duration::seconds(1));
        assert!(!occurrence.recovery_eligible(now));
        occurrence.lease_expires_at = Some(now);
        assert!(occurrence.recovery_eligible(now));
        occurrence.state = OneTimeOccurrenceState::Completed;
        occurrence.lease_expires_at = None;
        assert!(!occurrence.recovery_eligible(now));
    }

    #[test]
    fn recovery_detail_is_bounded_by_utf8_bytes() {
        assert_eq!(
            bounded_recovery_detail("a".repeat(4_096)).unwrap().len(),
            4_096
        );
        assert!(bounded_recovery_detail("界".repeat(1_366)).is_err());
    }
}
