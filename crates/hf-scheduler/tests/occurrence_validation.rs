use chrono::{Duration, Utc};
use hf_scheduler::{OccurrenceValidationError, OneTimeOccurrence, OneTimeOccurrenceState};

fn running_occurrence() -> OneTimeOccurrence {
    let now = Utc::now();
    OneTimeOccurrence {
        id: "occ-1".to_owned(),
        schedule_id: "schedule-1".to_owned(),
        execution_id: "exec-1".to_owned(),
        triggered_at: now,
        state: OneTimeOccurrenceState::Running,
        owner_id: "owner-1".to_owned(),
        lease_expires_at: Some(now + Duration::seconds(60)),
        recovery_detail: None,
    }
}

#[test]
fn every_durable_state_round_trips_and_unknown_state_is_rejected() {
    for (state, name) in [
        (OneTimeOccurrenceState::Reserved, "reserved"),
        (OneTimeOccurrenceState::Running, "running"),
        (OneTimeOccurrenceState::Completed, "completed"),
        (OneTimeOccurrenceState::Failed, "failed"),
        (OneTimeOccurrenceState::Cancelled, "cancelled"),
    ] {
        assert_eq!(state.to_string(), name);
        assert_eq!(name.parse::<OneTimeOccurrenceState>().unwrap(), state);
    }
    assert_eq!(
        "unknown".parse::<OneTimeOccurrenceState>(),
        Err(OccurrenceValidationError::UnknownState(
            "unknown".to_owned()
        ))
    );
}

#[test]
fn receipt_validation_rejects_missing_identity_and_wrong_lease_state() {
    let valid = running_occurrence();
    assert_eq!(valid.validate(), Ok(()));
    for missing in ["id", "schedule_id", "execution_id", "owner_id"] {
        let mut occurrence = valid.clone();
        match missing {
            "id" => occurrence.id.clear(),
            "schedule_id" => occurrence.schedule_id.clear(),
            "execution_id" => occurrence.execution_id.clear(),
            "owner_id" => occurrence.owner_id.clear(),
            _ => unreachable!(),
        }
        assert_eq!(
            occurrence.validate(),
            Err(OccurrenceValidationError::EmptyIdentity),
            "{missing}"
        );
    }

    let mut running_without_lease = valid.clone();
    running_without_lease.lease_expires_at = None;
    assert_eq!(
        running_without_lease.validate(),
        Err(OccurrenceValidationError::InvalidLeaseShape)
    );
    let mut completed_with_lease = valid;
    completed_with_lease.state = OneTimeOccurrenceState::Completed;
    assert_eq!(
        completed_with_lease.validate(),
        Err(OccurrenceValidationError::InvalidLeaseShape)
    );
}
