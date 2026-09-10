//! Bounded, read-only calendar opportunities for the Automation view.
use chrono::{DateTime, Utc};
use hf_scheduler::cron::CronSchedule;
use hf_scheduler::interval::IntervalSchedule;
use hf_scheduler::trigger::evaluate_trigger;
use hf_scheduler::{Schedule, TriggerConfig};
use serde::Serialize;

use super::{budget_skip_reason, CampaignDurabilityStatus, CampaignParams, CampaignRuntimeState};

/// Why a schedule does or does not currently have calendar opportunities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulePreviewState {
    Scheduled,
    Due,
    Paused,
    BudgetExhausted,
    RecoveryRequired,
    Consumed,
    WaitingForEvent,
    Unavailable,
}

/// Calendar opportunities and remaining successful-work allowance, without reserving work.
#[derive(Debug, Clone, Serialize)]
pub struct SchedulePreview {
    /// Current scheduling availability.
    pub state: SchedulePreviewState,
    /// Effective IANA timezone used to display the returned UTC instants.
    pub timezone: String,
    /// A legacy unknown timezone is being evaluated as UTC.
    pub timezone_fallback: bool,
    /// At most three opportunities, expressed as RFC3339 instants. Due work starts at now.
    pub next_fires: Vec<String>,
    /// Remaining completed-run allowance; absent means unbounded.
    pub remaining_runs: Option<u32>,
    /// Remaining whole-second successful-work allowance; absent means unbounded.
    pub remaining_secs: Option<u64>,
}

impl SchedulePreview {
    pub(super) fn unavailable() -> Self {
        Self {
            state: SchedulePreviewState::Unavailable,
            timezone: "UTC".into(),
            timezone_fallback: false,
            next_fires: Vec::new(),
            remaining_runs: None,
            remaining_secs: None,
        }
    }

    pub(super) fn for_schedule(
        schedule: &Schedule,
        params: &CampaignParams,
        progress: CampaignRuntimeState,
        durability: CampaignDurabilityStatus,
        now: DateTime<Utc>,
    ) -> Self {
        let mut preview = Self::unavailable();
        preview.remaining_runs = params
            .max_runs
            .map(|limit| limit.saturating_sub(progress.runs_done));
        preview.remaining_secs = params
            .max_total_secs
            .map(|limit| limit.saturating_sub(progress.secs_done));
        let cron = if let TriggerConfig::Cron {
            expression,
            timezone,
        } = &schedule.trigger
        {
            let configured = CronSchedule::new(expression).with_timezone(timezone);
            preview.timezone_fallback = !configured.is_timezone_valid();
            if !preview.timezone_fallback
                && !timezone.trim().is_empty()
                && !timezone.trim().eq_ignore_ascii_case("utc")
            {
                timezone.trim().clone_into(&mut preview.timezone);
            }
            Some(configured.with_timezone(&preview.timezone))
        } else {
            None
        };
        preview.state = match durability {
            CampaignDurabilityStatus::RecoveryRequired => SchedulePreviewState::RecoveryRequired,
            CampaignDurabilityStatus::Consumed => SchedulePreviewState::Consumed,
            CampaignDurabilityStatus::Ready if budget_skip_reason(&progress, params).is_some() => {
                SchedulePreviewState::BudgetExhausted
            }
            CampaignDurabilityStatus::Ready if !schedule.enabled => SchedulePreviewState::Paused,
            CampaignDurabilityStatus::Ready
                if matches!(schedule.trigger, TriggerConfig::Event { .. }) =>
            {
                SchedulePreviewState::WaitingForEvent
            }
            CampaignDurabilityStatus::Ready => SchedulePreviewState::Scheduled,
        };
        if preview.state != SchedulePreviewState::Scheduled {
            return preview;
        }
        let due = evaluate_trigger(schedule, now).is_some();
        let first = match &schedule.trigger {
            TriggerConfig::Cron { .. } => cron
                .as_ref()
                .and_then(|cron| cron.next_fire(schedule.last_fire.unwrap_or(schedule.created_at))),
            TriggerConfig::Interval { interval_secs } => {
                let interval = IntervalSchedule::new(*interval_secs);
                match schedule.last_fire {
                    Some(last) => interval.next_fire(last),
                    None => interval.next_fire(now).map(|_| now),
                }
            }
            TriggerConfig::OneTime { at } if schedule.last_fire.is_none() => Some(*at),
            TriggerConfig::OneTime { .. } | TriggerConfig::Event { .. } => None,
        };
        let Some(first) = first else {
            preview.state = SchedulePreviewState::Unavailable;
            return preview;
        };
        preview.state = if due {
            SchedulePreviewState::Due
        } else {
            SchedulePreviewState::Scheduled
        };
        let mut next = Some(if due { now } else { first });
        for _ in 0..3 {
            let Some(at) = next else {
                break;
            };
            preview.next_fires.push(at.to_rfc3339());
            next = match &schedule.trigger {
                TriggerConfig::Cron { .. } => cron.as_ref().and_then(|cron| cron.next_fire(at)),
                TriggerConfig::Interval { interval_secs } => {
                    IntervalSchedule::new(*interval_secs).next_fire(at)
                }
                TriggerConfig::OneTime { .. } | TriggerConfig::Event { .. } => None,
            };
        }
        preview
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 10, 12, 0, 0).unwrap()
    }
    fn schedule(trigger: TriggerConfig) -> Schedule {
        let mut schedule = Schedule::new("preview", "preview", trigger, "fuzz-campaign");
        schedule.created_at = now();
        schedule
    }
    fn preview(schedule: &Schedule) -> SchedulePreview {
        SchedulePreview::for_schedule(
            schedule,
            &CampaignParams::default(),
            CampaignRuntimeState::default(),
            CampaignDurabilityStatus::Ready,
            now(),
        )
    }

    #[test]
    fn new_cron_uses_calendar_and_configured_timezone() {
        let schedule = schedule(TriggerConfig::Cron {
            expression: "0 9 * * *".into(),
            timezone: "Asia/Shanghai".into(),
        });
        let result = preview(&schedule);
        assert_eq!(result.state, SchedulePreviewState::Scheduled);
        assert_eq!(result.timezone, "Asia/Shanghai");
        assert_eq!(
            result.next_fires,
            vec![
                "2026-09-11T01:00:00+00:00",
                "2026-09-12T01:00:00+00:00",
                "2026-09-13T01:00:00+00:00"
            ]
        );
        assert!(evaluate_trigger(&schedule, now()).is_none());
    }

    #[test]
    fn cron_opportunities_follow_local_time_across_daylight_saving() {
        let at = Utc.with_ymd_and_hms(2026, 10, 31, 12, 0, 0).unwrap();
        let mut schedule = schedule(TriggerConfig::Cron {
            expression: "0 9 * * *".into(),
            timezone: "America/New_York".into(),
        });
        schedule.created_at = at;
        let result = SchedulePreview::for_schedule(
            &schedule,
            &CampaignParams::default(),
            CampaignRuntimeState::default(),
            CampaignDurabilityStatus::Ready,
            at,
        );
        assert_eq!(
            result.next_fires,
            vec![
                "2026-10-31T13:00:00+00:00",
                "2026-11-01T14:00:00+00:00",
                "2026-11-02T14:00:00+00:00"
            ]
        );
    }

    #[test]
    fn interval_due_and_overdue_cron_start_at_now() {
        let interval = schedule(TriggerConfig::Interval { interval_secs: 60 });
        let result = preview(&interval);
        assert_eq!(result.state, SchedulePreviewState::Due);
        assert_eq!(result.next_fires[0], now().to_rfc3339());
        assert_eq!(
            result.next_fires[1],
            (now() + Duration::seconds(60)).to_rfc3339()
        );
        let mut cron = schedule(TriggerConfig::Cron {
            expression: "0 2 * * *".into(),
            timezone: "UTC".into(),
        });
        cron.created_at = now() - Duration::days(1);
        assert_eq!(preview(&cron).state, SchedulePreviewState::Due);
        assert_eq!(preview(&cron).next_fires[1], "2026-09-11T02:00:00+00:00");
    }

    #[test]
    fn paused_exhausted_and_recovery_schedules_do_not_predict_runs() {
        let mut schedule = schedule(TriggerConfig::Interval { interval_secs: 60 });
        schedule.enabled = false;
        assert_eq!(preview(&schedule).state, SchedulePreviewState::Paused);
        assert!(preview(&schedule).next_fires.is_empty());
        let params = CampaignParams {
            max_runs: Some(3),
            max_total_secs: Some(10),
            ..CampaignParams::default()
        };
        let progress = CampaignRuntimeState {
            cursor: 0,
            runs_done: 5,
            secs_done: 7,
        };
        let result = SchedulePreview::for_schedule(
            &schedule,
            &params,
            progress,
            CampaignDurabilityStatus::Ready,
            now(),
        );
        assert_eq!(result.state, SchedulePreviewState::BudgetExhausted);
        assert_eq!(result.remaining_runs, Some(0));
        assert_eq!(result.remaining_secs, Some(3));
        assert!(result.next_fires.is_empty());
        for (durability, state) in [
            (
                CampaignDurabilityStatus::Consumed,
                SchedulePreviewState::Consumed,
            ),
            (
                CampaignDurabilityStatus::RecoveryRequired,
                SchedulePreviewState::RecoveryRequired,
            ),
        ] {
            let result =
                SchedulePreview::for_schedule(&schedule, &params, progress, durability, now());
            assert_eq!(result.state, state);
            assert!(result.next_fires.is_empty());
        }
    }

    #[test]
    fn one_time_has_one_opportunity_and_event_has_none() {
        let once = preview(&schedule(TriggerConfig::OneTime {
            at: now() + Duration::hours(1),
        }));
        assert_eq!(once.next_fires.len(), 1);
        let event = preview(&schedule(TriggerConfig::Event {
            event_type: "run.completed".into(),
            debounce_secs: 0,
            filter: None,
        }));
        assert_eq!(event.state, SchedulePreviewState::WaitingForEvent);
        assert!(event.next_fires.is_empty());
        assert_eq!(event.remaining_runs, None);
        assert_eq!(event.remaining_secs, None);
    }

    #[test]
    fn invalid_trigger_is_unavailable_and_legacy_zone_reports_effective_utc() {
        let invalid = preview(&schedule(TriggerConfig::Interval {
            interval_secs: u64::MAX,
        }));
        assert_eq!(invalid.state, SchedulePreviewState::Unavailable);
        assert!(invalid.next_fires.is_empty());
        let fallback = preview(&schedule(TriggerConfig::Cron {
            expression: "0 9 * * *".into(),
            timezone: "unknown/zone".into(),
        }));
        assert!(fallback.timezone_fallback);
        assert_eq!(fallback.timezone, "UTC");
        assert_eq!(fallback.next_fires[0], "2026-09-11T09:00:00+00:00");
    }
}
