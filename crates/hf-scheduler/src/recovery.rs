//! Recovery manager: detects and handles missed schedule fires after restart.

use chrono::{DateTime, Duration, Utc};
use tracing::{debug, info};

use crate::config::MissedPolicy;
use crate::store::{Schedule, ScheduleStore, TriggerConfig};
use crate::trigger::{FiredTrigger, TriggerType};

/// Result summary of the recovery planning process.
#[derive(Debug, Default)]
pub struct RecoveryResult {
    /// Schedules that were caught up (fired once).
    pub caught_up: Vec<String>,
    /// Schedules whose missed occurrences were skipped.
    pub skipped: Vec<String>,
    /// Schedules that were backfilled and their complete occurrence counts.
    pub backfilled: Vec<(String, u64)>,
}

/// A compact batch of recovery triggers.
///
/// Backfills stay compact even after a long outage. The manager expands each
/// batch lazily into its bounded trigger channel, so recovery is lossless
/// without allocating one object or task per missed occurrence up front.
#[derive(Debug, Clone)]
pub(crate) struct RecoveryBatch {
    pub(crate) schedule_id: String,
    pub(crate) first_fire: DateTime<Utc>,
    cadence: RecoveryCadence,
    pub(crate) count: u64,
    pub(crate) trigger_type: TriggerType,
}

/// How to advance a compact recovery batch without assuming cron occurrences
/// have fixed UTC spacing across month boundaries or daylight-saving changes.
#[derive(Debug, Clone)]
enum RecoveryCadence {
    Fixed(Duration),
    Cron {
        expression: String,
        timezone: String,
    },
}

impl RecoveryBatch {
    pub(crate) fn single(schedule: &Schedule, at: DateTime<Utc>) -> Self {
        Self {
            schedule_id: schedule.id.clone(),
            first_fire: at,
            cadence: RecoveryCadence::Fixed(Duration::zero()),
            count: 1,
            trigger_type: trigger_type(schedule),
        }
    }

    pub(crate) fn next_fire(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match &self.cadence {
            RecoveryCadence::Fixed(interval) => after.checked_add_signed(*interval),
            RecoveryCadence::Cron {
                expression,
                timezone,
            } => crate::cron::CronSchedule::new(expression)
                .with_timezone(timezone)
                .next_fire(after),
        }
    }
}

/// A durable cursor advancement applied before the normal evaluator starts.
#[derive(Debug, Clone)]
pub(crate) struct RecoveryAdvance {
    pub(crate) schedule_id: String,
    pub(crate) last_fire: DateTime<Utc>,
}

/// Recovery work split into compact dispatch batches and cursor advances.
#[derive(Debug, Default)]
pub(crate) struct RecoveryPlan {
    pub(crate) batches: Vec<RecoveryBatch>,
    pub(crate) advances: Vec<RecoveryAdvance>,
    pub(crate) result: RecoveryResult,
}

impl RecoveryPlan {
    pub(crate) fn trigger_count(&self) -> u64 {
        self.batches
            .iter()
            .fold(0, |total, batch| total.saturating_add(batch.count))
    }
}

/// Plan missed schedule recovery.
///
/// `Skip` produces only a cursor advance. `CatchUp` produces one trigger.
/// `Backfill` produces a compact batch containing every missed occurrence.
/// Event schedules are never synthesized, and future one-time schedules remain
/// pending.
pub(crate) fn recover_missed(store: &ScheduleStore, now: DateTime<Utc>) -> RecoveryPlan {
    let mut plan = RecoveryPlan::default();

    for schedule in store.list_enabled() {
        let Some(last_fire) = schedule.last_fire else {
            plan_never_fired(schedule, now, &mut plan);
            continue;
        };

        let Some((first_fire, cadence, missed_count, latest_due)) =
            missed_occurrences(schedule, last_fire, now)
        else {
            continue;
        };
        match schedule.policies.effective_missed_policy() {
            MissedPolicy::Skip => {
                info!(schedule_id = %schedule.id, "Missed schedule, advancing (policy=skip)");
                plan.result.skipped.push(schedule.id.clone());
                plan.advances.push(RecoveryAdvance {
                    schedule_id: schedule.id.clone(),
                    last_fire: latest_due,
                });
            }
            MissedPolicy::CatchUp => {
                info!(schedule_id = %schedule.id, "Missed schedule, catching up (policy=catch_up)");
                plan.batches.push(RecoveryBatch::single(schedule, now));
                plan.result.caught_up.push(schedule.id.clone());
                plan.advances.push(RecoveryAdvance {
                    schedule_id: schedule.id.clone(),
                    last_fire: now,
                });
            }
            MissedPolicy::Backfill => {
                info!(
                    schedule_id = %schedule.id,
                    missed_count,
                    "Missed schedule, queueing lossless backfill"
                );
                plan.batches.push(RecoveryBatch {
                    schedule_id: schedule.id.clone(),
                    first_fire,
                    cadence,
                    count: missed_count,
                    trigger_type: trigger_type(schedule),
                });
                plan.result
                    .backfilled
                    .push((schedule.id.clone(), missed_count));
                plan.advances.push(RecoveryAdvance {
                    schedule_id: schedule.id.clone(),
                    last_fire: latest_due,
                });
            }
        }
    }

    plan
}

fn plan_never_fired(schedule: &Schedule, now: DateTime<Utc>, plan: &mut RecoveryPlan) {
    match &schedule.trigger {
        TriggerConfig::Event { .. } => return,
        TriggerConfig::OneTime { at } if *at > now => return,
        TriggerConfig::OneTime { .. }
            if schedule.policies.effective_missed_policy() == MissedPolicy::Skip =>
        {
            plan.result.skipped.push(schedule.id.clone());
        }
        _ => {
            debug!(schedule_id = %schedule.id, "Never fired, firing once now");
            plan.batches.push(RecoveryBatch::single(schedule, now));
            plan.result.caught_up.push(schedule.id.clone());
        }
    }
    plan.advances.push(RecoveryAdvance {
        schedule_id: schedule.id.clone(),
        last_fire: now,
    });
}

fn add_intervals(start: DateTime<Utc>, interval: Duration, count: u64) -> Option<DateTime<Utc>> {
    let count = i64::try_from(count).ok()?;
    let seconds = interval.num_seconds().checked_mul(count)?;
    start.checked_add_signed(Duration::seconds(seconds))
}

fn missed_occurrences(
    schedule: &Schedule,
    last_fire: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<(DateTime<Utc>, RecoveryCadence, u64, DateTime<Utc>)> {
    match &schedule.trigger {
        TriggerConfig::Interval { interval_secs } => {
            let interval = Duration::seconds(i64::try_from(*interval_secs).unwrap_or(i64::MAX));
            if interval <= Duration::zero() {
                return None;
            }
            let elapsed = now - last_fire;
            if elapsed < interval {
                return None;
            }
            let missed_count =
                u64::try_from(elapsed.num_seconds() / interval.num_seconds()).ok()?;
            if missed_count == 0 {
                return None;
            }
            let first_fire = last_fire.checked_add_signed(interval)?;
            let latest_due = add_intervals(last_fire, interval, missed_count)?;
            Some((
                first_fire,
                RecoveryCadence::Fixed(interval),
                missed_count,
                latest_due,
            ))
        }
        TriggerConfig::Cron {
            expression,
            timezone,
        } => {
            let cron = crate::cron::CronSchedule::new(expression).with_timezone(timezone);
            let first_fire = cron.next_fire(last_fire)?;
            if first_fire > now {
                return None;
            }
            let mut latest_due = first_fire;
            let mut missed_count = 1_u64;
            while let Some(next) = cron.next_fire(latest_due) {
                if next <= latest_due || next > now {
                    break;
                }
                latest_due = next;
                missed_count = missed_count.saturating_add(1);
            }
            Some((
                first_fire,
                RecoveryCadence::Cron {
                    expression: expression.clone(),
                    timezone: timezone.clone(),
                },
                missed_count,
                latest_due,
            ))
        }
        TriggerConfig::OneTime { .. } | TriggerConfig::Event { .. } => None,
    }
}

fn trigger_type(schedule: &Schedule) -> TriggerType {
    match &schedule.trigger {
        TriggerConfig::Cron { .. } => TriggerType::Cron,
        TriggerConfig::Interval { .. } => TriggerType::Interval,
        TriggerConfig::OneTime { .. } => TriggerType::OneTime,
        TriggerConfig::Event { .. } => TriggerType::Event,
    }
}

/// Expand one compact batch item into a trigger.
pub(crate) fn trigger_at(batch: &RecoveryBatch, at: DateTime<Utc>) -> FiredTrigger {
    FiredTrigger {
        schedule_id: batch.schedule_id.clone(),
        fired_at: at,
        trigger_type: batch.trigger_type,
        is_recovery: true,
        event_payload: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConcurrencyPolicy;
    use crate::store::SchedulePolicies;

    fn interval_schedule(id: &str, interval_secs: u64, policy: MissedPolicy) -> Schedule {
        Schedule::new(id, id, TriggerConfig::Interval { interval_secs }, "wf").with_policies(
            SchedulePolicies {
                missed_policy: Some(policy),
                concurrency_policy: Some(ConcurrencyPolicy::default()),
                max_executions_per_hour: 0,
            },
        )
    }

    #[test]
    fn recovery_skip_advances_without_a_trigger() {
        let mut store = ScheduleStore::new();
        let mut schedule = interval_schedule("s1", 60, MissedPolicy::Skip);
        let now = Utc::now();
        schedule.last_fire = Some(now - Duration::minutes(5));
        store.register(schedule);

        let plan = recover_missed(&store, now);
        assert_eq!(plan.trigger_count(), 0);
        assert_eq!(plan.result.skipped, ["s1"]);
        assert_eq!(plan.advances.len(), 1);
        assert_eq!(plan.advances[0].last_fire, now);
    }

    #[test]
    fn recovery_catch_up_emits_one_trigger() {
        let mut store = ScheduleStore::new();
        let mut schedule = interval_schedule("s1", 60, MissedPolicy::CatchUp);
        schedule.last_fire = Some(Utc::now() - Duration::minutes(5));
        store.register(schedule);

        let plan = recover_missed(&store, Utc::now());
        assert_eq!(plan.trigger_count(), 1);
        assert_eq!(plan.result.caught_up.len(), 1);
    }

    #[test]
    fn recovery_backfill_is_not_truncated() {
        let mut store = ScheduleStore::new();
        let mut schedule = interval_schedule("s1", 60, MissedPolicy::Backfill);
        let now = Utc::now();
        schedule.last_fire = Some(now - Duration::minutes(150));
        store.register(schedule);

        let plan = recover_missed(&store, now);
        assert_eq!(plan.trigger_count(), 150);
        assert_eq!(plan.result.backfilled, [("s1".to_owned(), 150)]);
        assert_eq!(plan.advances[0].last_fire, now);
    }

    #[test]
    fn cron_backfill_iterates_calendar_occurrences_in_configured_timezone() {
        let mut store = ScheduleStore::new();
        let mut schedule = Schedule::new(
            "monthly",
            "monthly",
            TriggerConfig::Cron {
                expression: "0 9 1 * *".to_owned(),
                timezone: "Asia/Shanghai".to_owned(),
            },
            "wf",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::Backfill),
            concurrency_policy: Some(ConcurrencyPolicy::Queue),
            max_executions_per_hour: 0,
        });
        schedule.last_fire = Some(
            DateTime::parse_from_rfc3339("2026-01-01T01:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        store.register(schedule);
        let now = DateTime::parse_from_rfc3339("2026-04-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let plan = recover_missed(&store, now);

        assert_eq!(plan.trigger_count(), 3);
        assert_eq!(plan.result.backfilled, [("monthly".to_owned(), 3)]);
        let batch = &plan.batches[0];
        assert_eq!(batch.first_fire.to_rfc3339(), "2026-02-01T01:00:00+00:00");
        let march = batch.next_fire(batch.first_fire).unwrap();
        assert_eq!(march.to_rfc3339(), "2026-03-01T01:00:00+00:00");
        assert_eq!(
            plan.advances[0].last_fire.to_rfc3339(),
            "2026-04-01T01:00:00+00:00"
        );
    }

    #[test]
    fn recovery_not_missed() {
        let mut store = ScheduleStore::new();
        let mut schedule = interval_schedule("s1", 3600, MissedPolicy::CatchUp);
        schedule.last_fire = Some(Utc::now() - Duration::seconds(10));
        store.register(schedule);

        let plan = recover_missed(&store, Utc::now());
        assert_eq!(plan.trigger_count(), 0);
        assert!(plan.result.caught_up.is_empty());
    }

    #[test]
    fn never_fired_interval_runs_once_but_event_and_future_onetime_do_not() {
        let mut store = ScheduleStore::new();
        store.register(interval_schedule("interval", 60, MissedPolicy::CatchUp));
        store.register(Schedule::new(
            "event",
            "event",
            TriggerConfig::Event {
                event_type: "push".to_owned(),
                debounce_secs: 0,
                filter: None,
            },
            "wf",
        ));
        store.register(Schedule::new(
            "future",
            "future",
            TriggerConfig::OneTime {
                at: Utc::now() + Duration::hours(1),
            },
            "wf",
        ));

        let plan = recover_missed(&store, Utc::now());
        assert_eq!(plan.trigger_count(), 1);
        assert_eq!(plan.batches[0].schedule_id, "interval");
    }

    #[test]
    fn disabled_schedule_is_not_recovered() {
        let mut store = ScheduleStore::new();
        let mut schedule = interval_schedule("s1", 60, MissedPolicy::CatchUp);
        schedule.last_fire = Some(Utc::now() - Duration::minutes(5));
        schedule.enabled = false;
        store.register(schedule);

        assert_eq!(recover_missed(&store, Utc::now()).trigger_count(), 0);
    }
}
