//! Interval-based schedule trigger.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A fixed-interval schedule trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntervalSchedule {
    /// Interval in seconds between executions.
    #[serde(deserialize_with = "deserialize_interval_secs")]
    pub interval_secs: u64,
}

impl IntervalSchedule {
    /// Create a new interval schedule.
    pub fn new(interval_secs: u64) -> Self {
        Self { interval_secs }
    }

    /// Get the next representable fire time, or `None` for an invalid interval/date.
    pub fn next_fire(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        after.checked_add_signed(self.duration()?)
    }

    pub(crate) fn duration(&self) -> Option<chrono::Duration> {
        if self.interval_secs == 0 {
            return None;
        }
        // Out-of-range seconds are not a representable scheduler duration.
        let seconds = i64::try_from(self.interval_secs).ok()?;
        chrono::Duration::try_seconds(seconds)
    }

    /// Validate an interval received from configuration or a public API.
    ///
    /// # Errors
    /// Returns an error for zero or an interval beyond the supported calendar.
    pub fn validate(&self) -> Result<(), String> {
        if self.next_fire(Utc::now()).is_none() {
            Err("interval must be positive and fit the supported calendar".to_owned())
        } else {
            Ok(())
        }
    }
}

pub(crate) fn deserialize_interval_secs<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let seconds = u64::deserialize(deserializer)?;
    IntervalSchedule::new(seconds)
        .validate()
        .map_err(serde::de::Error::custom)?;
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_next_fire() {
        let sched = IntervalSchedule::new(600); // 10 minutes.
        let now = Utc::now();
        let next = sched.next_fire(now).unwrap();
        assert_eq!((next - now).num_seconds(), 600);
    }
}
