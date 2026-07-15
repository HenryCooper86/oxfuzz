//! Cron-style schedule trigger using the `croner` crate for full
//! 5-field cron expression parsing.

use chrono::{DateTime, Utc};
use croner::Cron;
use serde::{Deserialize, Serialize};

/// A cron-based schedule trigger.
///
/// Supports standard 5-field cron expressions (minute, hour, day-of-month,
/// month, day-of-week) plus extended syntax (`L`, `#`, `W`) via `croner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronSchedule {
    /// Cron expression string (e.g., `"0 9 * * MON"`).
    pub expression: String,
    /// Timezone for evaluation (default: UTC).
    #[serde(default = "default_tz")]
    pub timezone: String,
}

fn default_tz() -> String {
    "UTC".into()
}

impl CronSchedule {
    /// Create a new cron schedule with the given expression.
    pub fn new(expression: &str) -> Self {
        Self {
            expression: expression.to_string(),
            timezone: "UTC".into(),
        }
    }

    /// Create a cron schedule with a specific timezone.
    #[must_use]
    pub fn with_timezone(mut self, tz: &str) -> Self {
        self.timezone = tz.to_string();
        self
    }

    /// Parse the cron expression into a `Cron` instance.
    fn parsed(&self) -> Option<Cron> {
        Cron::new(&self.expression).parse().ok()
    }

    /// Validate whether the cron expression is parseable.
    pub fn is_valid(&self) -> bool {
        self.parsed().is_some()
    }

    /// Whether the configured timezone is UTC or a recognized IANA timezone.
    #[must_use]
    pub fn is_timezone_valid(&self) -> bool {
        let name = self.timezone.trim();
        name.is_empty() || name.eq_ignore_ascii_case("utc") || name.parse::<chrono_tz::Tz>().is_ok()
    }

    /// Get the next fire time after `after`.
    ///
    /// The cron fields are interpreted in the schedule's `timezone` (e.g.
    /// `"0 9 * * *"` in `Asia/Shanghai` fires at 09:00 Shanghai time, not UTC).
    /// An unknown timezone falls back to UTC. The result is always returned in
    /// UTC. Returns `None` if the expression is invalid or has no future
    /// occurrence.
    pub fn next_fire(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let cron = self.parsed()?;
        match self.tz() {
            Some(tz) => cron
                .find_next_occurrence(&after.with_timezone(&tz), false)
                .ok()
                .map(|next| next.with_timezone(&Utc)),
            None => cron.find_next_occurrence(&after, false).ok(),
        }
    }

    /// Check whether a given `DateTime` matches the cron expression, evaluated
    /// in the schedule's timezone.
    pub fn matches(&self, time: &DateTime<Utc>) -> bool {
        let Some(cron) = self.parsed() else {
            return false;
        };
        match self.tz() {
            Some(tz) => cron
                .is_time_matching(&time.with_timezone(&tz))
                .unwrap_or(false),
            None => cron.is_time_matching(time).unwrap_or(false),
        }
    }

    /// Parse `timezone` into a `chrono_tz::Tz`. `None` means UTC (either the
    /// literal `"UTC"`/empty, or an unrecognized name we fall back from).
    fn tz(&self) -> Option<chrono_tz::Tz> {
        let name = self.timezone.trim();
        if name.is_empty() || name.eq_ignore_ascii_case("utc") {
            return None;
        }
        name.parse::<chrono_tz::Tz>().map_or_else(
            |_| {
                tracing::warn!(timezone = %name, "unknown cron timezone; evaluating in UTC");
                None
            },
            Some,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_valid_expression() {
        let cron = CronSchedule::new("0 9 * * MON");
        assert!(cron.is_valid());
    }

    #[test]
    fn test_cron_invalid_expression() {
        let cron = CronSchedule::new("invalid cron expr!!");
        assert!(!cron.is_valid());
        assert!(cron.next_fire(Utc::now()).is_none());
    }

    #[test]
    fn test_cron_next_fire_basic() {
        let cron = CronSchedule::new("* * * * *"); // every minute
        let now = Utc::now();
        let next = cron.next_fire(now).unwrap();
        assert!(next > now);
        // Should be within 60 seconds.
        let diff = (next - now).num_seconds();
        assert!(diff <= 60, "Expected <=60s but got {diff}s");
    }

    #[test]
    fn test_cron_next_fire_hourly() {
        let cron = CronSchedule::new("0 * * * *"); // every hour at :00
        let now = Utc::now();
        let next = cron.next_fire(now).unwrap();
        assert!(next > now);
        assert_eq!(next.format("%M").to_string(), "00");
    }

    #[test]
    fn test_cron_next_fire_daily() {
        let cron = CronSchedule::new("0 2 * * *"); // daily at 02:00
        let now = Utc::now();
        let next = cron.next_fire(now).unwrap();
        assert!(next > now);
        assert_eq!(next.format("%H:%M").to_string(), "02:00");
    }

    #[test]
    fn test_cron_next_fire_day_of_week() {
        let cron = CronSchedule::new("0 9 * * 1"); // every Monday at 09:00
        let now = Utc::now();
        let next = cron.next_fire(now).unwrap();
        assert!(next > now);
        // chrono: Monday = 1 in ISO weekday format (%u)
        assert_eq!(next.format("%u").to_string(), "1");
        assert_eq!(next.format("%H:%M").to_string(), "09:00");
    }

    #[test]
    fn test_cron_every_n_minutes() {
        let cron = CronSchedule::new("*/15 * * * *"); // every 15 minutes
        assert!(cron.is_valid());
        let now = Utc::now();
        let next = cron.next_fire(now).unwrap();
        assert!(next > now);
    }

    #[test]
    fn test_cron_with_timezone() {
        let cron = CronSchedule::new("0 9 * * *").with_timezone("Asia/Shanghai");
        assert_eq!(cron.timezone, "Asia/Shanghai");
        assert!(cron.is_valid());
    }

    #[test]
    fn next_fire_honors_timezone() {
        use chrono::TimeZone;
        // 09:00 in Asia/Shanghai (UTC+8) is 01:00 UTC. The timezone must shift
        // the fire time, not be silently ignored (which would give 09:00 UTC).
        let cron = CronSchedule::new("0 9 * * *").with_timezone("Asia/Shanghai");
        let after = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let next = cron.next_fire(after).unwrap();
        assert_eq!(next.format("%H:%M").to_string(), "01:00", "got {next}");

        // The same expression in UTC fires at 09:00 UTC.
        let utc = CronSchedule::new("0 9 * * *");
        let next_utc = utc.next_fire(after).unwrap();
        assert_eq!(next_utc.format("%H:%M").to_string(), "09:00");
    }

    #[test]
    fn unknown_timezone_falls_back_to_utc() {
        use chrono::TimeZone;
        let cron = CronSchedule::new("0 9 * * *").with_timezone("Mars/Olympus");
        let after = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let next = cron.next_fire(after).unwrap();
        assert_eq!(next.format("%H:%M").to_string(), "09:00");
    }
}
