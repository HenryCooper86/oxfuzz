//! `hf-scheduler`: scheduled workflow execution for `hobot_fuzz`.
//!
//! This crate provides time-based and event-driven task scheduling:
//!
//! - [`CronSchedule`] — cron expression-based triggers (full 5-field support via `croner`)
//! - [`IntervalSchedule`] — fixed-interval triggers
//! - [`OneTimeSchedule`] — one-time delayed triggers
//! - [`EventSchedule`] — event-driven triggers from external event producers
//! - [`ScheduleStore`] — schedule registry with CRUD operations
//! - [`ScheduleExecutor`] — trigger-to-workflow execution translation
//! - [`SchedulerManager`] — top-level async service that runs the trigger loop
//!
//! Scheduled tasks execute as standard orchestrated workflows, with parameter
//! resolution chaining schema defaults, static schedule overrides, and
//! trigger-time expressions (see [`params`]).

pub mod config;
pub mod cron;
pub mod dispatcher;
pub mod event;
pub mod event_bridge;
pub mod executor;
pub mod interval;
pub mod manager;
pub mod onetime;
pub mod params;
pub mod queue;
pub mod recovery;
pub mod store;
pub mod trigger;

// Re-export primary types.
pub use config::{ConcurrencyPolicy, MissedPolicy, SchedulerConfig};
pub use cron::CronSchedule;
pub use dispatcher::{DispatchError, DispatchResult, WorkflowDispatcher};
pub use event::{EventFilter, EventSchedule};
pub use event_bridge::{EventBridge, IncomingEvent};
pub use executor::{
    ExecutionStatus, ExecutionStore, ScheduleContext, ScheduleExecution, ScheduleExecutor,
};
pub use interval::IntervalSchedule;
pub use manager::{PersistenceError, SchedulerManager, SchedulerPersistence};
pub use onetime::OneTimeSchedule;
pub use params::{resolve_parameters, ResolutionContext, ResolveError};
pub use store::{Schedule, SchedulePolicies, ScheduleStore, TriggerConfig};
pub use trigger::{FiredTrigger, TriggerType};
