//! hf-service: Business logic and orchestration for `hobot_fuzz`.
//!
//! See `docs/design/service-orchestration-design.md`.
//!
//! [`ServiceContainer`] is the single canonical service object: every
//! presentation layer (CLI, web, GUI) constructs one via
//! [`ServiceContainer::bootstrap`] and calls methods through it, keeping
//! business logic out of presentation crates (AGENTS.md 2.9) and routing every
//! build/run through `hf-runtime` sandboxing (AGENTS.md 2.12).

pub mod agent;
#[cfg(feature = "automotive-scapy")]
pub mod automotive;
#[cfg(feature = "automotive-scapy")]
pub mod automotive_report;
pub mod campaign_state;
pub mod checkpoints;
pub mod config;
pub mod container;
mod crash_minimization;
pub mod defectdojo;
pub mod defectdojo_lifecycle;
pub mod diagnostics;
pub mod init;
pub mod issue_tracker;
pub mod knowledge;
pub mod recovery;
pub mod report;
pub mod report_export;
pub mod report_store;
pub mod sarif;
pub mod scheduler;
pub mod system;
mod syzkaller;
pub mod workbench;

pub use hf_agent::{
    AgentDefinition, AgentEvent, AgentRegistry, CollectingSink, EventSink, NullSink, TOOL_SPECS,
};
pub use hf_core::engine::{EngineCapabilities, EngineKind, FuzzProgress};
pub use hf_core::error::ClassifiedError;
pub use hf_core::provider::ProviderStatus;
pub use hf_core::runtime::CommandTermination;
pub use hf_core::target::{TargetInventory, TargetLanguage};
pub use hf_core::types::{Message, ProviderId, Role, SessionId};
pub use hf_guardrails::{Action, ApprovalGate, GuardrailPolicy, Guardrails};
pub use hf_runtime::{
    can_run_platform, docker_cli_present, docker_daemon_ready, host_platform, norm_platform,
    platform_short, sandbox_image_arch, sandbox_image_present,
};
pub use hf_skills::{SkillDefinition, SkillRegistry, TrustTier};

pub use agent::{AgentRegistryInfo, AgentToolDefinition, AgentTurnRequest};
pub use container::{
    build_sandbox_image, copy_project_sources, generate_target_seeds, initialize_workspace_root,
    project_workspace_dir, provider_pool_from_config, provider_pool_from_env, repo_root,
    runtime_from_env, workspace_dir, workspace_root, AgentInstanceSnapshot, AgentPoolSnapshot,
    ArtifactSummary, CompileOutcome, CoverageSample, EffectiveAutoRevert, MemorySnapshot,
    MinimizeOutcome, ProviderSnapshot, RegressionResult, RunCancelOutcome, RunControlStatus,
    RunHistoryItem, RunLifecycleStatus, RunSummary, SchedulableTarget, SeedEntry, ServiceContainer,
    SystemSnapshot, SyzkallerRunOpts, SyzkallerSummary,
};
pub use defectdojo::{DefectDojoConfig, PushOutcome};
pub use defectdojo_lifecycle::{DefectDojoState, DefectDojoStatus};
pub use hf_storage::{AutoRevertEvent, GuardrailDecisionRecord, ProjectAutoRevert};
pub use init::{init_at, init_workspace, InitReport};
pub use issue_tracker::{CreatedIssue, IssueTrackerConfig};
pub use report_store::ReportDraft;
pub use system::{system_status, SystemStatus};
pub use workbench::{
    CrashReviewItem, HarnessReviewItem, IssueExport, WorkbenchDashboard, WorkbenchReadiness,
    WorkbenchRun, WorkbenchTarget, WorkbenchTotals,
};
