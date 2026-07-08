//! hf-service: Business logic and orchestration for `hobot_fuzz`.
//!
//! See `docs/design/service-orchestration-design.md`.
//!
//! [`ServiceContainer`] is the single canonical service object: every
//! presentation layer (CLI, web, GUI) constructs one via
//! [`ServiceContainer::bootstrap`] and calls methods through it, keeping
//! business logic out of presentation crates (AGENTS.md 2.9) and routing every
//! build/run through `hf-runtime` sandboxing (AGENTS.md 2.12).

pub mod checkpoints;
pub mod config;
pub mod container;
pub mod diagnostics;
pub mod init;
pub mod knowledge;
pub mod recovery;
pub mod report;
pub mod report_store;
pub mod sarif;
pub mod scheduler;
pub mod system;
pub mod workbench;

pub use hf_core::engine::EngineKind;
pub use hf_core::target::TargetLanguage;
pub use hf_core::types::{Message, Role, SessionId};
pub use hf_runtime::host_platform;

pub use container::{
    build_sandbox_image, copy_project_sources, generate_target_seeds, project_workspace_dir,
    provider_pool_from_config, provider_pool_from_env, repo_root, runtime_from_env, workspace_dir,
    workspace_root, AgentInstanceSnapshot, AgentPoolSnapshot, ArtifactSummary, CompileOutcome,
    MemorySnapshot, MinimizeOutcome, ProviderSnapshot, RegressionResult, RunSummary, SeedEntry,
    ServiceContainer, SystemSnapshot, SyzkallerRunOpts, SyzkallerSummary,
};
pub use init::{init_at, init_workspace, InitReport};
pub use report_store::ReportDraft;
pub use system::{system_status, SystemStatus};
pub use workbench::{
    CrashReviewItem, GitLabIssueExport, HarnessReviewItem, WorkbenchDashboard, WorkbenchReadiness,
    WorkbenchRun, WorkbenchTarget, WorkbenchTotals,
};
