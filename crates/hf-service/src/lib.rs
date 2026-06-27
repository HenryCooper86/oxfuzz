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
pub mod scheduler;

pub use container::{
    build_sandbox_image, copy_project_sources, generate_target_seeds, provider_pool_from_config,
    provider_pool_from_env, repo_root, runtime_from_env, workspace_dir, CompileOutcome,
    MinimizeOutcome, RunSummary, SeedEntry, ServiceContainer,
};
pub use init::{init_at, init_workspace, InitReport};
