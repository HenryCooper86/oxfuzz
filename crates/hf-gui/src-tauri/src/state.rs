//! Application state managed by Tauri.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use hf_service::approval::PendingApprovals;
use hf_service::ServiceContainer;

/// Shared application state injected into every Tauri command handler.
pub struct AppState {
    /// The service container holding all wired domain services.
    pub container: ServiceContainer,
    /// In-flight HITL approval requests awaiting a user decision.
    pub pending_approvals: Arc<PendingApprovals>,
    /// Background scheduler driving recurring/one-time fuzz campaigns.
    pub scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
    /// Whether the embedded `DefectDojo` webview should currently exist. Set true
    /// by `defectdojo_embed` and false by `defectdojo_embed_close`; lets a create
    /// that finishes after a close (the view unmounted mid-creation) detect the
    /// race and tear itself down, so the embed never lingers over another view.
    pub dd_embed_wanted: AtomicBool,
}

impl AppState {
    /// Create a new `AppState`.
    #[must_use]
    pub fn new(
        container: ServiceContainer,
        scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
    ) -> Self {
        Self {
            container,
            pending_approvals: Arc::new(PendingApprovals::default()),
            scheduler,
            dd_embed_wanted: AtomicBool::new(false),
        }
    }
}
