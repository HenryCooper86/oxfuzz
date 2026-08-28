//! Container construction, bootstrap, accessors, and teardown.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::error::ClassifiedError;
use hf_core::provider::ProviderPool;
use hf_core::runtime::RuntimeAdapter;
use hf_guardrails::Guardrails;
use hf_storage::{RunStatus, Store};
use uuid::Uuid;

#[cfg(feature = "semgrep-enrichment")]
use super::acquire_semgrep_project_lease;
use super::guards::{spawn_provider_health_checks, AgentTurnGuard};
use super::project_identity::project_lookup_identity;
#[cfg(feature = "semgrep-enrichment")]
use super::workspace::initialize_workspace_root;
use super::workspace::{configured_workspace_root, project_workspace_dir, workspace_root};
use super::{
    build_cost_map, build_session_managers, provider_pool_from_config, provider_pool_from_env,
    runtime_from_env, PersistenceAvailability, ServiceContainer,
};

impl ServiceContainer {
    /// Create a new `ServiceContainer` without persistence.
    #[must_use]
    pub fn new(
        runtime: Arc<dyn RuntimeAdapter>,
        provider_pool: Option<Arc<dyn ProviderPool>>,
    ) -> Self {
        Self {
            runtime,
            provider_pool: Arc::new(std::sync::RwLock::new(provider_pool)),
            store: None,
            persistence_availability: PersistenceAvailability::NotConfigured,
            session_manager: None,
            checkpoint_manager: None,
            guardrails: Guardrails::permissive(),
            diagnostics: Arc::new(crate::diagnostics::DiagnosticsRecorder::new(
                build_cost_map(),
            )),
            run_journal: Arc::new(crate::recovery::RunJournal::in_memory()),
            #[cfg(feature = "semgrep-enrichment")]
            semgrep: Arc::new(crate::semgrep::SemgrepCoordinator::in_memory()),
            active_runs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            active_agents: Arc::new(std::sync::Mutex::new(Vec::new())),
            session_turn_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            scheduler_events: Arc::new(std::sync::Mutex::new(None)),
            _health_task: None,
        }
    }

    /// Create a non-persistent container backed by the stub runtime.
    ///
    /// Intended for presentation-layer tests and health checks that need the
    /// service API surface without Docker, an LLM provider, or a database.
    #[must_use]
    pub fn stubbed() -> Self {
        Self::new(Arc::new(hf_runtime::StubRuntime), None)
    }

    /// The LLM cost/trace diagnostics recorder for this session.
    #[must_use]
    pub fn diagnostics(&self) -> &Arc<crate::diagnostics::DiagnosticsRecorder> {
        &self.diagnostics
    }

    /// Attach a persistence store (and the session manager derived from it),
    /// returning the updated container.
    #[must_use]
    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        let (sessions, checkpoints) = build_session_managers(&store);
        self.session_manager = Some(sessions);
        self.checkpoint_manager = Some(checkpoints);
        self.store = Some(store);
        self.persistence_availability = PersistenceAvailability::Available;
        self
    }

    /// Connect persistence at an explicit path and attach it to this container.
    ///
    /// This keeps embedding and presentation tests on the service boundary
    /// without exposing the infrastructure store type in their manifests.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError::Storage`] when the database cannot be
    /// opened or migrated.
    pub async fn with_store_path(self, path: PathBuf) -> Result<Self, ClassifiedError> {
        let store = Store::connect(path)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(self.with_store(Arc::new(store)))
    }

    /// The chat checkpoint manager (turn-level rollback), if a database is
    /// configured.
    #[must_use]
    pub fn checkpoint_manager(&self) -> Option<&Arc<hf_session::ChatCheckpointManager>> {
        self.checkpoint_manager.as_ref()
    }

    /// The conversation session manager (if a database is configured): the
    /// `hf-session` tree model with display + context transcripts.
    #[must_use]
    pub fn session_manager(&self) -> Option<&Arc<hf_session::SessionManager>> {
        self.session_manager.as_ref()
    }

    /// The lock serializing persistent chat operations on `session`, creating
    /// it on first use. Distinct sessions take distinct locks and are
    /// unaffected.
    #[must_use]
    pub fn session_turn_lock(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .session_turn_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(locks.entry(session.clone()).or_default())
    }

    /// Replace the guardrail engine (e.g. install an interactive HITL gate),
    /// returning the updated container.
    #[must_use]
    pub fn with_guardrails(mut self, guardrails: Guardrails) -> Self {
        self.guardrails = guardrails;
        self
    }

    /// Attach (or replace) the LLM provider pool, returning the updated
    /// container. Lets a command pick up a freshly-configured provider without
    /// an app restart.
    #[must_use]
    pub fn with_provider_pool(self, pool: Arc<dyn ProviderPool>) -> Self {
        // Recover a poisoned lock so the pool is installed rather than silently
        // dropped (see `reload_providers`).
        {
            let mut guard = self
                .provider_pool
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = Some(pool);
        }
        self
    }

    /// A container with no LLM provider, leaving this one untouched.
    ///
    /// The pool lives behind an `Arc<RwLock<..>>` shared by every clone, so that
    /// a Settings edit reaches every consumer without a restart. Clearing it
    /// through that cell would therefore disable the LLM for the whole process
    /// -- for every other request a running server is serving, not just this
    /// operation. The detached container gets its own cell instead, so the
    /// effect is operation-local, the same way `run_ci_gate` installs
    /// operation-local guardrails.
    ///
    /// Every LLM call site checks [`Self::provider_pool`] first and already has
    /// a no-provider path, so this is what makes "use no model" an exact
    /// guarantee across a composite flow rather than a flag threaded through
    /// each step and forgotten at one of them.
    #[must_use]
    pub fn without_provider_pool(&self) -> Self {
        let mut detached = self.clone();
        detached.provider_pool = Arc::new(std::sync::RwLock::new(None));
        detached
    }

    /// Reload the provider pool from the current on-disk config, swapping it in
    /// for every consumer of this container (and its clones) so Settings edits
    /// apply live without a restart. Returns `true` if a pool was loaded (i.e.
    /// the config has at least one enabled provider).
    pub fn reload_providers(&self) -> bool {
        // Mirror `bootstrap`'s config-or-env resolution: a provider configured
        // only via `HF_PROVIDER_API_KEY` must survive a Settings reload. Using
        // config alone here would swap in `None` and silently disable the LLM
        // (e.g. after saving an unrelated setting) until a restart.
        let pool = provider_pool_from_config().or_else(provider_pool_from_env);
        let loaded = pool.is_some();
        // Recover a poisoned lock rather than skipping the swap: dropping the
        // write on poison would keep the stale pool while still returning
        // `loaded = true`, so the caller (UI) believes a reload that never
        // happened succeeded.
        let mut guard = self
            .provider_pool
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = pool;
        loaded
    }

    /// The active guardrail engine.
    #[must_use]
    pub fn guardrails(&self) -> &Guardrails {
        &self.guardrails
    }

    /// Construct the canonical container used by every presentation layer
    /// (CLI, web, GUI): a Docker (or stub) runtime, an LLM provider pool from
    /// the environment, and the persistence store from `HF_DB_PATH`.
    ///
    /// Storage and the provider pool are optional: when unavailable the
    /// container still serves every non-persistent, non-LLM operation, so a
    /// missing database or API key degrades gracefully instead of failing.
    pub async fn bootstrap() -> Self {
        let runtime = runtime_from_env();
        let config_dir = crate::init::config_dir();
        let private_config_ready = crate::config::secure_config_directory(&config_dir).map_or_else(
            |error| {
                tracing::warn!(
                    "ignoring file-based providers because private config validation failed in {}: {error}",
                    config_dir.display()
                );
                false
            },
            |()| true,
        );
        // Prefer the GUI-managed config/providers.toml; fall back to env vars.
        let provider_pool = private_config_ready
            .then(provider_pool_from_config)
            .flatten()
            .or_else(provider_pool_from_env);
        let (store, persistence_availability) = match Store::connect_from_env().await {
            Ok(s) => (Some(Arc::new(s)), PersistenceAvailability::Available),
            Err(e) => {
                tracing::warn!("persistence disabled: {e}");
                (None, PersistenceAvailability::Unavailable)
            }
        };
        #[cfg(feature = "semgrep-enrichment")]
        let semgrep = Arc::new(crate::semgrep::SemgrepCoordinator::persistent(
            crate::init::user_app_dir().join("semgrep-journal"),
        ));
        #[cfg(feature = "semgrep-enrichment")]
        if let Some(store) = &store {
            match initialize_workspace_root() {
                Ok(workspace) => {
                    match crate::semgrep::recover_semgrep_at_bootstrap(store, &semgrep, &workspace)
                        .await
                    {
                        Ok(crate::semgrep::StartupRecoveryOutcome::Recovered) => {}
                        Ok(crate::semgrep::StartupRecoveryOutcome::Deferred) => {
                            tracing::warn!(
                                failure_code = "semgrep_recovery_deferred",
                                "Semgrep recovery is deferred while another workspace operation is active"
                            );
                        }
                        Err(_) => {
                            tracing::error!(
                                failure_code = "semgrep_recovery_degraded",
                                "Semgrep recovery is degraded"
                            );
                        }
                    }
                }
                Err(error) => {
                    semgrep.mark_recovery_degraded(&error);
                    tracing::error!(
                        failure_code = "semgrep_recovery_workspace_degraded",
                        "Semgrep recovery workspace is degraded"
                    );
                }
            }
        }
        let (session_manager, checkpoint_manager) = match store.as_ref().map(build_session_managers)
        {
            Some((sessions, checkpoints)) => (Some(sessions), Some(checkpoints)),
            None => (None, None),
        };
        // Open the persistent run journal and detect runs interrupted by a prior
        // crash/quit (scopes opened but never closed). Reconcile the DB so those
        // runs are not left stuck as `Running` forever.
        let run_journal = Arc::new(crate::recovery::RunJournal::open(
            crate::init::user_app_dir().join("run_journal.jsonl"),
        ));
        if let Some(store) = &store {
            for run in run_journal.interrupted() {
                let id = match run.run_id.parse::<Uuid>() {
                    Ok(id) => id,
                    Err(error) => {
                        tracing::error!(
                            run_id = %run.run_id,
                            %error,
                            "cannot repair interrupted run with an invalid id"
                        );
                        continue;
                    }
                };
                if let Err(error) = store
                    .set_run_status(id, RunStatus::Failed, Some(Utc::now()))
                    .await
                {
                    tracing::error!(run_id = %id, %error, "failed to repair interrupted run status");
                }
            }
        }
        // Patch-to-Proof: a `running` remediation operation has no live sandbox
        // workflow after a restart. Fail it closed to `inconclusive` so it is
        // never stuck `running` forever. Best-effort: a failure is logged and
        // never blocks startup.
        #[cfg(feature = "patch-to-proof")]
        if let Some(store) = &store {
            match store.recover_interrupted_remediations(Utc::now()).await {
                Ok(affected) if affected > 0 => {
                    tracing::info!(
                        affected,
                        "marked interrupted remediation operations inconclusive after restart"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "could not recover interrupted remediation operations"
                    );
                }
            }
        }
        // Persist diagnostics to the database when one is configured, so LLM
        // cost/usage accumulates across restarts; otherwise keep it in-memory.
        let diagnostics = Arc::new(match &store {
            Some(store) => crate::diagnostics::DiagnosticsRecorder::with_store(
                build_cost_map(),
                Arc::new(hf_diagnostics::SqliteTraceStore::new(store.pool().clone())),
            ),
            None => crate::diagnostics::DiagnosticsRecorder::new(build_cost_map()),
        });
        let provider_pool = Arc::new(std::sync::RwLock::new(provider_pool));
        // Recover frozen providers (including permanent freezes, which have no
        // auto-thaw) on the pool's configured health-check cadence. The guard
        // is stored on the container so the task dies with it.
        let health_task = Arc::new(spawn_provider_health_checks(Arc::clone(&provider_pool)));
        Self {
            runtime,
            provider_pool,
            store,
            persistence_availability,
            session_manager,
            guardrails: Guardrails::from_env(),
            checkpoint_manager,
            diagnostics,
            run_journal,
            #[cfg(feature = "semgrep-enrichment")]
            semgrep,
            active_runs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            active_agents: Arc::new(std::sync::Mutex::new(Vec::new())),
            session_turn_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            scheduler_events: Arc::new(std::sync::Mutex::new(None)),
            _health_task: Some(health_task),
        }
    }

    /// The current provider pool (if an LLM is configured). Returns an owned
    /// handle snapshotted from the swappable cell, so a concurrent
    /// [`Self::reload_providers`] never invalidates it mid-use.
    #[must_use]
    pub fn provider_pool(&self) -> Option<Arc<dyn ProviderPool>> {
        self.provider_pool.read().ok().and_then(|g| g.clone())
    }

    /// The persistence store (if a database is configured).
    #[must_use]
    pub fn store(&self) -> Option<&Arc<Store>> {
        self.store.as_ref()
    }

    pub(crate) const fn persistence_availability(&self) -> PersistenceAvailability {
        self.persistence_availability
    }

    #[cfg(test)]
    pub(crate) fn with_unavailable_store_for_test(mut self) -> Self {
        self.store = None;
        self.persistence_availability = PersistenceAvailability::Unavailable;
        self
    }

    /// Clear all learned knowledge across every project: discovered targets and
    /// their harnesses, corpus entries, and crashes, plus all runs.
    /// Configuration and on-disk workspaces are left untouched. A no-op when no
    /// store is configured.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the delete fails.
    pub async fn clear_knowledge(&self) -> Result<(), ClassifiedError> {
        if let Some(store) = &self.store {
            let workspace = workspace_root();
            let _workspace_cleanup = Self::try_acquire_workspace_cleanup(&workspace)?;
            store
                .clear_knowledge()
                .await
                .map_err(|e| ClassifiedError::Internal(format!("clear knowledge: {e}")))?;
        }
        Ok(())
    }

    /// Delete every trace of a single project: its persisted records (targets,
    /// runs, harnesses, corpus entries, crashes) and its on-disk workspace
    /// (compiled harnesses, corpora, crash reproducers, coverage builds). Other
    /// projects are untouched. The DB delete and the disk delete are done
    /// together so a project never lingers in one place after being cleared from
    /// the other. A no-op when no store is configured.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if either the DB delete or the workspace
    /// removal fails.
    pub async fn delete_project(&self, project: &Path) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        // The DB stores canonical project roots (discovery/run inserts go through
        // `canonical_project_root`), and the on-disk workspace slug canonicalizes
        // too. Delete both halves under one canonical identity so a raw, symlinked,
        // or trailing-slash caller path can never wipe the disk while orphaning the
        // DB rows (e.g. `/tmp/p` vs the stored `/private/tmp/p` on macOS).
        let identity = project_lookup_identity(project);
        #[cfg(feature = "semgrep-enrichment")]
        let _semgrep_project = acquire_semgrep_project_lease(&identity)?;
        if let Some(store) = &self.store {
            let key = identity.to_string_lossy();
            store
                .delete_project(&key)
                .await
                .map_err(|e| ClassifiedError::Internal(format!("delete project: {e}")))?;
        }
        let dir = project_workspace_dir(&identity);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            // Already absent is success -- nothing on disk to reclaim.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ClassifiedError::Internal(format!(
                    "delete project workspace {}: {e}",
                    dir.display()
                )));
            }
        }
        Ok(())
    }

    /// Register an executing agent turn labelled `label` (e.g. the agent id) so
    /// the Observability panel reflects live activity. The turn stays tracked
    /// until the returned [`AgentTurnGuard`] is dropped.
    pub fn track_agent(&self, label: &str) -> AgentTurnGuard {
        if let Ok(mut agents) = self.active_agents.lock() {
            agents.push(label.to_owned());
        }
        AgentTurnGuard {
            active_agents: Arc::clone(&self.active_agents),
            label: label.to_owned(),
        }
    }

    /// Delete every on-disk fuzz workspace (compiled harnesses, corpora, crash
    /// reproducers, coverage builds), reclaiming disk space. Since the
    /// workspace is now persistent, it grows over time; this is the affordance
    /// to reset it. Persistent DB records (targets, runs, crashes) are left
    /// intact -- re-running a campaign rebuilds the workspace on disk.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the workspace directory cannot be removed.
    pub fn clear_workspace(&self) -> Result<(), ClassifiedError> {
        let (root, uses_trusted_default) = configured_workspace_root();
        self.clear_workspace_at_with_adoption(&root, uses_trusted_default)
    }
}
