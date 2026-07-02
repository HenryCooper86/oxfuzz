//! Central dependency container -- shared by all presentation layers.
//!
//! Mirrors the `y-service::ServiceContainer` pattern: the GUI, CLI, and
//! web API all construct one container and call service methods through it.
//! This keeps business logic out of presentation crates (AGENTS.md 2.9) and
//! ensures every build / fuzz run goes through `hf-runtime` sandboxing
//! (AGENTS.md 2.12).

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessDraft, HarnessStatus, SmokeRunSummary};
use hf_core::provider::ProviderPool;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{Sanitizer, TargetCandidate, TargetInventory, TargetLanguage};
use hf_guardrails::{Action, Guardrails};
use hf_runtime::{RuntimeConfig, SANDBOX_IMAGE};
use hf_storage::{RunRecord, RunStatus, Store};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Workspace resolution
// ---------------------------------------------------------------------------

/// The base directory that holds every per-project fuzz workspace.
///
/// Persistent by default so compiled harnesses, corpora, and crash reproducers
/// survive across sessions. It previously lived under `std::env::temp_dir()`,
/// which macOS (`/var/folders/.../T`) and Linux (`/tmp`) purge after a few days
/// -- silently deleting a campaign's artifacts and producing the confusing
/// "compiled harness not found" state after a successful compile. It now lives
/// under the same stable per-user directory as the database and run journal
/// ([`crate::init::user_app_dir`]).
///
/// Override with the `HF_WORKSPACE_DIR` environment variable to place
/// workspaces on a specific volume (e.g. a large scratch disk).
#[must_use]
pub fn workspace_root() -> PathBuf {
    workspace_root_from(std::env::var_os("HF_WORKSPACE_DIR"))
}

/// Pure resolver for [`workspace_root`], taking the `HF_WORKSPACE_DIR` value
/// explicitly so it can be tested without mutating global process env (which
/// races under the parallel test runner).
fn workspace_root_from(override_dir: Option<std::ffi::OsString>) -> PathBuf {
    if let Some(dir) = override_dir {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    crate::init::user_app_dir().join("workspaces")
}

/// Resolve a per-project/per-target workspace directory so multiple projects
/// do not collide.
///
/// `<workspace_root>/<project_name>/<target>`
///
/// `target` is untrusted (it flows in from the CLI/REST/GUI), so it is
/// sanitised before use: only `Normal` path components are kept, dropping any
/// root, prefix, or `..` segment. This guarantees the result always stays
/// within the per-project base directory, satisfying the sandbox boundary in
/// AGENTS.md 2.12 (untrusted inputs never touch the host FS outside the
/// workspace).
#[must_use]
pub fn workspace_dir(project: &Path, target: &str) -> PathBuf {
    let name = project
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");
    workspace_root().join(name).join(sanitize_target(target))
}

/// Whether the in-container qemu for a syzkaller run can use KVM hardware
/// acceleration. Requires a Linux host with `/dev/kvm`, and that the sandbox
/// arch matches the host arch (KVM cannot accelerate a foreign architecture).
/// On macOS/Windows the Docker VM does not expose nested KVM, so this is always
/// false and qemu falls back to slow TCG emulation.
fn syz_kvm_usable(platform: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        hf_runtime::norm_platform(platform) == hf_runtime::host_platform()
            && Path::new("/dev/kvm").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = platform;
        false
    }
}

/// Reduce an untrusted `target` to a path that cannot escape its parent
/// directory. Keeps only `Normal` components (so `..`, absolute roots, and
/// Windows prefixes are discarded) and falls back to `default` when nothing
/// safe remains.
fn sanitize_target(target: &str) -> PathBuf {
    use std::path::Component;
    let safe: PathBuf = Path::new(target)
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    if safe.as_os_str().is_empty() {
        PathBuf::from("default")
    } else {
        safe
    }
}

// ---------------------------------------------------------------------------
// Seed generation
// ---------------------------------------------------------------------------

/// Generate target-aware seed inputs for a corpus.
#[must_use]
pub fn generate_target_seeds(target: &str) -> Vec<(Vec<u8>, String)> {
    let lower = target.to_ascii_lowercase();
    if lower.contains("json") || lower.contains("parse") {
        vec![
            (b"{}".to_vec(), "seed_empty_obj".to_owned()),
            (b"[]".to_vec(), "seed_empty_arr".to_owned()),
            (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
            (b"\"hello\"".to_vec(), "seed_string".to_owned()),
            (b"true".to_vec(), "seed_bool".to_owned()),
            (b"null".to_vec(), "seed_null".to_owned()),
            (b"42".to_vec(), "seed_number".to_owned()),
            (b"{\"key\":\"value\"}".to_vec(), "seed_object".to_owned()),
            (b"{\"nested\":{\"a\":1}}".to_vec(), "seed_nested".to_owned()),
            (b"\"".to_vec(), "seed_truncated_string".to_owned()),
            (b"[".to_vec(), "seed_truncated_array".to_owned()),
            (b"{".to_vec(), "seed_truncated_object".to_owned()),
        ]
    } else if lower.contains("xml") {
        vec![
            (b"<root/>".to_vec(), "seed_empty_xml".to_owned()),
            (b"<root>text</root>".to_vec(), "seed_simple_xml".to_owned()),
            (b"<a><b/></a>".to_vec(), "seed_nested_xml".to_owned()),
        ]
    } else if lower.contains("csv") {
        vec![
            (b"a,b,c\n1,2,3\n".to_vec(), "seed_simple_csv".to_owned()),
            (
                b"\"quoted\",\"fields\"\n".to_vec(),
                "seed_quoted_csv".to_owned(),
            ),
        ]
    } else {
        vec![
            (b"\x00".to_vec(), "seed_null_byte".to_owned()),
            (b"\xff".to_vec(), "seed_high_byte".to_owned()),
            (b"AAAA".to_vec(), "seed_repeated".to_owned()),
            ("".as_bytes().to_vec(), "seed_empty".to_owned()),
            (b"test".to_vec(), "seed_ascii".to_owned()),
        ]
    }
}

/// Map a host path inside the workspace to its container path under `/work`
/// (the mount point), falling back to `/work/out/<filename>`.
fn container_input_path(workspace: &Path, host_path: &Path) -> String {
    host_path.strip_prefix(workspace).map_or_else(
        |_| {
            format!(
                "/work/out/{}",
                host_path.file_name().unwrap_or_default().to_string_lossy()
            )
        },
        |rel| format!("/work/{}", rel.display()),
    )
}

/// Copy likely crash inputs from a fuzzer `out` dir into a clean staging dir,
/// skipping coverage maps and sanitizer logs that engines interleave there.
/// Returns the number of inputs staged.
/// Extensions and name fragments that are engine bookkeeping, never crash
/// inputs (coverage maps, logs, sanitizer dumps, fuzzer stats).
fn is_crash_noise(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ext == "cov" || ext == "log" {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.contains("honggfuzz")
        || name.contains("sanitizer")
        || name.starts_with("hf.")
        || name == "fuzzer_stats"
}

fn stage_crash_inputs(out_dir: &Path, staging: &Path) -> usize {
    if std::fs::create_dir_all(staging).is_err() {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(out_dir) else {
        return 0;
    };
    let mut staged = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_crash_noise(&path) {
            continue;
        }
        if std::fs::copy(&path, staging.join(name)).is_ok() {
            staged += 1;
        }
    }
    staged
}

/// Collect crash input file paths from a run output directory, skipping engine
/// bookkeeping. Looks both at the top level (flat-output engines) and one level
/// down under `<instance>/crashes/` (AFL++ output layout).
fn collect_crash_inputs(out_dir: &Path) -> Vec<PathBuf> {
    let mut inputs = Vec::new();
    let push_files = |dir: &Path, inputs: &mut Vec<PathBuf>| {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && !is_crash_noise(&path) {
                    inputs.push(path);
                }
            }
        }
    };
    push_files(out_dir, &mut inputs);
    // AFL++ nests crashes under out/<instance>/crashes/.
    if let Ok(entries) = std::fs::read_dir(out_dir) {
        for entry in entries.flatten() {
            let crashes = entry.path().join("crashes");
            if crashes.is_dir() {
                push_files(&crashes, &mut inputs);
            }
        }
    }
    inputs
}

/// Cache value: the signature the covered set was computed for + the set.
type CoverageCache = std::sync::Mutex<std::collections::HashMap<String, (u64, Vec<String>)>>;

/// Process-global cache of covered-function sets, keyed by `project::target`,
/// each tagged with the corpus+harness signature it was computed for.
fn coverage_cache() -> &'static CoverageCache {
    static CACHE: std::sync::OnceLock<CoverageCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Cache value: the signature the summary was computed for + the summary.
type SummaryCache =
    std::sync::Mutex<std::collections::HashMap<String, (u64, hf_coverage::CoverageSummary)>>;

/// Process-global cache of line/region coverage summaries, keyed by
/// `project::target`, invalidated by the same corpus+harness signature.
fn summary_cache() -> &'static SummaryCache {
    static CACHE: std::sync::OnceLock<SummaryCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// A cheap fingerprint of the inputs that affect coverage: the corpus file count
/// and the latest mtime across the corpus and `harness.c`. Changes when a run
/// grows the corpus or the harness is rebuilt, invalidating the cache.
fn coverage_signature(workspace: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::time::UNIX_EPOCH;

    let mtime_secs = |meta: &std::fs::Metadata| -> u64 {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs())
    };

    let mut count = 0u64;
    let mut max_mtime = 0u64;
    if let Ok(entries) = std::fs::read_dir(workspace.join("corpus")) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                count += 1;
                max_mtime = max_mtime.max(mtime_secs(&meta));
            }
        }
    }
    if let Ok(meta) = std::fs::metadata(workspace.join("harness.c")) {
        max_mtime = max_mtime.max(mtime_secs(&meta));
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    count.hash(&mut hasher);
    max_mtime.hash(&mut hasher);
    hasher.finish()
}

/// Parse `llvm-cov export` JSON, returning the names of functions with a
/// non-zero execution count (the covered set).
fn parse_covered_functions(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut covered: Vec<String> = value
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|d| d.get("functions"))
        .and_then(serde_json::Value::as_array)
        .map(|funcs| {
            funcs
                .iter()
                .filter(|f| {
                    f.get("count")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                        > 0
                })
                .filter_map(|f| {
                    f.get("name")
                        .and_then(|n| n.as_str())
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    covered.sort();
    covered.dedup();
    covered
}

/// Recursively collect and parse every `.casrep` report under `dir`.
/// Collapse crashes that CASR placed in the same cluster to one representative
/// (the first seen). Crashes without a cluster id pass through unchanged, so
/// this only ever tightens dedup, never loses an un-clustered crash.
fn bucket_by_cluster(crashes: Vec<hf_core::crash::Crash>) -> Vec<hf_core::crash::Crash> {
    let mut seen_clusters = std::collections::HashSet::new();
    let mut kept = Vec::with_capacity(crashes.len());
    for crash in crashes {
        match crash.casr.as_ref().and_then(|c| c.cluster) {
            Some(cluster) if !seen_clusters.insert(cluster) => {} // duplicate cluster -> drop
            _ => kept.push(crash),
        }
    }
    kept
}

fn collect_casreps(dir: &Path) -> Vec<(PathBuf, hf_core::crash::CasrReport)> {
    let mut out = Vec::new();
    collect_casreps_into(dir, &mut out);
    out
}

fn collect_casreps_into(dir: &Path, out: &mut Vec<(PathBuf, hf_core::crash::CasrReport)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_casreps_into(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("casrep") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(mut report) = hf_crash::parse_casrep(&content) {
                    // CASR groups equivalent crashes into `cl<N>` dirs; carry the
                    // cluster id so triage can bucket by it.
                    report.cluster = hf_crash::cluster_from_path(&path);
                    out.push((path, report));
                }
            }
        }
    }
}

/// Map a `.casrep` path back to the crash input it analyzed: CASR names each
/// report after its input (`crash-abc.casrep` -> `crash-abc`), so the report's
/// file stem under `out` gives a clean input name for display. (The libFuzzer
/// path's input sits directly in `out`; the AFL path's lives deeper, but the
/// stem still carries the crash id.)
fn casrep_input_path(out_dir: &Path, casrep: &Path) -> PathBuf {
    casrep
        .file_stem()
        .and_then(|s| s.to_str())
        .map_or_else(|| casrep.to_path_buf(), |stem| out_dir.join(stem))
}

/// A stable crash id derived from its run, stack signature, and input file, so
/// re-triaging the same run replaces each crash row rather than inserting a new
/// one (the `crashes` table is keyed on `id`; a fresh random UUID per triage
/// pass would accumulate identical duplicate rows). The input filename keeps
/// distinct crashes apart even when they share (or lack) a signature.
fn deterministic_crash_id(run_id: Uuid, signature: &str, input: &Path) -> Uuid {
    let file = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let name = format!("{run_id}|{signature}|{file}");
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes())
}

/// Copy C/C++ source and header files from a project into the workspace
/// so the sandbox can compile the harness + target together.
pub fn copy_project_sources(project: &Path, workspace: &Path) {
    let exts = ["c", "h", "cc", "cpp", "cxx", "hpp"];
    if let Ok(entries) = std::fs::read_dir(project) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if exts.contains(&ext) {
                    let dest = workspace.join(entry.file_name());
                    if let Err(e) = std::fs::copy(&path, &dest) {
                        // Not fatal on its own, but a missing source surfaces
                        // later as a confusing compile error -- surface it here.
                        tracing::warn!(
                            "failed to copy source {} into workspace: {e}",
                            path.display()
                        );
                    }
                }
            }
        }
    }
}

/// Build the sandbox image from the repo's Dockerfile for a given platform.
///
/// # Errors
/// Returns `ClassifiedError::Internal` if the `docker build` command fails.
pub fn build_sandbox_image(root: &Path, platform: &str) -> Result<(), ClassifiedError> {
    let status = std::process::Command::new(hf_runtime::docker_bin())
        .current_dir(root)
        .args([
            "build",
            "--platform",
            platform,
            "-t",
            SANDBOX_IMAGE,
            "-f",
            "docker/sandbox/Dockerfile",
            ".",
        ])
        .status()
        .map_err(|e| ClassifiedError::Internal(format!("docker build: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ClassifiedError::Internal("docker build failed".to_owned()))
    }
}

/// Walk up from the current dir and the executable path looking for the repo
/// root (the directory that contains `docker/sandbox/Dockerfile`).
pub fn repo_root() -> Option<PathBuf> {
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(dir) = std::env::current_dir() {
        starts.push(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        starts.push(exe);
    }
    for start in starts {
        let mut cur: Option<&Path> = Some(start.as_path());
        while let Some(p) = cur {
            if p.join("Cargo.toml").is_file() && p.join("config").is_dir() {
                return Some(p.to_path_buf());
            }
            cur = p.parent();
        }
    }
    None
}

/// RAII guard that keeps an agent turn registered in the container's
/// `active_agents` list for its lifetime, removing it on drop (even if the turn
/// panics or is cancelled). Returned by [`ServiceContainer::track_agent`].
#[must_use = "the agent turn is only tracked while this guard is alive"]
pub struct AgentTurnGuard {
    active_agents: Arc<std::sync::Mutex<Vec<String>>>,
    label: String,
}

impl Drop for AgentTurnGuard {
    fn drop(&mut self) {
        if let Ok(mut agents) = self.active_agents.lock() {
            if let Some(pos) = agents.iter().position(|a| a == &self.label) {
                agents.remove(pos);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceContainer
// ---------------------------------------------------------------------------

/// All wired application services, constructed from a runtime + optional
/// provider pool.
///
/// The container is `Clone` (it wraps `Arc`) so Tauri commands can capture
/// it by value.
#[derive(Clone)]
pub struct ServiceContainer {
    runtime: Arc<dyn RuntimeAdapter>,
    /// The LLM provider pool, held in a shared swappable cell so it can be
    /// reloaded from config at runtime ([`Self::reload_providers`]) and the new
    /// pool is seen by every clone of this container (and thus every consumer)
    /// without a restart.
    provider_pool: Arc<std::sync::RwLock<Option<Arc<dyn ProviderPool>>>>,
    store: Option<Arc<Store>>,
    session_manager: Option<Arc<hf_session::SessionManager>>,
    checkpoint_manager: Option<Arc<hf_session::ChatCheckpointManager>>,
    guardrails: Guardrails,
    diagnostics: Arc<crate::diagnostics::DiagnosticsRecorder>,
    run_journal: Arc<crate::recovery::RunJournal>,
    /// Cancellation tokens for in-flight fuzz runs, keyed by run id. A run
    /// registers its token on start and removes it on completion;
    /// [`Self::cancel_run`] fires the token to stop the run cooperatively.
    active_runs: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, CancellationToken>>>,
    /// Labels of agent turns currently executing, so the Observability panel can
    /// show live agent activity instead of always "No active agent instances".
    /// A turn registers via [`Self::track_agent`] and is removed when the
    /// returned guard drops. Shared across clones of this container.
    active_agents: Arc<std::sync::Mutex<Vec<String>>>,
}

/// RAII guard that removes a run's cancellation token from the active-runs map
/// on drop, so the entry cannot leak if the `run_fuzzer` future is
/// dropped/aborted rather than returning normally (which would otherwise leave
/// a phantom run that `active_run_ids` reports and `cancel_run` can never clear).
struct ActiveRunGuard {
    active_runs: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, CancellationToken>>>,
    run_id: Uuid,
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.remove(&self.run_id);
        }
    }
}

/// Build the per-model cost table (`model -> (per-1k-in, per-1k-out)`) from the
/// configured providers, for LLM cost diagnostics.
fn build_cost_map() -> std::collections::HashMap<String, (f64, f64)> {
    crate::config::get_providers()
        .into_iter()
        .map(|p| (p.model, (p.cost_per_1k_input, p.cost_per_1k_output)))
        .collect()
}

/// Build the `hf-session` managers over a database store: the [`SessionManager`]
/// (`SQLite` session tree + `JSONL` display/context transcripts) and a
/// [`ChatCheckpointManager`] sharing the same stores for turn-level rollback
/// (checkpoints are in-memory -- a session-lifetime undo buffer).
///
/// [`SessionManager`]: hf_session::SessionManager
/// [`ChatCheckpointManager`]: hf_session::ChatCheckpointManager
fn build_session_managers(
    store: &Arc<Store>,
) -> (
    Arc<hf_session::SessionManager>,
    Arc<hf_session::ChatCheckpointManager>,
) {
    use hf_core::session::{
        ChatCheckpointStore, DisplayTranscriptStore, SessionStore, TranscriptStore,
    };

    let base = crate::init::user_app_dir().join("transcripts");
    let session_store: Arc<dyn SessionStore> =
        Arc::new(hf_storage::SqliteSessionStore::new(store.pool().clone()));
    let transcript: Arc<dyn TranscriptStore> =
        Arc::new(hf_storage::JsonlTranscriptStore::new(base.join("context")));
    let display: Arc<dyn DisplayTranscriptStore> = Arc::new(
        hf_storage::JsonlDisplayTranscriptStore::new(base.join("display")),
    );
    let checkpoint_store: Arc<dyn ChatCheckpointStore> =
        Arc::new(crate::checkpoints::InMemoryChatCheckpointStore::default());

    let manager = Arc::new(hf_session::SessionManager::new(
        Arc::clone(&session_store),
        Arc::clone(&transcript),
        Arc::clone(&display),
        hf_session::SessionConfig::default(),
    ));
    let checkpoints = Arc::new(hf_session::ChatCheckpointManager::new(
        transcript,
        display,
        checkpoint_store,
        session_store,
    ));
    (manager, checkpoints)
}

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
            session_manager: None,
            checkpoint_manager: None,
            guardrails: Guardrails::permissive(),
            diagnostics: Arc::new(crate::diagnostics::DiagnosticsRecorder::new(
                build_cost_map(),
            )),
            run_journal: Arc::new(crate::recovery::RunJournal::in_memory()),
            active_runs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            active_agents: Arc::new(std::sync::Mutex::new(Vec::new())),
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

    /// Runs interrupted by an app crash/quit, awaiting recovery.
    #[must_use]
    pub fn interrupted_runs(&self) -> Vec<crate::recovery::InterruptedRun> {
        self.run_journal.interrupted()
    }

    /// Dismiss an interrupted run from the recovery list.
    pub fn dismiss_interrupted_run(&self, run_id: &str) {
        self.run_journal.dismiss(run_id);
    }

    /// Aggregated LLM cost/usage recorded this session.
    pub async fn cost_summary(&self) -> crate::diagnostics::CostSummary {
        self.diagnostics.summary().await
    }

    /// Attach a persistence store (and the session manager derived from it),
    /// returning the updated container.
    #[must_use]
    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        let (sessions, checkpoints) = build_session_managers(&store);
        self.session_manager = Some(sessions);
        self.checkpoint_manager = Some(checkpoints);
        self.store = Some(store);
        self
    }

    /// The chat checkpoint manager (turn-level rollback), if a database is
    /// configured.
    #[must_use]
    pub fn checkpoint_manager(&self) -> Option<&Arc<hf_session::ChatCheckpointManager>> {
        self.checkpoint_manager.as_ref()
    }

    /// Create a turn checkpoint recording the transcript length before this
    /// turn (so a later rollback restores the pre-turn state). Best-effort.
    pub async fn chat_create_checkpoint(
        &self,
        session: &hf_core::types::SessionId,
        message_count_before: u32,
    ) {
        if let Some(manager) = &self.checkpoint_manager {
            let turn = manager.current_turn(session).await.unwrap_or(0) + 1;
            if let Err(e) = manager
                .create_checkpoint(
                    session,
                    turn,
                    message_count_before,
                    Uuid::new_v4().to_string(),
                )
                .await
            {
                tracing::warn!("chat checkpoint create failed: {e}");
            }
        }
    }

    /// Roll back the most recent chat turn, truncating the transcript. Returns
    /// the number of messages removed (0 if nothing to roll back).
    pub async fn chat_rollback_last(&self, session: &hf_core::types::SessionId) -> usize {
        if let Some(manager) = &self.checkpoint_manager {
            match manager.rollback_last(session).await {
                Ok(result) => return result.messages_removed,
                Err(e) => tracing::warn!("chat rollback failed: {e}"),
            }
        }
        0
    }

    /// List the (still-valid) per-turn checkpoints for a session, each with a
    /// preview of the user message that started the turn.
    pub async fn chat_checkpoints(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Vec<crate::checkpoints::CheckpointView> {
        let (Some(checkpoints), Some(sessions)) = (&self.checkpoint_manager, &self.session_manager)
        else {
            return Vec::new();
        };
        let list = checkpoints
            .list_checkpoints(session)
            .await
            .unwrap_or_default();
        let transcript = sessions.read_transcript(session).await.unwrap_or_default();
        list.into_iter()
            .filter(|c| !c.invalidated)
            .map(|c| {
                let preview = transcript
                    .get(c.message_count_before as usize)
                    .map(|m| m.content.chars().take(80).collect())
                    .unwrap_or_default();
                crate::checkpoints::CheckpointView {
                    checkpoint_id: c.checkpoint_id,
                    turn_number: c.turn_number,
                    message_count_before: c.message_count_before,
                    preview,
                }
            })
            .collect()
    }

    /// Roll back to a specific checkpoint (removing that turn and everything
    /// after). Returns the number of messages removed.
    pub async fn chat_rollback_to(
        &self,
        session: &hf_core::types::SessionId,
        checkpoint_id: &str,
    ) -> usize {
        if let Some(manager) = &self.checkpoint_manager {
            match manager.rollback_to(session, checkpoint_id).await {
                Ok(result) => return result.messages_removed,
                Err(e) => tracing::warn!("chat rollback_to failed: {e}"),
            }
        }
        0
    }

    /// Fork a conversation: create a branch session off `parent`, copying the
    /// parent's transcript up to `fork_message_count` so the branch can diverge
    /// independently. Returns the new session id.
    pub async fn chat_branch(
        &self,
        parent: &hf_core::types::SessionId,
        fork_message_count: u32,
        title: Option<String>,
    ) -> Option<String> {
        let sessions = self.session_manager.as_ref()?;
        let branch = sessions.branch(parent, title).await.ok()?;
        let parent_transcript = sessions.read_transcript(parent).await.unwrap_or_default();
        for message in parent_transcript
            .into_iter()
            .take(fork_message_count as usize)
        {
            if let Err(e) = sessions.append_message(&branch.id, &message).await {
                tracing::warn!("branch copy failed: {e}");
            }
        }
        Some(branch.id.0)
    }

    /// The context transcript (LLM-facing messages) of a session, for loading a
    /// branch into the chat view.
    pub async fn chat_history(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Vec<hf_core::types::Message> {
        match &self.session_manager {
            Some(sessions) => sessions.read_transcript(session).await.unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Create a new top-level chat session, returning its id, or `None` when no
    /// database is configured. Shared by every presentation layer so session
    /// creation behaves identically (AGENTS.md 2.9).
    pub async fn create_chat_session(&self, title: Option<String>) -> Option<String> {
        let manager = self.session_manager.as_ref()?;
        manager
            .create_session(hf_core::session::CreateSessionOptions {
                parent_id: None,
                session_type: hf_core::session::SessionType::Main,
                agent_id: None,
                title: title.or_else(|| Some("Chat".to_owned())),
            })
            .await
            .ok()
            .map(|node| node.id.0)
    }

    /// All sessions in the same conversation tree as `session` (the main session
    /// plus every branch), for the branch switcher.
    pub async fn chat_branches(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Vec<crate::checkpoints::BranchView> {
        use hf_core::session::{SessionFilter, SessionType};
        let Some(sessions) = &self.session_manager else {
            return Vec::new();
        };
        let Ok(node) = sessions.get_session(session).await else {
            return Vec::new();
        };
        let filter = SessionFilter {
            root_id: Some(node.root_id.clone()),
            ..SessionFilter::default()
        };
        let mut nodes = sessions.list_sessions(&filter).await.unwrap_or_default();
        nodes.sort_by_key(|n| (n.depth, n.created_at));
        nodes
            .into_iter()
            .map(|n| {
                let is_main = n.session_type == SessionType::Main;
                let active = n.id == *session;
                crate::checkpoints::BranchView {
                    title: n.title.unwrap_or_else(|| {
                        if is_main {
                            "Main".to_owned()
                        } else {
                            format!("Branch (depth {})", n.depth)
                        }
                    }),
                    id: n.id.0,
                    depth: n.depth,
                    is_main,
                    active,
                }
            })
            .collect()
    }

    /// The conversation session manager (if a database is configured): the
    /// `hf-session` tree model with display + context transcripts.
    #[must_use]
    pub fn session_manager(&self) -> Option<&Arc<hf_session::SessionManager>> {
        self.session_manager.as_ref()
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
        if let Ok(mut guard) = self.provider_pool.write() {
            *guard = Some(pool);
        }
        self
    }

    /// Per-provider health/usage for the Observability panel: freeze state,
    /// in-flight and total requests, and error counts. Empty when no provider
    /// pool is configured.
    pub async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        match self.provider_pool() {
            Some(pool) => pool.provider_statuses().await,
            None => Vec::new(),
        }
    }

    /// A live system snapshot for the Observability panel: per-provider health
    /// and usage, the agent pool, and runtime memory counters. Merges live
    /// provider stats (concurrency/requests/errors) with the provider config
    /// (model/tags/limits) and cumulative diagnostics (tokens/cost by model).
    /// `agents.available_slots` is left for the caller to fill from the agent
    /// registry.
    pub async fn system_snapshot(&self) -> SystemSnapshot {
        let statuses = self.provider_statuses().await;
        let configs = crate::config::get_providers();
        let cost = self.diagnostics.summary().await;

        let providers = statuses
            .into_iter()
            .map(|s| {
                let cfg = configs.iter().find(|c| c.id == s.id.0);
                let model = cfg.map(|c| c.model.clone()).unwrap_or_default();
                let by_model = cost.by_model.iter().find(|m| m.model == model);
                #[allow(clippy::cast_precision_loss)]
                let error_rate = if s.total_requests > 0 {
                    s.total_errors as f64 / s.total_requests as f64
                } else {
                    0.0
                };
                ProviderSnapshot {
                    id: s.id.0,
                    model,
                    tags: cfg.map(|c| c.tags.clone()).unwrap_or_default(),
                    is_frozen: s.is_frozen,
                    active_requests: s.active_requests,
                    max_concurrency: cfg.map_or(0, |c| c.max_concurrency),
                    total_requests: s.total_requests,
                    total_errors: s.total_errors,
                    error_rate,
                    total_input_tokens: by_model.map_or(0, |m| m.input_tokens),
                    total_output_tokens: by_model.map_or(0, |m| m.output_tokens),
                    estimated_cost_usd: by_model.map_or(0.0, |m| m.cost_usd),
                }
            })
            .collect();

        let (targets, crashes) = if let Some(store) = &self.store {
            (
                store.list_all_targets().await.map_or(0, |t| t.len()),
                store.list_all_crashes().await.map_or(0, |c| c.len()),
            )
        } else {
            (0, 0)
        };
        let memory = MemorySnapshot {
            pending_runs: self.active_run_ids().len(),
            interrupted_runs: self.interrupted_runs().len(),
            llm_calls: cost.calls,
            targets,
            crashes,
        };

        SystemSnapshot {
            providers,
            agents: self.active_agent_pool(),
            memory,
        }
    }

    /// A cheap snapshot of a target's on-disk artifacts (compiled harness,
    /// corpus size, crash inputs) for the Info panel. Pure filesystem reads --
    /// no sandbox, no LLM.
    #[must_use]
    pub fn artifact_summary(&self, project: &Path, target: &str) -> ArtifactSummary {
        let workspace = workspace_dir(project, target);
        let harness_built = workspace.join(format!("fuzz_{target}")).exists();
        let corpus_count =
            hf_corpus::list(&workspace.join("corpus")).map_or(0, |c| c.entries.len());
        let crash_count = collect_crash_inputs(&workspace.join("out")).len();
        ArtifactSummary {
            harness_built,
            corpus_count,
            crash_count,
        }
    }

    /// Every crash persisted to the store, across all targets and runs.
    ///
    /// This is the correct source for a browse-all artifacts view: it returns
    /// crashes already ingested by triage regardless of which target's workspace
    /// they came from, rather than re-scanning a single (possibly wrong) target
    /// workspace. Returns an empty list when no database is configured.
    pub async fn all_crashes(&self) -> Vec<hf_core::crash::Crash> {
        match self.store.as_ref() {
            Some(store) => store.list_all_crashes().await.unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Every corpus entry persisted to the store, across all targets.
    ///
    /// The browse-all counterpart to [`Self::corpus_list`] (which is scoped to a
    /// single target's on-disk corpus). Returns an empty list when no database
    /// is configured.
    pub async fn all_corpus_entries(&self) -> Vec<hf_core::corpus::CorpusEntry> {
        match self.store.as_ref() {
            Some(store) => store.list_all_corpus_entries().await.unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Ingest a document into a project's knowledge base.
    ///
    /// Converts the file (PDF, Office, HTML, CSV, ...) to Markdown with
    /// `markitdown` inside the sandbox (offline; network-isolated), stores the
    /// Markdown under the per-project knowledge docs dir, and re-indexes the
    /// project so the harness-author and triage agents can search it (specs,
    /// RFCs, threat models). Returns the post-index stats.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the file is missing, the sandbox conversion
    /// fails, or the Markdown cannot be written.
    pub async fn ingest_document(
        &self,
        project: &Path,
        file: &Path,
    ) -> Result<crate::knowledge::KnowledgeStats, ClassifiedError> {
        if !file.is_file() {
            return Err(ClassifiedError::Validation(format!(
                "document not found: {}",
                file.display()
            )));
        }
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ClassifiedError::Validation("invalid document name".to_owned()))?;

        // Stage the document in a clean dir mounted as /work, then convert it.
        let docs = crate::knowledge::docs_dir(project);
        let staging = docs.join(".staging");
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir staging: {e}")))?;
        std::fs::copy(file, staging.join(name))
            .map_err(|e| ClassifiedError::Internal(format!("stage document: {e}")))?;

        let cmd = vec!["markitdown".to_owned(), format!("/work/{name}")];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 120,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let result = self.runtime.run_command(&cmd, &staging, &limits).await?;
        let _ = std::fs::remove_dir_all(&staging);
        if result.exit_code != 0 || result.stdout.trim().is_empty() {
            return Err(ClassifiedError::Internal(format!(
                "markitdown failed (exit {}): {}",
                result.exit_code,
                result.stderr.lines().last().unwrap_or_default()
            )));
        }

        // Persist the Markdown under the docs dir, then re-index.
        std::fs::create_dir_all(&docs)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir docs: {e}")))?;
        let stem = Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(name);
        std::fs::write(docs.join(format!("{stem}.md")), &result.stdout)
            .map_err(|e| ClassifiedError::Internal(format!("write doc markdown: {e}")))?;

        crate::knowledge::index_project(project)
    }

    /// Reload the provider pool from the current on-disk config, swapping it in
    /// for every consumer of this container (and its clones) so Settings edits
    /// apply live without a restart. Returns `true` if a pool was loaded (i.e.
    /// the config has at least one enabled provider).
    pub fn reload_providers(&self) -> bool {
        let pool = provider_pool_from_config();
        let loaded = pool.is_some();
        if let Ok(mut guard) = self.provider_pool.write() {
            *guard = pool;
        }
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
        // Prefer the GUI-managed config/providers.toml; fall back to env vars.
        let provider_pool = provider_pool_from_config().or_else(provider_pool_from_env);
        let store = match Store::connect_from_env().await {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                tracing::warn!("persistence disabled: {e}");
                None
            }
        };
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
                if let Ok(id) = run.run_id.parse::<Uuid>() {
                    let _ = store
                        .set_run_status(id, RunStatus::Failed, Some(Utc::now()))
                        .await;
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
        Self {
            runtime,
            provider_pool: Arc::new(std::sync::RwLock::new(provider_pool)),
            store,
            session_manager,
            guardrails: Guardrails::from_env(),
            checkpoint_manager,
            diagnostics,
            run_journal,
            active_runs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            active_agents: Arc::new(std::sync::Mutex::new(Vec::new())),
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

    /// Clear learned knowledge: all discovered targets, runs, and crashes.
    /// Corpus inputs on disk and configuration are left untouched. A no-op when
    /// no store is configured.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the delete fails.
    pub async fn clear_knowledge(&self) -> Result<(), ClassifiedError> {
        if let Some(store) = &self.store {
            store
                .clear_knowledge()
                .await
                .map_err(|e| ClassifiedError::Internal(format!("clear knowledge: {e}")))?;
        }
        Ok(())
    }

    /// Delete every on-disk fuzz workspace (compiled harnesses, corpora, crash
    /// reproducers, coverage builds), reclaiming disk space. Since the
    /// workspace is now persistent, it grows over time; this is the affordance
    /// to reset it. Persistent DB records (targets, runs, crashes) are left
    /// intact -- re-running a campaign rebuilds the workspace on disk.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the workspace directory cannot be removed.
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

    /// A snapshot of the agent turns currently executing.
    fn active_agent_pool(&self) -> AgentPoolSnapshot {
        let labels = self
            .active_agents
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default();
        let instances: Vec<AgentInstanceSnapshot> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| AgentInstanceSnapshot {
                instance_id: format!("turn-{i}"),
                agent_name: label.clone(),
                state: "running".to_owned(),
                elapsed_ms: 0,
                iterations: 0,
                tokens_used: 0,
            })
            .collect();
        AgentPoolSnapshot {
            active_instances: instances.len(),
            available_slots: 0,
            total_instances: instances.len(),
            instances,
        }
    }

    pub fn clear_workspace(&self) -> Result<(), ClassifiedError> {
        let root = workspace_root();
        match std::fs::remove_dir_all(&root) {
            Ok(()) => Ok(()),
            // Already absent is success -- nothing to reclaim.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ClassifiedError::Internal(format!(
                "clear workspace {}: {e}",
                root.display()
            ))),
        }
    }

    // -- Discovery --------------------------------------------------------

    /// Discover fuzzing targets in a project.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the project root cannot be read.
    pub async fn discover(
        &self,
        project: &Path,
        lang: TargetLanguage,
    ) -> Result<TargetInventory, ClassifiedError> {
        let inv = hf_discovery::discover(project, lang).await?;
        if let Some(store) = &self.store {
            if let Err(e) = store.save_inventory(&inv, Utc::now()).await {
                tracing::warn!("failed to persist target inventory: {e}");
            }
        }
        Ok(inv)
    }

    /// Re-rank a target inventory using the configured LLM provider pool.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Provider` if no provider is configured, or the
    /// underlying ranking error if the LLM call fails.
    pub async fn rank(
        &self,
        inventory: TargetInventory,
    ) -> Result<TargetInventory, ClassifiedError> {
        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for ranking".to_owned())
        })?;
        let bridge =
            LlmProviderBridge::new(pool).with_diagnostics(Arc::clone(&self.diagnostics), "rank");
        let ranked = hf_discovery::rank(inventory, Box::new(bridge)).await?;
        if let Some(store) = &self.store {
            if let Err(e) = store.save_inventory(&ranked, Utc::now()).await {
                tracing::warn!("failed to persist ranked inventory: {e}");
            }
        }
        Ok(ranked)
    }

    // -- Harness ----------------------------------------------------------

    /// Draft a harness for a target using the LLM provider pool.
    ///
    /// Falls back to a heuristic template when no provider is configured so
    /// the GUI still produces a draft without an API key.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the LLM call fails or the target is not
    /// found.
    pub async fn harness_draft(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<HarnessDraft, ClassifiedError> {
        let inv = self.discover(project, lang).await?;
        let candidate = inv
            .candidates
            .iter()
            .find(|c| c.symbol == target)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            match hf_harness::draft(&candidate, engine, Box::new(provider)).await {
                Ok(draft) => Ok(draft),
                // The LLM is configured but the call failed (provider down, auth,
                // bad model, network). Degrade to the heuristic draft so the
                // pipeline still produces a usable harness instead of dead-ending
                // on a red error; the warning makes the LLM failure visible.
                Err(e) => {
                    tracing::warn!(
                        "LLM harness draft for '{target}' failed ({e}); \
                         falling back to heuristic draft"
                    );
                    Ok(heuristic_draft(&candidate, engine))
                }
            }
        } else {
            // No LLM configured: generate a heuristic draft so the GUI still
            // produces something useful.
            Ok(heuristic_draft(&candidate, engine))
        }
    }

    /// Resolve a target symbol to its discovered candidate id, falling back to
    /// the nil UUID when discovery fails or the symbol is unknown. Shared by
    /// harness compilation and triage so persisted records key off the same id.
    async fn resolve_target_id(&self, project: &Path, target: &str, lang: TargetLanguage) -> Uuid {
        self.discover(project, lang)
            .await
            .ok()
            .and_then(|inv| {
                inv.candidates
                    .iter()
                    .find(|c| c.symbol == target)
                    .map(|c| c.id)
            })
            .unwrap_or_default()
    }

    /// Persist corpus entries for a target so the Corpus view and later runs
    /// survive restarts (best-effort; a store failure only logs).
    async fn persist_corpus(&self, target_id: Uuid, corpus: &hf_core::corpus::Corpus) {
        let Some(store) = &self.store else { return };
        for entry in &corpus.entries {
            if let Err(e) = store.upsert_corpus_entry(target_id, entry).await {
                tracing::warn!("failed to persist corpus entry {}: {e}", entry.sha256);
            }
        }
    }

    /// Compile a harness in the sandbox via `hf-runtime`.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the build command fails.
    pub async fn harness_compile(
        &self,
        source: String,
        project: &Path,
        engine: EngineKind,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<CompileOutcome, ClassifiedError> {
        self.guardrails.authorize(Action::CompileHarness).await?;
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        let harness_path = workspace.join("harness.c");
        std::fs::write(&harness_path, &source)
            .map_err(|e| ClassifiedError::Internal(format!("write harness: {e}")))?;
        copy_project_sources(project, &workspace);

        let build_cmd = hf_harness::build_command(engine, lang, &format!("fuzz_{target}"));
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id: self.resolve_target_id(project, target, lang).await,
            engine,
            source,
            language: lang,
            build_cmd,
            sanitizer: hf_core::target::Sanitizer::Address,
            status: HarnessStatus::Draft,
            smoke_run: None,
        };
        let compiled = hf_harness::compile(harness, self.runtime.as_ref(), &workspace).await?;
        // Persist the compiled harness so it survives restarts and the
        // Harness/list views can show it (best-effort).
        if let Some(store) = &self.store {
            if let Err(e) = store.upsert_harness(&compiled).await {
                tracing::warn!("failed to persist harness {}: {e}", compiled.id);
            }
        }
        Ok(CompileOutcome {
            status: compiled.status,
            binary_name: compiled
                .build_cmd
                .output
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(target)
                .to_string(),
            workspace,
        })
    }

    /// Run a 60-second smoke fuzz on an already-compiled harness binary in the
    /// per-target workspace.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the binary is missing or the smoke run
    /// finds zero execs/sec.
    pub async fn harness_smoke(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<SmokeRunSummary, ClassifiedError> {
        self.guardrails.authorize(Action::RunHarness).await?;
        let workspace = workspace_dir(project, target);
        let bin = format!("fuzz_{target}");
        let mut build_cmd = hf_harness::build_command(engine, lang, &bin);
        build_cmd.output = workspace.join(&bin);
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id: Uuid::nil(),
            engine,
            source: String::new(),
            language: lang,
            build_cmd,
            sanitizer: Sanitizer::Address,
            status: HarnessStatus::Compiled,
            smoke_run: None,
        };
        let smoked = hf_harness::smoke_fuzz(harness, self.runtime.as_ref(), &workspace).await?;
        smoked
            .smoke_run
            .ok_or_else(|| ClassifiedError::Harness("smoke run produced no summary".to_owned()))
    }

    // -- Seeds ------------------------------------------------------------

    /// Generate seed corpus inputs for a target.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be written.
    pub fn generate_seeds(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        use sha2::{Digest, Sha256};
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        std::fs::create_dir_all(&corpus_dir)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir corpus: {e}")))?;
        let seeds = generate_target_seeds(target);
        let mut entries = Vec::new();
        for (data, name) in seeds {
            let path = corpus_dir.join(&name);
            std::fs::write(&path, &data)
                .map_err(|e| ClassifiedError::Internal(format!("write seed: {e}")))?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let sha = format!("{:x}", hasher.finalize());
            entries.push(SeedEntry {
                name,
                size: data.len(),
                sha256: sha,
            });
        }
        Ok(entries)
    }

    // -- Run --------------------------------------------------------------

    /// Cancel an in-flight fuzz run by id.
    ///
    /// Fires the run's cancellation token, which cooperatively tears down the
    /// sandboxed fuzzer (the container is killed) and lets [`Self::run_fuzzer`]
    /// return with the partial results it collected, marking the run
    /// `Cancelled`. Returns `true` if a matching active run was found.
    #[must_use]
    pub fn cancel_run(&self, run_id: Uuid) -> bool {
        let Ok(runs) = self.active_runs.lock() else {
            return false;
        };
        if let Some(token) = runs.get(&run_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Cancel every in-flight fuzz run, returning how many were signalled.
    ///
    /// Used for a blanket stop (e.g. a CLI Ctrl-C) where the caller does not
    /// track individual run ids.
    pub fn cancel_all_runs(&self) -> usize {
        let Ok(runs) = self.active_runs.lock() else {
            return 0;
        };
        for token in runs.values() {
            token.cancel();
        }
        runs.len()
    }

    /// The ids of fuzz runs currently in flight.
    #[must_use]
    pub fn active_run_ids(&self) -> Vec<Uuid> {
        self.active_runs
            .lock()
            .map(|runs| runs.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Run a fuzz campaign via `hf-engine::runner::EngineRunner`.
    ///
    /// `on_progress` is called for each parsed `FuzzProgress` event so the
    /// caller can stream it to the UI.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the engine is not supported or the
    /// sandboxed command returns a non-zero exit code.
    pub async fn run_fuzzer(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        duration_secs: u64,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<RunSummary, ClassifiedError> {
        self.guardrails
            .authorize(Action::RunFuzzer {
                engine: format!("{engine:?}"),
                duration_secs,
            })
            .await?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let out_dir = workspace.join("out");
        std::fs::create_dir_all(&corpus_dir)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir corpus: {e}")))?;
        std::fs::create_dir_all(&out_dir)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir out: {e}")))?;

        let bin = format!("fuzz_{target}");
        let binary = workspace.join(&bin);
        if !binary.exists() {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{bin}' not found -- compile the harness first."
            )));
        }
        let binary_str = format!("/work/{bin}");

        let run_cfg = FuzzRunConfig {
            harness_id: Uuid::new_v4(),
            engine,
            duration: Some(std::time::Duration::from_secs(duration_secs)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: Some(corpus_dir.clone()),
            sanitizer: hf_core::target::Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
        };
        // Record the run so campaigns survive restarts (best-effort).
        let run_record = self.store.as_ref().map(|_| {
            let mut rec = RunRecord::new(
                project.to_string_lossy().to_string(),
                engine,
                Some(run_cfg.clone()),
                Utc::now(),
            );
            rec.status = RunStatus::Running;
            rec
        });
        if let (Some(store), Some(rec)) = (&self.store, &run_record) {
            if let Err(e) = store.insert_run(rec).await {
                tracing::warn!("failed to record run start: {e}");
            }
        }
        // Journal the run as an open scope so an interrupted run (crash/quit
        // mid-fuzz) is detected and offered for recovery on the next startup.
        let run_id = run_record.as_ref().map_or_else(Uuid::new_v4, |rec| rec.id);
        self.run_journal.open_run(run_id, project, target, engine);

        // Register a cancellation token so `cancel_run(run_id)` can stop this
        // run cooperatively. `ActiveRunGuard` removes it again when this scope
        // ends -- crucially, even if the `run_fuzzer` future is dropped/aborted
        // (e.g. wrapped in a `timeout`) rather than returning normally. A plain
        // post-await removal would leak the entry on abort, leaving a phantom
        // run that `active_run_ids` reports and `cancel_run` can never clear.
        let cancel = CancellationToken::new();
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.insert(run_id, cancel.clone());
        }
        let _active_run_guard = ActiveRunGuard {
            active_runs: Arc::clone(&self.active_runs),
            run_id,
        };

        let runner = hf_engine::runner::EngineRunner::new();
        // Stream progress live: `on_progress` fires for each output line and
        // stat as the fuzzer runs, not post-hoc.
        let run_result = runner
            .run_streaming(
                engine,
                &run_cfg,
                &binary_str,
                "/work/corpus",
                "/work/out",
                self.runtime.as_ref(),
                &workspace,
                &cancel,
                on_progress,
            )
            .await;
        let was_cancelled = cancel.is_cancelled();
        if let (Some(store), Some(rec)) = (&self.store, &run_record) {
            let status = if was_cancelled {
                RunStatus::Cancelled
            } else if run_result.is_ok() {
                RunStatus::Done
            } else {
                RunStatus::Failed
            };
            if let Err(e) = store.set_run_status(rec.id, status, Some(Utc::now())).await {
                tracing::warn!("failed to record run end: {e}");
            }
        }
        // Close the run's journal scope: it completed (whether ok, errored, or
        // cancelled), so it is no longer a recovery candidate.
        self.run_journal.close_run(run_id);
        let result = run_result?;
        // Summarize from the parsed events. Live streaming already forwarded
        // them to `on_progress`, so do not re-emit here.
        let mut edges = 0u64;
        let mut execs = 0.0_f64;
        let mut crashes = 0u32;
        for p in &result.progress {
            match p {
                FuzzProgress::EdgesCovered(v) => edges = edges.max(*v),
                FuzzProgress::ExecsPerSec(v) => execs = execs.max(*v),
                FuzzProgress::CrashesFound(n) => crashes += n,
                FuzzProgress::LogLine(_) | FuzzProgress::Done => {}
            }
        }
        Ok(RunSummary {
            edges,
            execs,
            crashes: u64::from(crashes),
        })
    }

    /// Run a syzkaller kernel-fuzzing campaign through the sandbox.
    ///
    /// syzkaller fuzzes an OS kernel by mutating syscall sequences inside a
    /// managed VM whose kernel is built with KCOV coverage. This mounts the
    /// user-supplied kernel image + rootfs (or an existing `manager.cfg`) into
    /// the sandbox, synthesizes a qemu `manager.cfg` when needed, and streams
    /// `syz-manager` progress to `on_progress`.
    ///
    /// Unlike a harness/fuzz run, qemu needs container networking and a relaxed
    /// capability profile, so this uses
    /// [`SandboxOptions`](hf_core::runtime::SandboxOptions) rather than the
    /// hardened default -- but it still goes through the `hf-runtime` sandbox
    /// abstraction (no presentation layer shells out to `docker`).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if Docker is unavailable, an artifact path is
    /// invalid, or the sandbox run fails.
    pub async fn run_syzkaller(
        &self,
        opts: &SyzkallerRunOpts,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<SyzkallerSummary, ClassifiedError> {
        use std::sync::atomic::{AtomicU64, Ordering};

        self.guardrails
            .authorize(Action::RunFuzzer {
                engine: "Syzkaller".to_owned(),
                duration_secs: opts.duration_secs,
            })
            .await?;

        let platform = opts
            .arch
            .as_deref()
            .map_or_else(hf_runtime::host_platform, hf_runtime::norm_platform);
        let target_triple = format!("linux/{}", hf_runtime::platform_short(&platform));

        let log = |s: &str| on_progress(FuzzProgress::LogLine(s.to_owned()));
        let nonempty = |o: &Option<String>| {
            o.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let manager_cfg = nonempty(&opts.manager_cfg);
        let kernel_image = nonempty(&opts.kernel_image);
        let disk_image = nonempty(&opts.disk_image);
        let ssh_key = nonempty(&opts.ssh_key);

        let have_artifacts = kernel_image.is_some() && disk_image.is_some();

        // No artifacts at all: surface what a campaign needs and stop (no error).
        if manager_cfg.is_none() && !have_artifacts {
            for line in [
                format!("syzkaller (kernel fuzzing) -- project: {}", opts.project),
                "No campaign artifacts provided. syzkaller drives a VM against a".to_owned(),
                "KCOV-instrumented kernel; it needs one of:".to_owned(),
                "  (a) a kernel image (bzImage) + a rootfs disk image, or".to_owned(),
                "  (b) an existing syz-manager config (manager.cfg).".to_owned(),
                "Build a KCOV kernel + rootfs per the setup guide, then select them above:"
                    .to_owned(),
                "https://github.com/google/syzkaller/blob/master/docs/linux/setup.md".to_owned(),
            ] {
                log(&line);
            }
            on_progress(FuzzProgress::Done);
            return Ok(SyzkallerSummary::default());
        }

        if !hf_runtime::docker_daemon_ready() {
            return Err(ClassifiedError::Sandbox(
                "Docker daemon not running -- cannot launch syz-manager.".to_owned(),
            ));
        }

        let file_ok = |p: &str| Path::new(p).is_file();

        // Assemble bind mounts and resolve the in-container config path.
        let mut mounts: Vec<String> = Vec::new();
        let workspace = workspace_root().join("syzkaller");
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir syzkaller workspace: {e}")))?;
        let cfg_in_container: String;

        // Use KVM when the host can (native-arch Linux with /dev/kvm); this is
        // orders of magnitude faster than TCG emulation. It drives both the
        // synthesized qemu args and the `--device /dev/kvm` passthrough below.
        let use_kvm = syz_kvm_usable(&platform);

        if let Some(cfg) = manager_cfg.as_deref() {
            if !file_ok(cfg) {
                return Err(ClassifiedError::Validation(format!(
                    "manager.cfg not found: {cfg}"
                )));
            }
            let dir = Path::new(cfg).parent().ok_or_else(|| {
                ClassifiedError::Validation("manager.cfg has no parent directory".to_owned())
            })?;
            mounts.push(format!("{0}:{0}", dir.display()));
            cfg_in_container = cfg.to_owned();
            log(&format!("Using provided manager.cfg: {cfg}"));
        } else {
            let kernel = kernel_image.ok_or_else(|| {
                ClassifiedError::Validation(
                    "kernel_image is required when no manager.cfg is provided".to_owned(),
                )
            })?;
            let disk = disk_image.ok_or_else(|| {
                ClassifiedError::Validation(
                    "disk_image is required when no manager.cfg is provided".to_owned(),
                )
            })?;
            if !file_ok(&kernel) {
                return Err(ClassifiedError::Validation(format!(
                    "kernel image not found: {kernel}"
                )));
            }
            if !file_ok(&disk) {
                return Err(ClassifiedError::Validation(format!(
                    "disk image not found: {disk}"
                )));
            }
            mounts.push(format!("{kernel}:/syzbench/kernel:ro"));
            mounts.push(format!("{disk}:/syzbench/rootfs.img"));

            let sshkey_field = if let Some(key) = ssh_key.as_deref() {
                if !file_ok(key) {
                    return Err(ClassifiedError::Validation(format!(
                        "ssh key not found: {key}"
                    )));
                }
                mounts.push(format!("{key}:/syzbench/id_rsa:ro"));
                "\n  \"sshkey\": \"/syzbench/id_rsa\",".to_owned()
            } else {
                String::new()
            };

            let count = opts.vm_count.unwrap_or(2).max(1);
            let procs = count.min(4);
            let machine = if hf_runtime::platform_short(&platform) == "arm64" {
                "virt"
            } else {
                "pc"
            };
            let accel = if use_kvm { "kvm" } else { "tcg" };
            // KVM pairs with `-cpu host`; TCG emulation uses `-cpu max`.
            let cpu = if use_kvm { "host" } else { "max" };
            let qemu_args = format!("-machine {machine},accel={accel} -cpu {cpu}");
            let cfg_json = format!(
                "{{\n  \"target\": \"{target_triple}\",\n  \"http\": \"0.0.0.0:56741\",\n  \"workdir\": \"/syzbench/workdir\",\n  \"image\": \"/syzbench/rootfs.img\",{sshkey_field}\n  \"syzkaller\": \"/opt/syzkaller\",\n  \"procs\": {procs},\n  \"type\": \"qemu\",\n  \"vm\": {{\n    \"count\": {count},\n    \"kernel\": \"/syzbench/kernel\",\n    \"cpu\": 2,\n    \"mem\": 2048,\n    \"qemu_args\": \"{qemu_args}\"\n  }}\n}}\n"
            );
            let cfg_host = workspace.join("manager.cfg");
            std::fs::write(&cfg_host, &cfg_json)
                .map_err(|e| ClassifiedError::Internal(format!("write manager.cfg: {e}")))?;
            let workdir_host = workspace.join("workdir");
            std::fs::create_dir_all(&workdir_host)
                .map_err(|e| ClassifiedError::Internal(format!("mkdir syzkaller workdir: {e}")))?;
            mounts.push(format!("{}:/syzbench/manager.cfg:ro", cfg_host.display()));
            mounts.push(format!("{}:/syzbench/workdir", workdir_host.display()));
            cfg_in_container = "/syzbench/manager.cfg".to_owned();
            log(&format!(
                "Synthesized qemu manager.cfg ({target_triple}, {count} VM(s))."
            ));
        }

        log(&format!(
            "Launching syz-manager in the sandbox for {}s...",
            opts.duration_secs
        ));
        if use_kvm {
            log("Note: qemu uses KVM acceleration (/dev/kvm passed through) -- expect good exec rates.");
        } else {
            log("Note: qemu runs under TCG emulation inside Docker (no KVM on this host) -- expect low exec rates.");
        }

        let inner = format!(
            "command -v syz-manager >/dev/null 2>&1 || {{ echo 'ERROR: syz-manager not found in the sandbox image. Rebuild the image with the syzkaller toolchain: open Settings > General and switch the sandbox Architecture (forces a rebuild), or remove the image with: docker image rm {sandbox_img}'; exit 3; }}; timeout {duration} syz-manager -config={cfg_in_container} 2>&1 || true",
            sandbox_img = SANDBOX_IMAGE,
            duration = opts.duration_secs,
        );

        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 4,
            // The inner `timeout` governs the campaign; give the sandbox deadline
            // a grace margin so it is only a backstop.
            max_duration_secs: opts.duration_secs.saturating_add(30),
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox_opts = hf_core::runtime::SandboxOptions {
            extra_mounts: mounts,
            platform: Some(platform),
            network_enabled: true,
            workdir: Some("/syzbench".to_owned()),
            relax_hardening: true,
            devices: if use_kvm {
                vec!["/dev/kvm".to_owned()]
            } else {
                Vec::new()
            },
        };

        // Cross-line state for the streaming callback.
        let peak_edges = AtomicU64::new(0);
        let last_execs = AtomicU64::new(0);
        let peak_crashes = AtomicU64::new(0);
        let on_line = |line: &str| {
            if let Some((cover, executed, crash_ct)) =
                hf_engine::progress::parse_syzkaller_status(line)
            {
                peak_edges.fetch_max(cover, Ordering::Relaxed);
                last_execs.store(executed, Ordering::Relaxed);
                let prev = peak_crashes.load(Ordering::Relaxed);
                if crash_ct > prev {
                    on_progress(FuzzProgress::CrashesFound(
                        u32::try_from(crash_ct - prev).unwrap_or(u32::MAX),
                    ));
                    peak_crashes.store(crash_ct, Ordering::Relaxed);
                }
                on_progress(FuzzProgress::EdgesCovered(cover));
                on_progress(FuzzProgress::ExecsPerSec(executed as f64));
                on_progress(FuzzProgress::LogLine(line.to_owned()));
            } else if !line.trim().is_empty() {
                on_progress(FuzzProgress::LogLine(line.to_owned()));
            }
        };

        let cancel = CancellationToken::new();
        let cmd = ["bash".to_owned(), "-c".to_owned(), inner];
        let result = self
            .runtime
            .run_command_streaming_opts(&cmd, &workspace, &limits, &sandbox_opts, &cancel, &on_line)
            .await?;

        on_progress(FuzzProgress::Done);
        Ok(SyzkallerSummary {
            edges: peak_edges.load(Ordering::Relaxed),
            execs: last_execs.load(Ordering::Relaxed) as f64,
            crashes: peak_crashes.load(Ordering::Relaxed),
            exit_code: Some(result.exit_code),
        })
    }

    // -- Triage -----------------------------------------------------------

    /// Ingest and deduplicate crash artifacts from the output directory.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the output directory cannot be read.
    pub async fn triage(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        /// Cap on LLM bug-report drafts per triage pass: a run may surface many
        /// distinct bugs, and one report each would fan out into hundreds of LLM
        /// calls. Crashes beyond the cap are still ingested and persisted, just
        /// without a drafted report.
        const MAX_BUG_REPORT_DRAFTS: usize = 20;

        self.guardrails.authorize(Action::Triage).await?;
        let workspace = workspace_dir(project, target);
        let out_dir = workspace.join("out");
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;
        // Link crashes to the run that produced them, and learn its engine to
        // pick the right CASR driver. The most recent run for this project is the
        // one whose `out` dir we are triaging; a fresh UUID would orphan every
        // crash (crashes.run_id is NOT NULL and indexed for `list_crashes_by_run`).
        let (run_id, engine) = self.latest_run(project).await;

        // Prefer CASR: it reproduces each crash, classifies exploitability and
        // severity, and clusters/deduplicates -- all in the sandbox. Fall back to
        // the built-in reproduce/classify/dedup path when CASR is unavailable (no
        // harness binary, native runtime without casr, or the tool errored). The
        // captured sanitizer traces (`logs`) feed bug-report drafting; CASR-path
        // crashes carry their summary instead.
        let (mut deduped, logs): (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ) = match self
            .run_casr_triage(&workspace, target, engine, run_id, target_id)
            .await
        {
            Some(crashes) if !crashes.is_empty() => (crashes, std::collections::HashMap::new()),
            _ => {
                self.legacy_triage(&out_dir, &workspace, target, run_id, target_id)
                    .await?
            }
        };

        // Give each crash a deterministic id so persisting is idempotent: a
        // second triage of the same run replaces these rows instead of adding
        // duplicates (the report lists every persisted crash for the run).
        for crash in &mut deduped {
            crash.id = deterministic_crash_id(run_id, &crash.stack_signature, &crash.input_path);
        }

        // Draft an LLM bug report for each unique crash when a provider is
        // configured, using the captured sanitizer trace (capped, see above).
        if let Some(pool) = self.provider_pool() {
            let unique = deduped.len();
            for crash in deduped.iter_mut().take(MAX_BUG_REPORT_DRAFTS) {
                let bridge = LlmProviderBridge::new(Arc::clone(&pool))
                    .with_diagnostics(Arc::clone(&self.diagnostics), "triage_report");
                let log = logs
                    .get(&crash.input_path)
                    .filter(|l| !l.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| crash.summary.clone());
                match hf_crash::draft_report(crash, &log, Box::new(bridge)).await {
                    Ok(report) => crash.bug_report = Some(report),
                    Err(e) => tracing::warn!("bug report drafting failed for {}: {e}", crash.id),
                }
            }
            if unique > MAX_BUG_REPORT_DRAFTS {
                tracing::info!(
                    "capped bug-report drafting at {MAX_BUG_REPORT_DRAFTS} of {unique} unique crashes"
                );
            }
        }

        if let Some(store) = &self.store {
            for crash in &deduped {
                if let Err(e) = store.upsert_crash(crash).await {
                    tracing::warn!("failed to persist crash {}: {e}", crash.id);
                }
            }
        }
        Ok(deduped)
    }

    /// Regression check: replay stored crash inputs against the current harness
    /// and report which ones still crash.
    ///
    /// The workflow is: fix the bug, recompile the harness, then run this to
    /// confirm the fix (and catch re-introductions). Prefers the persisted
    /// crashes for the project's latest run; falls back to crash inputs staged
    /// under the run output directory. Requires a compiled harness binary.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the harness is missing or the action is
    /// denied by guardrails.
    pub async fn verify_regressions(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<RegressionResult>, ClassifiedError> {
        // Replaying crash inputs runs the (untrusted) harness in the sandbox --
        // gate it like triage.
        self.guardrails.authorize(Action::Triage).await?;
        let workspace = workspace_dir(project, target);
        if !workspace.join(format!("fuzz_{target}")).exists() {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness 'fuzz_{target}' not found -- compile the harness first."
            )));
        }

        // (crash_id, input_path) pairs: persisted crashes first, else staged.
        let mut inputs: Vec<(String, PathBuf)> = Vec::new();
        if let Some(store) = &self.store {
            let (run_id, _engine) = self.latest_run(project).await;
            if let Ok(crashes) = store.list_crashes_by_run(run_id).await {
                inputs.extend(
                    crashes
                        .into_iter()
                        .map(|c| (c.id.to_string(), c.input_path)),
                );
            }
        }
        if inputs.is_empty() {
            inputs = collect_crash_inputs(&workspace.join("out"))
                .into_iter()
                .map(|p| (String::new(), p))
                .collect();
        }

        let mut results = Vec::with_capacity(inputs.len());
        for (crash_id, input) in inputs {
            if !input.is_file() {
                continue;
            }
            let trace = self.reproduce_crash(&workspace, target, &input).await;
            let still_crashes = hf_crash::looks_like_crash(&trace);
            let summary = if still_crashes {
                trace
                    .lines()
                    .find(|l| {
                        let s = l.to_ascii_lowercase();
                        s.contains("error") || s.contains("summary")
                    })
                    .unwrap_or("still crashes")
                    .trim()
                    .chars()
                    .take(200)
                    .collect()
            } else {
                "no crash on replay (fixed)".to_owned()
            };
            results.push(RegressionResult {
                crash_id,
                input: input.display().to_string(),
                still_crashes,
                summary,
            });
        }
        Ok(results)
    }

    /// Functions covered by a fuzz run, for the call-tree coverage overlay.
    ///
    /// Builds a source-based-coverage harness from the workspace sources,
    /// replays the accumulated corpus through it in the sandbox, and exports
    /// per-function execution counts with `llvm-cov` -- engine-agnostic, since
    /// it compiles its own coverage binary rather than reusing the run's. Empty
    /// when no harness was built or coverage tooling is unavailable. Results are
    /// cached per target, keyed by a corpus+harness signature so they refresh
    /// automatically when a run grows the corpus or the harness is rebuilt.
    pub async fn coverage_functions(&self, project: &Path, target: &str) -> Vec<String> {
        let workspace = workspace_dir(project, target);
        if !workspace.join("harness.c").exists() {
            return Vec::new();
        }
        let cache_key = format!("{}::{target}", project.display());
        let signature = coverage_signature(&workspace);
        if let Some((cached_sig, cached)) = coverage_cache()
            .lock()
            .ok()
            .and_then(|map| map.get(&cache_key).cloned())
        {
            if cached_sig == signature {
                return cached;
            }
        }
        // One sandbox shell pipeline: coverage build -> replay corpus -> export.
        let pipeline = "clang -g -O1 -fsanitize=fuzzer -fprofile-instr-generate \
             -fcoverage-mapping *.c -o fuzz_cov 2>/dev/null \
             && LLVM_PROFILE_FILE=cov.profraw ./fuzz_cov -runs=0 corpus 2>/dev/null; \
             llvm-profdata merge -sparse cov.profraw -o cov.profdata 2>/dev/null \
             && llvm-cov export ./fuzz_cov -instr-profile=cov.profdata 2>/dev/null";
        let cmd = vec!["sh".to_owned(), "-c".to_owned(), pipeline.to_owned()];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 180,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        match self.runtime.run_command(&cmd, &workspace, &limits).await {
            // Cache successful runs (even empty -- the signature invalidates them
            // when the corpus changes); do not cache infra failures, so they retry.
            Ok(result) => {
                let covered = parse_covered_functions(&result.stdout);
                if let Ok(mut map) = coverage_cache().lock() {
                    map.insert(cache_key, (signature, covered.clone()));
                }
                covered
            }
            Err(e) => {
                tracing::warn!("coverage collection failed: {e}");
                Vec::new()
            }
        }
    }

    /// Line/region/function coverage totals for a fuzz run.
    ///
    /// Complements [`Self::coverage_functions`] (which names covered functions
    /// for the call-tree overlay) with the structural percentages reviewers
    /// actually report: lines, functions, and regions covered out of the total.
    /// Builds the same source-based-coverage binary in the sandbox, replays the
    /// corpus, and parses the `llvm-cov export` totals. Returns `None` when no
    /// harness was built or the coverage tooling is unavailable. Cached per
    /// target by the corpus+harness signature, like the covered-function set.
    pub async fn coverage_summary(
        &self,
        project: &Path,
        target: &str,
    ) -> Option<hf_coverage::CoverageSummary> {
        let workspace = workspace_dir(project, target);
        if !workspace.join("harness.c").exists() {
            return None;
        }
        let cache_key = format!("{}::{target}", project.display());
        let signature = coverage_signature(&workspace);
        if let Some((cached_sig, cached)) = summary_cache()
            .lock()
            .ok()
            .and_then(|map| map.get(&cache_key).copied())
        {
            if cached_sig == signature {
                return Some(cached);
            }
        }
        let pipeline = "clang -g -O1 -fsanitize=fuzzer -fprofile-instr-generate \
             -fcoverage-mapping *.c -o fuzz_cov 2>/dev/null \
             && LLVM_PROFILE_FILE=cov.profraw ./fuzz_cov -runs=0 corpus 2>/dev/null; \
             llvm-profdata merge -sparse cov.profraw -o cov.profdata 2>/dev/null \
             && llvm-cov export ./fuzz_cov -instr-profile=cov.profdata 2>/dev/null";
        let cmd = vec!["sh".to_owned(), "-c".to_owned(), pipeline.to_owned()];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 180,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        match self.runtime.run_command(&cmd, &workspace, &limits).await {
            Ok(result) => {
                let summary = hf_coverage::parse_llvm_cov_summary(&result.stdout)?;
                if let Ok(mut map) = summary_cache().lock() {
                    map.insert(cache_key, (signature, summary));
                }
                Some(summary)
            }
            Err(e) => {
                tracing::warn!("coverage summary collection failed: {e}");
                None
            }
        }
    }

    /// Compose a detailed Markdown campaign report for a target.
    ///
    /// Aggregates the discovered target, the most recent run, its triaged
    /// crashes (with CASR severity + LLM bug reports), line/region coverage, and
    /// corpus composition into a single self-contained Markdown document the
    /// user can download and paste into any Markdown tool. Pulls persisted data
    /// from the store and computes coverage live; degrades gracefully (honest
    /// "not available" sections) when a store, run, or coverage tooling is
    /// absent.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected internal failure; missing
    /// data is rendered as empty sections rather than an error.
    /// The persisted crashes for a project's most recent run (empty without a
    /// store or runs).
    async fn crashes_for_latest_run(&self, project: &Path) -> Vec<hf_core::crash::Crash> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let run = store
            .list_runs(Some(&project.to_string_lossy()))
            .await
            .ok()
            .and_then(|runs| runs.into_iter().next());
        match run {
            // Guard against any pre-existing duplicate rows (e.g. crashes
            // persisted before the deterministic-id fix): collapse by signature.
            Some(r) => hf_crash::dedup(store.list_crashes_by_run(r.id).await.unwrap_or_default()),
            None => Vec::new(),
        }
    }

    /// Export the latest run's crashes as a SARIF 2.1.0 document (string),
    /// for `GitHub` code scanning / security dashboards. Empty `results` when
    /// there are no crashes.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected serialization failure.
    pub async fn export_sarif(
        &self,
        project: &Path,
        _target: &str,
    ) -> Result<String, ClassifiedError> {
        let crashes = self.crashes_for_latest_run(project).await;
        let sarif = crate::sarif::crashes_to_sarif(&crashes, env!("CARGO_PKG_VERSION"));
        serde_json::to_string_pretty(&sarif)
            .map_err(|e| ClassifiedError::Internal(format!("serialize sarif: {e}")))
    }

    pub async fn generate_report(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<String, ClassifiedError> {
        use crate::report::{render_markdown, ReportData};

        // Resolve the target candidate (best-effort) and its id.
        let candidate = self
            .discover(project, TargetLanguage::C)
            .await
            .ok()
            .and_then(|inv| inv.candidates.into_iter().find(|c| c.symbol == target));
        let target_id = candidate.as_ref().map_or_else(Uuid::nil, |c| c.id);

        // Latest run + its crashes from the store, when persistence is wired.
        let (run, crashes) = if let Some(store) = &self.store {
            let run = store
                .list_runs(Some(&project.to_string_lossy()))
                .await
                .ok()
                .and_then(|runs| runs.into_iter().next());
            let crashes = match &run {
                // Collapse any pre-existing duplicate rows by signature so the
                // report never lists the same crash twice.
                Some(r) => {
                    hf_crash::dedup(store.list_crashes_by_run(r.id).await.unwrap_or_default())
                }
                None => Vec::new(),
            };
            (run, crashes)
        } else {
            (None, Vec::new())
        };

        // Live coverage (best-effort) and corpus composition.
        let coverage = self.coverage_summary(project, target).await;
        let covered_functions = self.coverage_functions(project, target).await.len();
        let corpus = self.collect_corpus_stats(project, target, target_id).await;

        let data = ReportData {
            generated_at: Utc::now().to_rfc3339(),
            project: project.to_string_lossy().to_string(),
            target: target.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            candidate,
            run,
            crashes,
            coverage,
            covered_functions,
            corpus,
        };

        // The deterministic fact-sheet is always correct and carries the graphs;
        // it is the no-provider fallback AND the grounded input for the LLM.
        let facts = render_markdown(&data);

        // When a provider is configured, have the LLM compose a professional
        // narrative grounded in those facts. On any failure, fall back to the
        // deterministic fact-sheet so a report is always produced.
        if let Some(pool) = self.provider_pool() {
            match self.compose_ai_report(&pool, &facts, &data).await {
                Ok(report) => return Ok(report),
                Err(e) => tracing::warn!("AI report composition failed, using fact-sheet: {e}"),
            }
        }
        Ok(facts)
    }

    /// Compose the narrative report with the LLM, grounded in the fact-sheet.
    async fn compose_ai_report(
        &self,
        pool: &Arc<dyn ProviderPool>,
        facts: &str,
        data: &crate::report::ReportData,
    ) -> Result<String, ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;

        let messages = vec![
            Message::system(crate::report::report_system_prompt()),
            Message::user(crate::report::report_user_prompt(facts, data)),
        ];
        let req = ChatRequest::from_messages(messages);
        let resp = pool
            .chat_completion(
                &req,
                &RouteRequest::with_tags(&["reasoning", "code", "general"]),
            )
            .await?;
        self.diagnostics
            .record("report", &resp.model, &resp.usage)
            .await;
        let text = resp.text().trim();
        if text.is_empty() {
            return Err(ClassifiedError::Provider(
                "empty report from provider".to_owned(),
            ));
        }
        // Guarantee the campaign graphs survive even if the model dropped them.
        Ok(crate::report::ensure_graphs(text, data))
    }

    /// Summarize corpus composition for the report, preferring the persisted
    /// entries (richer source tags) and falling back to the workspace listing.
    async fn collect_corpus_stats(
        &self,
        project: &Path,
        target: &str,
        target_id: Uuid,
    ) -> crate::report::CorpusStats {
        use hf_core::corpus::CorpusSource;

        let entries = match &self.store {
            Some(store) if target_id != Uuid::nil() => store
                .list_corpus_entries(target_id)
                .await
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let entries = if entries.is_empty() {
            // No persisted entries: read the live corpus directory.
            let workspace = workspace_dir(project, target);
            hf_corpus::list(&workspace.join("corpus"))
                .map(|c| c.entries)
                .unwrap_or_default()
        } else {
            entries
        };

        let mut stats = crate::report::CorpusStats::default();
        for e in &entries {
            stats.count += 1;
            stats.total_bytes += e.size;
            match e.source {
                CorpusSource::Seed => stats.seeds += 1,
                CorpusSource::Fuzzer => stats.from_fuzzer += 1,
                CorpusSource::Minimized => stats.minimized += 1,
                CorpusSource::Manual => {}
            }
        }
        stats
    }

    /// Replay a single crash input through the compiled harness in the sandbox
    /// and return the combined stdout+stderr (the sanitizer trace). Best-effort:
    /// returns an empty string if the binary is missing or the run fails.
    async fn reproduce_crash(
        &self,
        workspace: &Path,
        target: &str,
        input_host_path: &Path,
    ) -> String {
        let bin = format!("fuzz_{target}");
        if !workspace.join(&bin).exists() {
            return String::new();
        }
        let container_input = container_input_path(workspace, input_host_path);
        let cmd = vec![format!("/work/{bin}"), container_input];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 30,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        match self.runtime.run_command(&cmd, workspace, &limits).await {
            // A crashing input exits non-zero; the trace is the useful output.
            Ok(result) => format!("{}\n{}", result.stdout, result.stderr),
            Err(e) => {
                tracing::warn!("crash reproduction failed: {e}");
                String::new()
            }
        }
    }

    /// Most recent run id + engine for a project (defaults when none exists).
    async fn latest_run(&self, project: &Path) -> (Uuid, EngineKind) {
        match &self.store {
            Some(store) => store
                .list_runs(Some(&project.to_string_lossy()))
                .await
                .ok()
                .and_then(|runs| runs.into_iter().next())
                .map_or_else(
                    || (Uuid::new_v4(), EngineKind::LibFuzzer),
                    |run| (run.id, run.engine),
                ),
            None => (Uuid::new_v4(), EngineKind::LibFuzzer),
        }
    }

    /// Run CASR over the crash dir in the sandbox, returning one `Crash` per
    /// unique (clustered) report with its severity/analysis. Returns `None` when
    /// CASR is unavailable or produced nothing, so the caller can fall back.
    async fn run_casr_triage(
        &self,
        workspace: &Path,
        target: &str,
        engine: EngineKind,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Option<Vec<hf_core::crash::Crash>> {
        let bin = format!("fuzz_{target}");
        if !workspace.join(&bin).exists() {
            return None;
        }
        let out_dir = workspace.join("out");
        if !out_dir.exists() {
            return None;
        }
        // CASR's input expectation differs by driver: `casr-afl` walks the AFL
        // output tree (out/<instance>/crashes/...), while `casr-libfuzzer` wants
        // a flat directory of crash inputs. For non-AFL engines we stage only
        // real crash inputs into a clean dir, since engines like honggfuzz mix
        // coverage maps and logs into `out` that CASR would otherwise replay.
        let crash_dir = if engine == EngineKind::AflPlusPlus {
            "/work/out".to_owned()
        } else {
            let staging = workspace.join("casr_in");
            let _ = std::fs::remove_dir_all(&staging);
            if stage_crash_inputs(&out_dir, &staging) == 0 {
                return None;
            }
            "/work/casr_in".to_owned()
        };
        // Fresh CASR output directory each pass.
        let casr_host = workspace.join("casr_out");
        let _ = std::fs::remove_dir_all(&casr_host);
        let cmd = hf_crash::casr_command(
            engine,
            &format!("/work/{bin}"),
            &crash_dir,
            "/work/casr_out",
            30,
        );
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 900,
            env: std::collections::HashMap::new(),
            ptrace: true,
        };
        match self.runtime.run_command(&cmd, workspace, &limits).await {
            Ok(r) if r.exit_code != 0 => {
                tracing::warn!(
                    "casr exited {}: {}",
                    r.exit_code,
                    r.stderr.lines().last().unwrap_or_default()
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("casr run failed, falling back to built-in triage: {e}");
                return None;
            }
        }
        let reports = collect_casreps(&casr_host);
        if reports.is_empty() {
            tracing::info!("casr produced no reports; falling back to built-in triage");
            return None;
        }
        let mut crashes = reports
            .into_iter()
            .map(|(path, casr)| {
                let input_path = casrep_input_path(&out_dir, &path);
                let signature = if casr.crashline.is_empty() {
                    casr.stack.first().cloned().unwrap_or_default()
                } else {
                    casr.crashline.clone()
                };
                let summary = if casr.severity_short.is_empty() {
                    casr.crashline.clone()
                } else {
                    format!("{} at {}", casr.severity_short, casr.crashline)
                };
                hf_core::crash::Crash {
                    id: Uuid::new_v4(),
                    run_id,
                    target_id,
                    input_path,
                    stack_signature: signature,
                    kind: hf_crash::kind_from_short(&casr.severity_short),
                    summary,
                    minimized: false,
                    bug_report: None,
                    casr: Some(casr),
                }
            })
            .collect::<Vec<_>>();
        // Bucket by CASR cluster: keep one representative per cluster (clusters
        // are CASR's own "same bug" grouping, stronger than our stack signature).
        // Crashes CASR did not cluster (cluster=None) all pass through.
        crashes = bucket_by_cluster(crashes);
        tracing::info!("casr triaged {} unique crash(es)", crashes.len());
        Some(crashes)
    }

    /// Built-in triage fallback: replay crashes in the sandbox until the set of
    /// distinct stack signatures saturates, classify, and dedup. Returns the
    /// deduped crashes plus captured sanitizer traces for bug-report drafting.
    async fn legacy_triage(
        &self,
        out_dir: &Path,
        workspace: &Path,
        target: &str,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Result<
        (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ),
        ClassifiedError,
    > {
        /// Hard cap on sandbox crash replays per triage pass.
        const MAX_REPRODUCE: usize = 300;
        /// Stop reproducing after this many consecutive crashes with no new
        /// stack signature (the distinct-bug set has saturated).
        const SIGNATURE_STAGNATION: usize = 40;

        let crashes = hf_crash::ingest(out_dir, run_id, target_id)?;
        let total_ingested = crashes.len();
        let mut logs: std::collections::HashMap<PathBuf, String> = std::collections::HashMap::new();
        let mut reproduced: Vec<hf_core::crash::Crash> = Vec::new();
        let mut seen_signatures: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut since_new_signature = 0usize;
        for mut crash in crashes {
            if reproduced.len() >= MAX_REPRODUCE || since_new_signature >= SIGNATURE_STAGNATION {
                break;
            }
            let log = self
                .reproduce_crash(workspace, target, &crash.input_path)
                .await;
            if log.trim().is_empty() {
                since_new_signature += 1;
            } else {
                let (kind, sig, summary) = hf_crash::classify(&log);
                crash.kind = kind;
                crash.summary = summary;
                if seen_signatures.insert(sig.clone()) {
                    since_new_signature = 0;
                } else {
                    since_new_signature += 1;
                }
                crash.stack_signature = sig;
            }
            logs.insert(crash.input_path.clone(), log);
            reproduced.push(crash);
        }
        if reproduced.len() < total_ingested {
            tracing::info!(
                "reproduced {} of {total_ingested} crash inputs ({} distinct signatures) before saturating",
                reproduced.len(),
                seen_signatures.len()
            );
        }
        Ok((hf_crash::dedup(reproduced), logs))
    }

    // -- Corpus -----------------------------------------------------------

    /// List corpus entries for a project/target.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory cannot be read.
    pub fn corpus_list(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<hf_core::corpus::Corpus, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        hf_corpus::list(&corpus_dir)
    }

    /// Seed the corpus with default inputs.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be written.
    pub async fn corpus_seed(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        std::fs::create_dir_all(&corpus_dir)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        let seeds = vec![
            (b"{}".to_vec(), "seed_empty".to_owned()),
            (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
        ];
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;
        let corpus = hf_corpus::seed(target_id, &corpus_dir, seeds).await?;
        self.persist_corpus(target_id, &corpus).await;
        Ok(corpus.entries.len())
    }

    /// Grow the corpus from engine output.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the directories cannot be read.
    pub async fn corpus_grow(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let out_dir = workspace.join("out");
        let mut corpus = hf_corpus::grow(&corpus_dir, &out_dir)?;
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;
        corpus.target_id = target_id;
        self.persist_corpus(target_id, &corpus).await;
        Ok(corpus.entries.len())
    }

    /// Prune duplicate-coverage entries from the corpus.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be removed.
    pub fn corpus_prune(&self, project: &Path, target: &str) -> Result<usize, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let corpus = hf_corpus::list(&corpus_dir)?;
        let pruned = hf_corpus::prune(corpus)?;
        Ok(pruned.entries.len())
    }

    /// Feed triaged crash reproducers back into the corpus.
    ///
    /// Closes the run -> triage -> corpus loop: every crash-triggering input
    /// surfaced by the most recent triage (persisted crashes for the project's
    /// latest run, falling back to scanning the run output directory) is copied
    /// into the corpus, deduplicated by content, so the harness keeps exercising
    /// the paths that already broke it. Returns the number of inputs newly
    /// added.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus cannot be read or written.
    pub async fn corpus_absorb_crashes(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");

        // Prefer the deduplicated crash set triage persisted for the latest run;
        // fall back to whatever crash inputs are staged under the run output.
        let mut inputs: Vec<PathBuf> = Vec::new();
        if let Some(store) = &self.store {
            let (run_id, _engine) = self.latest_run(project).await;
            if let Ok(crashes) = store.list_crashes_by_run(run_id).await {
                inputs.extend(crashes.into_iter().map(|c| c.input_path));
            }
        }
        if inputs.is_empty() {
            inputs = collect_crash_inputs(&workspace.join("out"));
        }

        let (mut corpus, added) = hf_corpus::absorb(&corpus_dir, &inputs)?;
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;
        corpus.target_id = target_id;
        self.persist_corpus(target_id, &corpus).await;
        Ok(added)
    }

    /// Coverage-guided corpus minimization.
    ///
    /// Builds a libFuzzer coverage binary from the workspace sources in the
    /// sandbox and runs the canonical `-merge=1` pass, which keeps only inputs
    /// that contribute new coverage, into a fresh directory; the survivors then
    /// replace the live corpus (tagged `CorpusSource::Minimized`). Engine-
    /// agnostic: it compiles its own coverage binary rather than reusing the
    /// run's. Returns the entry counts before and after. When the coverage
    /// tooling is unavailable the corpus is left untouched and the two counts
    /// are equal.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory cannot be read or
    /// rewritten.
    pub async fn corpus_minimize(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<MinimizeOutcome, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let before = hf_corpus::list(&corpus_dir)?.entries.len();
        if !workspace.join("harness.c").exists() || before == 0 {
            return Ok(MinimizeOutcome {
                before,
                after: before,
            });
        }
        // Build the coverage binary and run libFuzzer's coverage-guided merge
        // into a clean directory, all inside the sandbox.
        let min_host = workspace.join("corpus_min");
        let _ = std::fs::remove_dir_all(&min_host);
        let pipeline = "clang -g -O1 -fsanitize=fuzzer,address *.c -o fuzz_min 2>/dev/null \
             && rm -rf corpus_min && mkdir -p corpus_min \
             && ./fuzz_min -merge=1 corpus_min corpus 2>/dev/null";
        let cmd = vec!["sh".to_owned(), "-c".to_owned(), pipeline.to_owned()];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 300,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        // If the sandbox build/merge fails or yields nothing, leave the corpus
        // untouched rather than wiping it on tooling failure.
        match self.runtime.run_command(&cmd, &workspace, &limits).await {
            Ok(_)
                if min_host.is_dir()
                    && std::fs::read_dir(&min_host).is_ok_and(|mut d| d.next().is_some()) => {}
            Ok(_) => {
                tracing::info!("corpus minimize produced no merged set; leaving corpus untouched");
                return Ok(MinimizeOutcome {
                    before,
                    after: before,
                });
            }
            Err(e) => {
                tracing::warn!("corpus minimize failed: {e}");
                return Ok(MinimizeOutcome {
                    before,
                    after: before,
                });
            }
        }
        let mut minimized = hf_corpus::minimize(&corpus_dir, &min_host)?;
        let _ = std::fs::remove_dir_all(&min_host);
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;
        minimized.target_id = target_id;
        self.persist_corpus(target_id, &minimized).await;
        Ok(MinimizeOutcome {
            before,
            after: minimized.entries.len(),
        })
    }

    // -- Chat -------------------------------------------------------------

    /// Send a chat message to the LLM provider pool.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if no provider is configured or the LLM
    /// call fails.
    pub async fn chat_send(&self, message: &str) -> Result<String, ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;
        let pool = self
            .provider_pool()
            .ok_or_else(|| ClassifiedError::Provider("no LLM provider configured".to_owned()))?;
        let messages = vec![
            Message::system(
                "You are hobot_fuzz, an AI fuzzing assistant. You help users discover \
                 fuzzing targets, generate harnesses, run fuzzing engines, triage crashes, \
                 and manage corpora. Be concise and actionable.",
            ),
            Message::user(message),
        ];
        let req = ChatRequest::from_messages(messages);
        let resp = pool
            .chat_completion(
                &req,
                &RouteRequest::with_tags(&["general", "reasoning", "code"]),
            )
            .await?;
        self.diagnostics
            .record("chat", &resp.model, &resp.usage)
            .await;
        Ok(resp.text().to_owned())
    }
}

// ---------------------------------------------------------------------------
// Environment-driven construction
// ---------------------------------------------------------------------------

/// Build the sandbox runtime from the environment: a Docker runtime when the
/// daemon is reachable (and `HF_USE_DOCKER` is not disabled), else the stub.
#[must_use]
pub fn runtime_from_env() -> Arc<dyn RuntimeAdapter> {
    let use_docker = std::env::var("HF_USE_DOCKER").map_or(true, |v| v != "0" && v != "false");
    if use_docker && hf_runtime::docker_daemon_ready() {
        let cfg = RuntimeConfig::default();
        Arc::new(hf_runtime::docker::DockerRuntime::new(cfg, Path::new(".")))
    } else {
        Arc::new(hf_runtime::StubRuntime)
    }
}

/// Build an LLM provider pool from `HF_PROVIDER_*` env vars, or `None` when no
/// API key is configured.
#[must_use]
pub fn provider_pool_from_env() -> Option<Arc<dyn ProviderPool>> {
    let api_key = std::env::var("HF_PROVIDER_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())?;
    let model = std::env::var("HF_PROVIDER_MODEL").unwrap_or_else(|_| "gpt-4o".to_owned());
    let base_url = std::env::var("HF_PROVIDER_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1".to_owned());
    // Build a single-provider pool through the TOML schema so every
    // ProviderConfig field receives its serde default without an unwieldy
    // struct literal.
    let toml_str = format!(
        "[[providers]]
\
         id = \"env\"
\
         provider_type = \"openai-compat\"
\
         model = \"{model}\"
\
         api_key = \"{api_key}\"
\
         base_url = \"{base_url}\"
\
         tags = [\"general\", \"reasoning\", \"code\"]
"
    );
    let cfg: hf_provider::ProviderPoolConfig = toml::from_str(&toml_str).ok()?;
    hf_provider::ProviderPoolImpl::from_config(&cfg)
        .ok()
        .map(|p| Arc::new(p) as Arc<dyn ProviderPool>)
}

/// Build an LLM provider pool from `config/providers.toml` (the file the GUI
/// Settings -> Providers tab writes). Returns `None` if the file is missing,
/// unparsable, or has no enabled provider.
#[must_use]
pub fn provider_pool_from_config() -> Option<Arc<dyn ProviderPool>> {
    let path = crate::init::config_dir().join("providers.toml");
    let text = std::fs::read_to_string(&path).ok()?;
    let cfg: hf_provider::ProviderPoolConfig = toml::from_str(&text).ok()?;
    if !cfg.providers.iter().any(|p| p.enabled) {
        return None;
    }
    match hf_provider::ProviderPoolImpl::from_config(&cfg) {
        Ok(pool) => Some(Arc::new(pool) as Arc<dyn ProviderPool>),
        Err(e) => {
            tracing::warn!("failed to build provider pool from config: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome types
// ---------------------------------------------------------------------------

/// The result of a harness compile.
#[derive(Debug, Clone)]
pub struct CompileOutcome {
    pub status: HarnessStatus,
    pub binary_name: String,
    pub workspace: PathBuf,
}

/// A generated seed entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SeedEntry {
    pub name: String,
    pub size: usize,
    pub sha256: String,
}

/// The result of a corpus minimization pass: entry counts before and after.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct MinimizeOutcome {
    pub before: usize,
    pub after: usize,
}

/// Outcome of replaying one stored crash input against the current harness.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegressionResult {
    /// Persisted crash id (empty if the input came from the output dir).
    pub crash_id: String,
    /// The crash input that was replayed.
    pub input: String,
    /// True if the input still triggers a crash (a regression / unfixed bug).
    pub still_crashes: bool,
    /// A short trace/summary line from the replay.
    pub summary: String,
}

/// Per-provider health + usage for the Observability panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderSnapshot {
    pub id: String,
    pub model: String,
    pub tags: Vec<String>,
    pub is_frozen: bool,
    pub active_requests: usize,
    pub max_concurrency: usize,
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub estimated_cost_usd: f64,
}

/// A single running agent instance (hobot has no live agent pool yet, so this is
/// reserved for forward compatibility and always empty for now).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInstanceSnapshot {
    pub instance_id: String,
    pub agent_name: String,
    pub state: String,
    pub elapsed_ms: u64,
    pub iterations: u32,
    pub tokens_used: u64,
}

/// Agent pool state. `available_slots` is the number of agent definitions that
/// can be run; hobot runs agents per-turn rather than as a persistent pool, so
/// `active`/`total`/`instances` stay zero/empty until that lands.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AgentPoolSnapshot {
    pub active_instances: usize,
    pub available_slots: usize,
    pub total_instances: usize,
    pub instances: Vec<AgentInstanceSnapshot>,
}

/// Runtime/state counters for the Observability panel's Memory section.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct MemorySnapshot {
    pub pending_runs: usize,
    pub interrupted_runs: usize,
    pub llm_calls: u64,
    pub targets: usize,
    pub crashes: usize,
}

/// A live snapshot of system state for the Observability panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemSnapshot {
    pub providers: Vec<ProviderSnapshot>,
    pub agents: AgentPoolSnapshot,
    pub memory: MemorySnapshot,
}

/// A cheap snapshot of a target's on-disk artifacts, for the Info panel.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ArtifactSummary {
    /// Whether the compiled harness binary (`fuzz_<target>`) exists.
    pub harness_built: bool,
    /// Number of corpus inputs on disk.
    pub corpus_count: usize,
    /// Number of crash inputs staged in the run output directory.
    pub crash_count: usize,
}

/// A fuzz run summary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSummary {
    pub edges: u64,
    pub execs: f64,
    pub crashes: u64,
}

/// Inputs for a syzkaller kernel-fuzzing campaign.
#[derive(Debug, Clone, Default)]
pub struct SyzkallerRunOpts {
    /// Project label (for logging only).
    pub project: String,
    /// Target architecture (e.g. `"amd64"`); defaults to the host platform.
    pub arch: Option<String>,
    /// Campaign duration in seconds.
    pub duration_secs: u64,
    /// Path to a KCOV kernel image (bzImage). Required without `manager_cfg`.
    pub kernel_image: Option<String>,
    /// Path to a rootfs disk image. Required without `manager_cfg`.
    pub disk_image: Option<String>,
    /// Optional SSH private key for the VM.
    pub ssh_key: Option<String>,
    /// Path to an existing `syz-manager` config; bypasses synthesis.
    pub manager_cfg: Option<String>,
    /// Number of fuzzing VMs (default 2).
    pub vm_count: Option<u32>,
}

/// Result of a syzkaller campaign.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SyzkallerSummary {
    pub edges: u64,
    pub execs: f64,
    pub crashes: u64,
    pub exit_code: Option<i32>,
}

// ---------------------------------------------------------------------------
// LLM provider bridge: wraps a ProviderPool as a single LlmProvider
// ---------------------------------------------------------------------------

struct LlmProviderBridge {
    pool: Arc<dyn ProviderPool>,
    meta: hf_core::provider::ProviderMetadata,
    /// When set, each completion is recorded as a cost/trace diagnostic under
    /// the given operation label.
    diag: Option<(Arc<crate::diagnostics::DiagnosticsRecorder>, String)>,
}

impl LlmProviderBridge {
    fn new(pool: Arc<dyn ProviderPool>) -> Self {
        use hf_core::provider::{
            ProviderCapability, ProviderMetadata, ProviderType, ToolCallingMode,
        };
        let meta = ProviderMetadata {
            id: hf_core::types::ProviderId::from_string("pool-bridge"),
            provider_type: ProviderType::Custom,
            model: String::new(),
            tags: Vec::new(),
            capabilities: vec![ProviderCapability::Text],
            max_concurrency: 1,
            context_window: 128_000,
            cost_per_1k_input: 0.0,
            cost_per_1k_output: 0.0,
            tool_calling_mode: ToolCallingMode::PromptBased,
        };
        Self {
            pool,
            meta,
            diag: None,
        }
    }

    /// Record completions through this bridge as diagnostics under `op`.
    fn with_diagnostics(
        mut self,
        recorder: Arc<crate::diagnostics::DiagnosticsRecorder>,
        op: &str,
    ) -> Self {
        self.diag = Some((recorder, op.to_owned()));
        self
    }
}

#[async_trait::async_trait]
impl hf_core::provider::LlmProvider for LlmProviderBridge {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        let response = self
            .pool
            .chat_completion(request, &hf_core::provider::RouteRequest::default())
            .await?;
        if let Some((recorder, op)) = &self.diag {
            recorder.record(op, &response.model, &response.usage).await;
        }
        Ok(response)
    }

    async fn chat_completion_stream(
        &self,
        request: &hf_core::provider::ChatRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        self.pool
            .chat_completion_stream(request, &hf_core::provider::RouteRequest::default())
            .await
    }

    fn metadata(&self) -> &hf_core::provider::ProviderMetadata {
        &self.meta
    }
}

// ---------------------------------------------------------------------------
// Heuristic harness draft (no-LLM fallback)
// ---------------------------------------------------------------------------

/// Generate a heuristic harness draft when no LLM provider is configured.
fn heuristic_draft(candidate: &TargetCandidate, engine: EngineKind) -> HarnessDraft {
    let includes = generate_includes(candidate);
    let forward_decl = generate_forward_decl(&candidate.symbol, candidate.signature.as_deref());
    let body = generate_harness_body(&candidate.symbol, candidate.signature.as_deref());
    let source = format!(
        r"// Auto-generated harness for {symbol}
// Engine: {engine}
// Target: {file}:{line}
#include <stdint.h>
#include <stddef.h>
{includes}
{forward_decl}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Target signature: {sig}
{body}
    return 0;
}}
",
        symbol = candidate.symbol,
        engine = engine_label(engine),
        file = candidate.location.file.display(),
        line = candidate.location.line,
        includes = includes,
        forward_decl = forward_decl,
        sig = candidate.signature.as_deref().unwrap_or("(unknown)"),
        body = body,
    );
    HarnessDraft {
        target_id: candidate.id,
        engine,
        source,
        rationale: String::new(),
        build_cmd: hf_harness::build_command(
            engine,
            candidate.language,
            &format!("fuzz_{}", candidate.symbol),
        ),
    }
}

fn engine_label(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::LibFuzzer => "libFuzzer",
        EngineKind::AflPlusPlus => "AFL++",
        EngineKind::Honggfuzz => "honggfuzz",
        EngineKind::ClusterFuzzLite => "ClusterFuzzLite",
        EngineKind::Syzkaller => "syzkaller",
    }
}

/// Build the `#include` line for a target's header.
fn generate_includes(candidate: &TargetCandidate) -> String {
    let file = &candidate.location.file;
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("target");
    format!("#include \"{stem}.h\"")
}

/// Build a forward declaration for the target function so the harness
/// compiles even when the header does not export the symbol.
///
/// Uses the signature captured by the scanner (the declarator portion of the
/// function definition).  We prepend the return type that the scanner strips
/// out (best-effort: assume `int` when unknown) and terminate with `;`.
fn generate_forward_decl(symbol: &str, signature: Option<&str>) -> String {
    let Some(sig) = signature else {
        return format!("int {symbol}();");
    };
    // The scanner stores the declarator, e.g. "parse_value_inner(const char
    // *buf, size_t len, value_t *out, int *err)".  Use it verbatim and append
    // `;` to form a prototype.  When the return type is not visible we
    // declare it as `int` (C default) so the compiler has a prototype.
    let trimmed = sig.trim();
    if trimmed.is_empty() {
        return format!("int {symbol}();");
    }
    // If the declarator already has a return type prefix, keep it; otherwise
    // assume int.
    let has_return_type = trimmed.split_whitespace().next().is_some_and(|first_word| {
        // If the first token contains the function name (starts with the
        // symbol or has no space before the opening paren) there is no
        // explicit return type in the declarator.
        !first_word.starts_with(symbol) && first_word != symbol
    });
    if has_return_type {
        format!("{trimmed};")
    } else {
        format!("int {trimmed};")
    }
}

/// Build the body of `LLVMFuzzerTestOneInput` for a target.
fn generate_harness_body(symbol: &str, signature: Option<&str>) -> String {
    let fallback = format!("    {symbol}((const char *)data, size);");
    let Some(sig) = signature else {
        return fallback;
    };
    let (Some(open), Some(close)) = (sig.find('('), sig.rfind(')')) else {
        return fallback;
    };
    let params_str = &sig[open + 1..close];
    let params: Vec<&str> = params_str
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "void")
        .collect();
    if params.is_empty() {
        return fallback;
    }

    let mut decls: Vec<String> = Vec::new();
    let mut args: Vec<String> = Vec::new();
    let mut buffer_used = false;

    for (i, param) in params.iter().enumerate() {
        let star_count = param.matches('*').count();
        let is_char_like =
            param.contains("char") || param.contains("uint8") || param.contains("void");
        if star_count == 1 && is_char_like && !buffer_used {
            args.push("(const char *)data".to_string());
            buffer_used = true;
        } else if star_count >= 1 {
            let base = param[..param.find('*').unwrap_or(param.len())]
                .trim()
                .trim_start_matches("const ")
                .trim();
            let base = if base.is_empty() { "char" } else { base };
            decls.push(format!("    {base} _arg{i} = {{0}};"));
            args.push(format!("&_arg{i}"));
        } else {
            args.push("size".to_string());
        }
    }

    let mut body = String::new();
    for d in &decls {
        body.push_str(d);
        body.push('\n');
    }
    let _ = write!(body, "    {symbol}({});", args.join(", "));
    body
}

#[cfg(test)]
mod coverage_tests {
    use super::parse_covered_functions;

    #[test]
    fn parses_covered_functions_from_llvm_cov_json() {
        let json = r#"{"data":[{"functions":[
            {"name":"parse_entry","count":5},
            {"name":"validate","count":2},
            {"name":"never_called","count":0},
            {"name":"decode","count":3}
        ]}]}"#;
        let covered = parse_covered_functions(json);
        assert_eq!(covered, vec!["decode", "parse_entry", "validate"]);
        assert!(!covered.contains(&"never_called".to_owned()));
    }

    #[test]
    fn parse_handles_garbage() {
        assert!(parse_covered_functions("not json").is_empty());
        assert!(parse_covered_functions("{}").is_empty());
    }

    #[test]
    fn coverage_signature_changes_when_corpus_grows() {
        use super::coverage_signature;
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        std::fs::write(ws.join("harness.c"), "x").unwrap();
        std::fs::create_dir_all(ws.join("corpus")).unwrap();
        std::fs::write(ws.join("corpus/a"), "1").unwrap();

        let sig1 = coverage_signature(ws);
        // Same inputs -> same signature (cache hit).
        assert_eq!(sig1, coverage_signature(ws));
        // A new corpus file -> different signature (cache invalidated).
        std::fs::write(ws.join("corpus/b"), "2").unwrap();
        assert_ne!(sig1, coverage_signature(ws));
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::workspace_dir;
    use std::path::{Component, Path};

    /// The per-project workspace base every resolved path must stay within.
    fn base(project: &Path) -> std::path::PathBuf {
        super::workspace_root().join(project.file_name().unwrap())
    }

    #[test]
    fn workspace_root_uses_dedicated_app_workspace_root() {
        // With no override the workspace root normally lives under the
        // platform app-data dir. In restricted environments that path can be
        // unwritable, so `user_app_dir` may fall back to temp; either way,
        // artifacts stay under a dedicated hobot_fuzz/workspaces root rather
        // than directly in the OS temp directory.
        let root = super::workspace_root_from(None);
        assert!(root.ends_with(std::path::Path::new("hobot_fuzz").join("workspaces")));
        assert_ne!(root, std::env::temp_dir());
    }

    #[test]
    fn workspace_root_honors_env_override() {
        let root = super::workspace_root_from(Some("/mnt/scratch/hf".into()));
        assert_eq!(root, std::path::PathBuf::from("/mnt/scratch/hf"));
        // An empty override falls back to the persistent default.
        let empty = super::workspace_root_from(Some(String::new().into()));
        assert!(empty.ends_with("workspaces"));
    }

    #[test]
    fn normal_target_is_preserved() {
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "parse_json");
        assert_eq!(ws, base(project).join("parse_json"));
    }

    #[test]
    fn cpp_style_target_is_preserved() {
        // C++ symbols contain `::`; that is filesystem-safe and must survive.
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "ns::Class::method");
        assert_eq!(ws, base(project).join("ns::Class::method"));
    }

    #[test]
    fn dotdot_target_cannot_escape_workspace() {
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "../../../../etc/evil");
        // Stays inside the project workspace base...
        assert!(
            ws.starts_with(base(project)),
            "escaped workspace: {}",
            ws.display()
        );
        // ...and contains no parent-dir traversal components.
        assert!(
            !ws.components().any(|c| c == Component::ParentDir),
            "path retained `..`: {}",
            ws.display()
        );
    }

    #[test]
    fn absolute_target_cannot_escape_workspace() {
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "/etc/passwd");
        assert!(
            ws.starts_with(base(project)),
            "escaped workspace: {}",
            ws.display()
        );
        assert_ne!(ws, Path::new("/etc/passwd"));
    }

    #[test]
    fn empty_or_all_traversal_target_falls_back() {
        let project = Path::new("/home/user/myproj");
        assert_eq!(workspace_dir(project, ""), base(project).join("default"));
        assert_eq!(
            workspace_dir(project, "../.."),
            base(project).join("default")
        );
    }
}

#[cfg(test)]
mod crash_id_tests {
    use super::deterministic_crash_id;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn same_run_signature_and_input_yield_the_same_id() {
        // Re-triaging the same crash must produce the same id (idempotent
        // persistence -> INSERT OR REPLACE collapses the duplicate).
        let run = Uuid::new_v4();
        let a = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        let b = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_runs_or_signatures_yield_distinct_ids() {
        let run = Uuid::new_v4();
        let base = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        // Different input file -> different id (keeps distinct crashes apart).
        assert_ne!(
            base,
            deterministic_crash_id(run, "sig", Path::new("/work/out/crash-def"))
        );
        // Different signature -> different id.
        assert_ne!(
            base,
            deterministic_crash_id(run, "other", Path::new("/work/out/crash-abc"))
        );
        // Different run -> different id.
        assert_ne!(
            base,
            deterministic_crash_id(Uuid::new_v4(), "sig", Path::new("/work/out/crash-abc"))
        );
    }
}
