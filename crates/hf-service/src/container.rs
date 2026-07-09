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
use hf_storage::{ProjectAutoRevert, RunRecord, RunStatus, Store};
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
    workspace_root()
        .join(project_slug(project))
        .join(sanitize_target(target))
}

/// The on-disk workspace directory holding every target's artifacts for a
/// single project (compiled harnesses, corpora, crash reproducers, coverage
/// builds). This is the parent of the per-target [`workspace_dir`] directories,
/// and the unit removed when a project is deleted.
pub fn project_workspace_dir(project: &Path) -> PathBuf {
    workspace_root().join(project_slug(project))
}

/// A per-project workspace directory name: the human-readable basename plus a
/// short deterministic hash of the full path. The hash disambiguates projects
/// that share a basename (e.g. `/a/libfoo` and `/b/libfoo`) so their persistent
/// workspaces -- and thus compiled binaries, corpora, and crash reproducers --
/// never collide, while the basename keeps the directory recognizable. Stable
/// across processes (SHA-256, unlike `DefaultHasher`), so the same project maps
/// to the same workspace on every invocation.
fn project_slug(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    let name = project
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");
    let mut hasher = Sha256::new();
    hasher.update(project.to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("{name}-{}", &digest[..8])
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

/// Build a fuzzing dictionary from the C/C++ sources in `workspace`, writing it
/// to `<workspace>/<dict_name>` and returning that path.
///
/// The literals a target compares against (magic bytes, format keywords) are
/// among the cheapest ways to get a fuzzer past shallow `memcmp`/keyword gates,
/// so seeding the engine dictionary with them measurably deepens coverage.
/// Returns `None` when no usable literals were found (so the caller adds no
/// dictionary flag) or the file cannot be written.
fn build_workspace_dictionary(workspace: &Path, dict_name: &str) -> Option<PathBuf> {
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let entries = std::fs::read_dir(workspace).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "hh") {
            continue;
        }
        // Skip the generated harness itself -- its literals are hobot's, not
        // the target's, and add noise.
        if path.file_stem().and_then(|s| s.to_str()) == Some("harness") {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(&path) {
            for token in hf_engine::dict::extract_tokens(&src) {
                if seen.insert(token.clone()) {
                    tokens.push(token);
                }
            }
        }
    }
    if tokens.is_empty() {
        return None;
    }
    let dict_path = workspace.join(dict_name);
    std::fs::write(&dict_path, hf_engine::dict::render_dict(&tokens)).ok()?;
    Some(dict_path)
}

/// Concatenate the target's C/C++ sources (excluding the generated harness)
/// into a single, size-bounded string for root-cause analysis. Returns `None`
/// when there are no sources to include.
fn gather_source_context(workspace: &Path) -> Option<String> {
    let mut out = String::new();
    let entries = std::fs::read_dir(workspace).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "hh") {
            continue;
        }
        if path.file_stem().and_then(|s| s.to_str()) == Some("harness") {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(&path) {
            use std::fmt::Write as _;
            if out.len() >= hf_crash::MAX_SOURCE_CONTEXT_CHARS {
                break;
            }
            let _ = writeln!(out, "// {}", path.display());
            out.push_str(&src);
            out.push('\n');
        }
    }
    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Read the current harness source from a target workspace, trying the known
/// per-language harness filenames. Returns `None` when none exists yet.
fn read_current_harness_source(workspace: &Path) -> Option<String> {
    for name in [
        "harness.c",
        "harness.cc",
        "harness.cpp",
        "harness.cxx",
        "harness.rs",
        "harness.go",
    ] {
        if let Ok(src) = std::fs::read_to_string(workspace.join(name)) {
            if !src.trim().is_empty() {
                return Some(src);
            }
        }
    }
    None
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

/// Map a `.casrep` path back to the crash input it analyzed. CASR names each
/// report after its input file (`id:000….casrep` -> `id:000…`); match that
/// filename against the actual crash inputs so an AFL++ input nested under
/// `out/<instance>/crashes/` resolves to its real location rather than a
/// nonexistent `out/<name>` (which broke `verify_regressions`/reproduce). Falls
/// back to the flat `out_dir/<name>` layout (libFuzzer) when not found.
fn casrep_input_path(out_dir: &Path, casrep: &Path, crash_inputs: &[PathBuf]) -> PathBuf {
    let Some(stem) = casrep.file_stem().and_then(|s| s.to_str()) else {
        return casrep.to_path_buf();
    };
    crash_inputs
        .iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(stem))
        .cloned()
        .unwrap_or_else(|| out_dir.join(stem))
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
///
/// For Rust projects it also stages the crate under test -- `Cargo.toml`,
/// `Cargo.lock`, and the `src/` tree -- so the cargo-fuzz project's path
/// dependency on the crate resolves inside the sandbox.
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
    stage_rust_crate(project, workspace);
}

/// Stage a Rust crate (its manifest + `src/` tree) from `project` into
/// `workspace` so a cargo-fuzz project can depend on it by path. A no-op when the
/// project has no `Cargo.toml` (i.e. is not a Rust crate).
fn stage_rust_crate(project: &Path, workspace: &Path) {
    let manifest = project.join("Cargo.toml");
    if !manifest.is_file() {
        return;
    }
    for name in ["Cargo.toml", "Cargo.lock"] {
        let src = project.join(name);
        if src.is_file() {
            if let Err(e) = std::fs::copy(&src, workspace.join(name)) {
                tracing::warn!("failed to stage {} into workspace: {e}", src.display());
            }
        }
    }
    let src_dir = project.join("src");
    if src_dir.is_dir() {
        if let Err(e) = copy_dir_recursive(&src_dir, &workspace.join("src")) {
            tracing::warn!("failed to stage crate src/ into workspace: {e}");
        }
    }
}

/// Recursively copy a directory tree, creating destination directories as needed.
fn copy_dir_recursive(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)?.flatten() {
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if path.is_dir() {
            copy_dir_recursive(&path, &dest)?;
        } else if path.is_file() {
            std::fs::copy(&path, &dest)?;
        }
    }
    Ok(())
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
    /// Per-session locks serializing chat turns on the same session. A turn is a
    /// read-modify-write over the transcript (read history, run the turn, append
    /// user+assistant + checkpoint); two concurrent turns on one session would
    /// otherwise interleave appends and mint duplicate checkpoint turn numbers.
    /// Different sessions still run concurrently. Shared across clones.
    session_turn_locks: Arc<
        std::sync::Mutex<
            std::collections::HashMap<hf_core::types::SessionId, Arc<tokio::sync::Mutex<()>>>,
        >,
    >,
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
    // Persist checkpoints in the DB so turn-level rollback survives a restart
    // (the in-memory store lost them on exit, silently no-op'ing rollback).
    let checkpoint_store: Arc<dyn ChatCheckpointStore> = Arc::new(
        hf_storage::SqliteChatCheckpointStore::new(store.pool().clone()),
    );

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
            session_turn_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
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
        let mut valid: Vec<_> = list.into_iter().filter(|c| !c.invalidated).collect();
        // Present turns oldest-first for the picker, regardless of the store's
        // list ordering (the trait returns them newest-first).
        valid.sort_by_key(|c| c.turn_number);
        valid
            .into_iter()
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

    /// Delete a chat session and its transcript (used by the "clear history"
    /// action). No-op when no session store is configured. Returns whether a
    /// deletion was performed.
    pub async fn delete_chat_session(&self, session: &hf_core::types::SessionId) -> bool {
        let Some(manager) = self.session_manager.as_ref() else {
            return false;
        };
        manager.delete_session(session).await.is_ok()
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

    /// The lock serializing chat turns on `session`, creating it on first use.
    /// Held for the whole turn so concurrent turns on one session run one at a
    /// time; distinct sessions take distinct locks and are unaffected.
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

    /// Run history for a project (or all projects when `None`), newest first,
    /// enriched with the crash count per run. Powers the Runs history view.
    pub async fn run_history(&self, project: Option<&Path>) -> Vec<RunHistoryItem> {
        let Some(store) = self.store.as_ref() else {
            return Vec::new();
        };
        let key = project.map(|p| p.to_string_lossy().to_string());
        let runs = store.list_runs(key.as_deref()).await.unwrap_or_default();
        let crashes = store.list_all_crashes().await.unwrap_or_default();
        let mut crashes_by_run: std::collections::HashMap<Uuid, usize> =
            std::collections::HashMap::new();
        for c in &crashes {
            *crashes_by_run.entry(c.run_id).or_insert(0) += 1;
        }
        let mut items: Vec<RunHistoryItem> = runs
            .into_iter()
            .map(|r| {
                let duration_secs = r
                    .ended_at
                    .map(|end| (end - r.started_at).num_seconds().max(0));
                RunHistoryItem {
                    id: r.id.to_string(),
                    project_root: r.project_root,
                    engine: format!("{:?}", r.engine),
                    status: format!("{:?}", r.status),
                    started_at: r.started_at.to_rfc3339(),
                    ended_at: r.ended_at.map(|t| t.to_rfc3339()),
                    duration_secs,
                    // Prefer the fuzzer's recorded crash count (available even
                    // without triage); fall back to the deduped crashes table
                    // for runs recorded before stats were persisted.
                    crashes: r.crash_count.map_or_else(
                        || crashes_by_run.get(&r.id).copied().unwrap_or(0),
                        |c| usize::try_from(c).unwrap_or(0),
                    ),
                    edges: r.edges,
                    execs: r.execs,
                    harness_rev: r.harness_rev,
                }
            })
            .collect();
        items.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        items
    }

    /// The intra-run coverage/throughput curve for a run (empty if none was
    /// recorded, e.g. runs from before this was captured).
    pub async fn run_coverage_series(&self, run_id: &str) -> Vec<CoverageSample> {
        let Some(store) = self.store.as_ref() else {
            return Vec::new();
        };
        let Ok(id) = Uuid::parse_str(run_id) else {
            return Vec::new();
        };
        match store.run_samples(id).await {
            Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// The harness source a run used, for diffing revisions (empty if none was
    /// recorded).
    pub async fn run_harness_source(&self, run_id: &str) -> String {
        let Some(store) = self.store.as_ref() else {
            return String::new();
        };
        let Ok(id) = Uuid::parse_str(run_id) else {
            return String::new();
        };
        store
            .run_harness_source(id)
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Restore the harness a run used and recompile it, so it becomes the
    /// current harness for that target -- a one-click revert to an earlier (e.g.
    /// last-good) revision. Everything (source, engine, target, language) is
    /// resolved from the persisted run + harness records.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run/harness/source cannot be resolved or
    /// the recompile fails.
    pub async fn revert_harness_from_run(
        &self,
        run_id: &str,
    ) -> Result<CompileOutcome, ClassifiedError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let id = Uuid::parse_str(run_id)
            .map_err(|e| ClassifiedError::Validation(format!("bad run id: {e}")))?;
        let source = store
            .run_harness_source(id)
            .await?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ClassifiedError::Validation(
                    "no harness source was recorded for this run".to_owned(),
                )
            })?;
        let run = store
            .get_run(id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation("run not found".to_owned()))?;
        let harness_id = run.config.as_ref().map(|c| c.harness_id).ok_or_else(|| {
            ClassifiedError::Validation("run has no harness reference".to_owned())
        })?;
        let harness = store.get_harness(harness_id).await?.ok_or_else(|| {
            ClassifiedError::Validation("the harness for this run no longer exists".to_owned())
        })?;
        let symbol = store
            .list_all_targets()
            .await?
            .into_iter()
            .find(|t| t.id == harness.target_id)
            .map(|t| t.symbol)
            .ok_or_else(|| {
                ClassifiedError::Validation("the target for this run no longer exists".to_owned())
            })?;
        let project = std::path::PathBuf::from(&run.project_root);
        self.harness_compile(source, &project, harness.engine, &symbol, harness.language)
            .await
    }

    /// The target a persisted run exercised, resolved through its harness
    /// (`run.config.harness_id -> harness.target_id`). `None` if unrecorded.
    async fn run_target_id(&self, store: &Store, run: &RunRecord) -> Option<Uuid> {
        let harness_id = run.config.as_ref().map(|c| c.harness_id)?;
        let harness = store.get_harness(harness_id).await.ok().flatten()?;
        Some(harness.target_id)
    }

    /// The effective auto-revert policy for a project: its stored per-project
    /// override when one is set, otherwise the global policy from config.
    async fn effective_auto_revert_policy(
        &self,
        project: &Path,
    ) -> crate::config::AutoRevertPolicy {
        if let Some(store) = self.store.as_ref() {
            let key = project.to_string_lossy().to_string();
            if let Ok(Some(o)) = store.project_auto_revert(&key).await {
                return crate::config::AutoRevertPolicy {
                    enabled: o.enabled,
                    threshold_pct: o.threshold_pct,
                    notify_only: o.notify_only,
                };
            }
        }
        crate::config::auto_revert_policy()
    }

    /// A project's auto-revert override, or `None` when it inherits the global
    /// policy. For the settings UI to show whether an override is in effect.
    pub async fn project_auto_revert_override(&self, project: &Path) -> Option<ProjectAutoRevert> {
        let store = self.store.as_ref()?;
        let key = project.to_string_lossy().to_string();
        store.project_auto_revert(&key).await.ok().flatten()
    }

    /// Set (or replace) a project's auto-revert override.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when no store is configured or the write fails.
    pub async fn set_project_auto_revert_override(
        &self,
        project: &Path,
        enabled: bool,
        threshold_pct: f64,
        notify_only: bool,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let key = project.to_string_lossy().to_string();
        // Guard the threshold like the global resolver does (must be positive).
        let threshold_pct = if threshold_pct > 0.0 {
            threshold_pct
        } else {
            crate::config::DEFAULT_AUTO_REVERT_THRESHOLD_PCT
        };
        store
            .set_project_auto_revert(
                &key,
                ProjectAutoRevert {
                    enabled,
                    threshold_pct,
                    notify_only,
                },
            )
            .await?;
        Ok(())
    }

    /// Clear a project's auto-revert override, so it inherits the global policy.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when no store is configured or the delete fails.
    pub async fn clear_project_auto_revert_override(
        &self,
        project: &Path,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let key = project.to_string_lossy().to_string();
        store.clear_project_auto_revert(&key).await?;
        Ok(())
    }

    /// Evaluate the auto-revert policy for a just-finished run and, if it
    /// triggered, restore the previous (last-good) harness revision.
    ///
    /// The policy fires only when it is enabled and this run's harness revision
    /// differs from the previous finished run for the same target *and* this
    /// run's peak edge coverage dropped by at least the configured percentage
    /// versus that previous run. The restore reuses
    /// [`Self::revert_harness_from_run`], so the recompile is HITL-gated exactly
    /// like a manual revert -- a denied approval simply leaves the harness
    /// unchanged. Returns the outcome only when the revert actually applied.
    async fn maybe_auto_revert(
        &self,
        project: &Path,
        target: &str,
        this_run_id: Uuid,
        this_edges: u64,
        this_rev: Option<&str>,
    ) -> Option<AutoRevertOutcome> {
        let policy = self.effective_auto_revert_policy(project).await;
        if !policy.enabled {
            return None;
        }
        let store = self.store.as_ref()?;
        // Without a recorded revision we cannot attribute a change to a harness.
        let this_rev = this_rev.filter(|r| !r.is_empty())?;
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;

        // The most recent finished run for this same target, before this one,
        // that recorded edge coverage and a harness revision -- the baseline.
        let key = project.to_string_lossy().to_string();
        let mut runs = store.list_runs(Some(&key)).await.unwrap_or_default();
        runs.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        let this_started = runs
            .iter()
            .find(|r| r.id == this_run_id)
            .map(|r| r.started_at);
        let mut prev = None;
        for r in runs {
            if r.id == this_run_id
                || r.status != RunStatus::Done
                || r.edges.is_none()
                || r.harness_rev.is_none()
            {
                continue;
            }
            if let Some(t) = this_started {
                if r.started_at >= t {
                    continue;
                }
            }
            if self.run_target_id(store, &r).await == Some(target_id) {
                prev = Some(r);
                break;
            }
        }
        let prev = prev?;
        let prev_rev = prev.harness_rev.clone().unwrap_or_default();
        let prev_edges = prev.edges.unwrap_or(0);
        let drop_pct = auto_revert_decision(
            &prev_rev,
            this_rev,
            prev_edges,
            this_edges,
            policy.threshold_pct,
        )?;

        let prev_id = prev.id.to_string();
        let outcome = |reverted: bool| AutoRevertOutcome {
            reverted_to_run: prev_id.clone(),
            from_rev: this_rev.to_owned(),
            to_rev: prev_rev.clone(),
            previous_edges: prev_edges,
            regressed_edges: this_edges,
            drop_pct,
            reverted,
        };

        // Notify-only: report the regression (journal + surfaced outcome) but do
        // not touch the harness. This is the safe default for headless/scheduled
        // campaigns, which run permissively and would otherwise mutate unattended.
        if policy.notify_only {
            let detail = format!(
                "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev}; last-good {prev_rev} is run {prev_id} (notify-only, not restored)"
            );
            tracing::warn!("auto-revert (notify-only): {detail}");
            self.run_journal
                .note(this_run_id, "auto-revert-notify", &detail);
            return Some(outcome(false));
        }

        // Regression confirmed: restore the previous run's harness. The recompile
        // is HITL-gated inside `harness_compile`; if approval is denied the
        // revert errors and we leave everything as-is.
        match self.revert_harness_from_run(&prev_id).await {
            Ok(_) => {
                let detail = format!(
                    "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev} -> restored {prev_rev} from run {prev_id}"
                );
                tracing::warn!("auto-revert: {detail}");
                self.run_journal.note(this_run_id, "auto-revert", &detail);
                Some(outcome(true))
            }
            Err(e) => {
                tracing::warn!("auto-revert declined or failed: {e}");
                None
            }
        }
    }

    /// A JSON bundle of a project's persisted fuzzing data (targets, runs,
    /// harnesses, crashes, corpus) for hand-off to other tools. Scoped by
    /// project; pass `None` to export everything.
    pub async fn export_project_data(&self, project: Option<&Path>) -> serde_json::Value {
        let Some(store) = self.store.as_ref() else {
            return serde_json::json!({ "error": "no database configured" });
        };
        let key = project.map(|p| p.to_string_lossy().to_string());
        let targets = store.list_all_targets().await.unwrap_or_default();
        let scoped_targets: Vec<_> = match &key {
            Some(k) => targets
                .into_iter()
                .filter(|t| t.project_root.to_string_lossy() == *k)
                .collect(),
            None => targets,
        };
        let target_ids: std::collections::HashSet<Uuid> =
            scoped_targets.iter().map(|t| t.id).collect();
        let harnesses: Vec<_> = store
            .list_all_harnesses()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|h| key.is_none() || target_ids.contains(&h.target_id))
            .collect();
        let crashes: Vec<_> = store
            .list_all_crashes()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|c| key.is_none() || target_ids.contains(&c.target_id))
            .collect();
        let corpus: Vec<_> = store
            .list_all_corpus_entries()
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let runs = self.run_history(project).await;
        serde_json::json!({
            "schema": "hobot_fuzz.export.v1",
            "project": key,
            "targets": scoped_targets,
            "harnesses": harnesses,
            "crashes": crashes,
            "corpus": corpus,
            "runs": runs,
        })
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

    /// Internal-team dashboard summary for the active project/target.
    pub async fn workbench_dashboard(
        &self,
        project: Option<&Path>,
        target: Option<&str>,
    ) -> crate::workbench::WorkbenchDashboard {
        crate::workbench::dashboard(self.store.as_deref(), project, target).await
    }

    /// Generated harnesses that need human review or promotion.
    pub async fn harness_review_queue(
        &self,
        project: Option<&Path>,
        target: Option<&str>,
    ) -> Vec<crate::workbench::HarnessReviewItem> {
        crate::workbench::harness_review_queue(self.store.as_deref(), project, target).await
    }

    /// Build a human-reviewable GitLab issue draft for a crash.
    ///
    /// This is intentionally non-publishing: it returns a title, Markdown body,
    /// labels, and a prefilled issue URL when a GitLab remote/config is known.
    pub async fn gitlab_issue_export(
        &self,
        project: &Path,
        crash_id: &str,
    ) -> Result<crate::workbench::GitLabIssueExport, ClassifiedError> {
        crate::workbench::gitlab_issue_export(self.store.as_deref(), project, crash_id).await
    }

    /// Saved editable report drafts for the internal workbench.
    pub fn list_report_drafts(
        &self,
    ) -> Result<Vec<crate::report_store::ReportDraft>, ClassifiedError> {
        crate::report_store::list_report_drafts()
    }

    /// Save or update one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid input and storage errors for failed
    /// filesystem writes.
    pub fn save_report_draft(
        &self,
        id: Option<String>,
        title: &str,
        project: &str,
        target: Option<&str>,
        status: &str,
        content: &str,
    ) -> Result<crate::report_store::ReportDraft, ClassifiedError> {
        crate::report_store::save_report_draft(id, title, project, target, status, content)
    }

    /// Delete one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid ids and storage errors for failed
    /// filesystem deletion.
    pub fn delete_report_draft(&self, id: &str) -> Result<(), ClassifiedError> {
        crate::report_store::delete_report_draft(id)
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

    /// Ask the operator to approve an agent's tool call, for an agent running
    /// with manual autonomy that gates every action. Returns whether it was
    /// approved. Tighten-only: it only ever adds a prompt via the guardrail
    /// gate; it never bypasses the policy or auto-allows.
    pub async fn approve_agent_tool(&self, tool: &str, agent: &str) -> bool {
        self.guardrails
            .require_approval(
                &Action::AgentTool {
                    name: tool.to_owned(),
                },
                &format!("agent '{agent}' runs with manual autonomy and requests tool '{tool}'"),
            )
            .await
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
            session_turn_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
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

    /// Clear all learned knowledge across every project: discovered targets and
    /// their harnesses, corpus entries, and crashes, plus all runs.
    /// Configuration and on-disk workspaces are left untouched. A no-op when no
    /// store is configured.
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
        if let Some(store) = &self.store {
            let key = project.to_string_lossy();
            store
                .delete_project(&key)
                .await
                .map_err(|e| ClassifiedError::Internal(format!("delete project: {e}")))?;
        }
        let dir = project_workspace_dir(project);
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

    /// Delete every on-disk fuzz workspace (compiled harnesses, corpora, crash
    /// reproducers, coverage builds), reclaiming disk space. Since the
    /// workspace is now persistent, it grows over time; this is the affordance
    /// to reset it. Persistent DB records (targets, runs, crashes) are left
    /// intact -- re-running a campaign rebuilds the workspace on disk.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the workspace directory cannot be removed.
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

    /// Resolve the persisted harness id that a run should be linked to, so the
    /// target-scoped workbench dashboard can attribute the run to its target
    /// (runs carry only `config.harness_id`, and the dashboard maps that id back
    /// through the stored harness to the target). Prefers the harness compiled
    /// for the same engine, then any harness for the target; falls back to a
    /// fresh id only when nothing is persisted yet.
    async fn resolve_run_harness_id(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Uuid {
        let Some(store) = &self.store else {
            return Uuid::new_v4();
        };
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;
        let harnesses = store.list_harnesses(target_id).await.unwrap_or_default();
        select_run_harness(&harnesses, engine).unwrap_or_else(Uuid::new_v4)
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

    /// Draft the harness source for a candidate: LLM-authored when a provider is
    /// configured, otherwise the heuristic template. Never fails -- an LLM error
    /// degrades to the heuristic draft so generation can proceed.
    async fn draft_harness_source(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
    ) -> String {
        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            match hf_harness::draft(candidate, engine, Box::new(provider)).await {
                Ok(draft) => return draft.source,
                Err(e) => tracing::warn!(
                    "LLM harness draft for '{}' failed ({e}); using heuristic draft",
                    candidate.symbol
                ),
            }
        }
        heuristic_draft(candidate, engine).source
    }

    /// Generate a harness end to end with automatic repair: draft -> compile,
    /// and on a compile failure feed the diagnostics back to the LLM for up to
    /// `max_repairs` corrective passes before giving up.
    ///
    /// This is the recommended entry point over calling `harness_draft` +
    /// `harness_compile` separately: a large fraction of first-draft harnesses
    /// fail to compile, and abandoning the target on the first failure wastes a
    /// discovered, potentially high-value target. Repair recovers many of them.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown,
    /// `ClassifiedError::Harness` if the harness still fails to build after
    /// `max_repairs` attempts, or an infrastructure error from the sandbox.
    pub async fn harness_generate(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        self.guardrails.authorize(Action::CompileHarness).await?;
        let inv = self.discover(project, lang).await?;
        let candidate = inv
            .candidates
            .iter()
            .find(|c| c.symbol == target)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        let source = self.draft_harness_source(&candidate, engine).await;
        self.compile_source_with_repair(&candidate, engine, lang, &workspace, source, max_repairs)
            .await
    }

    /// Compile `initial_source` in the sandbox, and on a compile failure feed the
    /// diagnostics back to the LLM for up to `max_repairs` corrective passes.
    /// Shared by harness generation and coverage-guided refinement.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Harness` if the harness still fails to build
    /// after `max_repairs` attempts, or an infrastructure error from the sandbox.
    async fn compile_source_with_repair(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
        lang: TargetLanguage,
        workspace: &Path,
        initial_source: String,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let target = &candidate.symbol;
        let mut source = initial_source;
        let mut repairs_used = 0usize;
        let mut last_diagnostics = String::new();

        loop {
            let mut build_cmd = hf_harness::build_command(engine, lang, &format!("fuzz_{target}"));
            build_cmd.output = PathBuf::from(format!("fuzz_{target}"));
            let harness = Harness {
                id: Uuid::new_v4(),
                target_id: candidate.id,
                engine,
                source: source.clone(),
                language: lang,
                build_cmd,
                sanitizer: Sanitizer::Address,
                status: HarnessStatus::Draft,
                smoke_run: None,
            };
            match hf_harness::try_compile(harness, self.runtime.as_ref(), workspace).await? {
                hf_harness::CompileResult::Ok(compiled) => {
                    if let Some(store) = &self.store {
                        if let Err(e) = store.upsert_harness(&compiled).await {
                            tracing::warn!("failed to persist harness {}: {e}", compiled.id);
                        }
                    }
                    let binary_name = compiled
                        .build_cmd
                        .output
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(target)
                        .to_string();
                    return Ok(HarnessGenOutcome {
                        status: compiled.status,
                        binary_name,
                        workspace: workspace.to_path_buf(),
                        repairs_used,
                    });
                }
                hf_harness::CompileResult::Failed(failure) => {
                    last_diagnostics = failure.diagnostics();
                    if repairs_used >= max_repairs {
                        break;
                    }
                    let Some(pool) = self.provider_pool() else {
                        // No LLM to repair with; the first failure is terminal.
                        break;
                    };
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "harness_repair");
                    match hf_harness::repair(
                        candidate,
                        engine,
                        &source,
                        &last_diagnostics,
                        Box::new(provider),
                    )
                    .await
                    {
                        Ok(draft) => {
                            source = draft.source;
                            repairs_used += 1;
                        }
                        Err(e) => {
                            tracing::warn!("harness repair for '{target}' failed: {e}");
                            break;
                        }
                    }
                }
            }
        }

        let diag: String = last_diagnostics.chars().take(600).collect();
        Err(ClassifiedError::Harness(format!(
            "harness for '{target}' failed to build after {repairs_used} repair attempt(s): {diag}"
        )))
    }

    /// Coverage-guided harness refinement: when coverage has stagnated, ask the
    /// LLM to reshape the current harness so the fuzzer reaches the target's
    /// still-uncovered reachable functions, then compile the result (with the
    /// same auto-repair loop as generation).
    ///
    /// Recomputes coverage to determine which reachable functions are still
    /// uncovered, so the model gets a concrete goal rather than "improve this".
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown or has no
    /// current harness, `ClassifiedError::Provider` if no LLM is configured, or
    /// an error from the refine/compile steps.
    pub async fn harness_refine(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        self.guardrails.authorize(Action::CompileHarness).await?;
        let inv = self.discover(project, lang).await?;
        let candidate = inv
            .candidates
            .iter()
            .find(|c| c.symbol == target)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        let workspace = workspace_dir(project, target);
        let current_source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "no current harness for '{target}' to refine; generate one first"
            ))
        })?;

        // Which reachable functions has coverage not reached yet?
        let covered: std::collections::HashSet<String> = self
            .coverage_functions(project, target)
            .await
            .into_iter()
            .collect();
        let uncovered: Vec<String> = candidate
            .reachable_functions
            .iter()
            .filter(|f| !covered.contains(*f))
            .cloned()
            .collect();

        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for refinement".to_owned())
        })?;
        let provider = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "harness_refine");
        let refined = hf_harness::refine(
            &candidate,
            engine,
            &current_source,
            &uncovered,
            Box::new(provider),
        )
        .await?;

        self.compile_source_with_repair(
            &candidate,
            engine,
            lang,
            &workspace,
            refined.source,
            max_repairs,
        )
        .await
    }

    /// Run an autonomous fuzzing campaign end to end: discover (and pick the
    /// best target when none is given) -> generate + auto-repair a harness ->
    /// seed the corpus -> loop [run -> triage -> feed crashes back -> refine on
    /// stagnation] until a crash is found or `max_iterations` is reached.
    ///
    /// This is the coded orchestration the scheduler and "just fuzz this" flows
    /// use, so a scheduled campaign runs the whole pipeline rather than a single
    /// fixed run. Each iteration is bounded by `duration_secs`.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if discovery finds no target, or harness
    /// generation / the first run fails. Triage and refinement failures within
    /// the loop are logged and do not abort the campaign.
    pub async fn run_campaign(
        &self,
        project: &Path,
        target: Option<&str>,
        engine: EngineKind,
        lang: TargetLanguage,
        duration_secs: u64,
        max_repairs: usize,
        max_iterations: usize,
    ) -> Result<CampaignOutcome, ClassifiedError> {
        // 1. Choose a target: the caller's, else the top-ranked candidate.
        let inv = self.discover(project, lang).await?;
        let target = match target.filter(|t| !t.is_empty()) {
            Some(t) => t.to_owned(),
            None => inv
                .ranked()
                .first()
                .map(|c| c.symbol.clone())
                .ok_or_else(|| {
                    ClassifiedError::Validation("no fuzzable targets discovered".to_owned())
                })?,
        };

        // 2. Generate a harness (with auto-repair) and seed the corpus.
        let gen = self
            .harness_generate(project, &target, engine, lang, max_repairs)
            .await?;
        let _ = self.generate_seeds_llm(project, &target, lang, 12).await;

        // 3. Run -> triage loop, stopping on the first crash or the iteration cap.
        let noop = |_: FuzzProgress| {};
        let mut edges = 0u64;
        let mut crashes = 0usize;
        let mut iterations = 0usize;
        let mut auto_reverts = 0usize;
        let cap = max_iterations.max(1);
        while iterations < cap {
            iterations += 1;
            let summary = self
                .run_fuzzer(project, &target, engine, duration_secs, &noop)
                .await?;
            edges = edges.max(summary.edges);
            // A refine step between iterations can regress coverage; the policy
            // (armed via config) then restores the last-good harness, or, in
            // notify-only mode, flags it. Count either so history shows it.
            if summary.auto_revert.is_some() {
                auto_reverts += 1;
            }

            let triaged = self.triage(project, &target).await.unwrap_or_default();
            crashes = triaged.len();
            // Feed any crash reproducers back into the corpus (close the loop).
            let _ = self.corpus_absorb_crashes(project, &target).await;

            if crashes > 0 || iterations >= cap {
                break;
            }
            // No crash yet and iterations remain: refine the harness toward
            // uncovered code before the next run. Best-effort.
            if let Err(e) = self
                .harness_refine(project, &target, engine, lang, max_repairs)
                .await
            {
                tracing::info!("campaign refine step skipped for '{target}': {e}");
            }
        }

        Ok(CampaignOutcome {
            target,
            harness_status: gen.status,
            repairs_used: gen.repairs_used,
            crashes,
            edges,
            iterations,
            auto_reverts,
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

    /// Generate a seed corpus for a target using the LLM (structural, format-
    /// aware seeds), falling back to the heuristic seeds when no provider is
    /// configured or the model returns nothing usable. Seeds are written into
    /// the target's corpus directory and deduplicated by content hash.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory or a seed file cannot
    /// be written.
    pub async fn generate_seeds_llm(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
        count: usize,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        use sha2::{Digest, Sha256};
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        std::fs::create_dir_all(&corpus_dir)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir corpus: {e}")))?;

        // LLM seeds when a provider and the target candidate are available.
        let mut datas: Vec<Vec<u8>> = Vec::new();
        if let Some(pool) = self.provider_pool() {
            if let Ok(inv) = self.discover(project, lang).await {
                if let Some(candidate) = inv.candidates.iter().find(|c| c.symbol == target) {
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "seed_gen");
                    match hf_harness::generate_seeds(candidate, count, Box::new(provider)).await {
                        Ok(seeds) => datas = seeds,
                        Err(e) => tracing::warn!("LLM seed generation for '{target}' failed: {e}"),
                    }
                }
            }
        }
        // Fall back to the heuristic seeds so a corpus is always produced.
        if datas.is_empty() {
            datas = generate_target_seeds(target)
                .into_iter()
                .map(|(data, _)| data)
                .collect();
        }

        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (i, data) in datas.into_iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let sha = format!("{:x}", hasher.finalize());
            if !seen.insert(sha.clone()) {
                continue;
            }
            let name = format!("llmseed_{i}");
            std::fs::write(corpus_dir.join(&name), &data)
                .map_err(|e| ClassifiedError::Internal(format!("write seed: {e}")))?;
            entries.push(SeedEntry {
                name,
                size: data.len(),
                sha256: sha,
            });
        }

        // Make the AI seeds first-class, tracked corpus entries (parity with
        // corpus_seed/corpus_grow), so they show in the browse-all corpus view
        // and survive as persisted rows -- previously LLM seeds only landed on
        // disk. Listing the dir also folds in any pre-existing entries; the
        // upsert is keyed on (target_id, sha256), so this stays idempotent.
        let target_id = self.resolve_target_id(project, target, lang).await;
        if let Ok(corpus) = hf_corpus::list(&corpus_dir) {
            self.persist_corpus(target_id, &corpus).await;
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

        // Build a dictionary from the target sources and point the engine at it.
        // A dictionary of the literals the target compares against is one of the
        // cheapest coverage multipliers; absent literals just yield no flag.
        let dict_name = format!("{target}.dict");
        let extra_args = if build_workspace_dictionary(&workspace, &dict_name).is_some() {
            hf_engine::dict::dict_run_args(engine, &format!("/work/{dict_name}"))
        } else {
            Vec::new()
        };

        let run_cfg = FuzzRunConfig {
            // Link the run to the target's compiled harness so the target-scoped
            // workbench dashboard can attribute it. A throwaway id here would
            // leave every run unattributable (dashboard shows zero runs).
            harness_id: self.resolve_run_harness_id(project, target, engine).await,
            engine,
            duration: Some(std::time::Duration::from_secs(duration_secs)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: Some(corpus_dir.clone()),
            sanitizer: hf_core::target::Sanitizer::Address,
            env: Vec::new(),
            extra_args,
        };
        // The harness the run is about to use, plus a short content hash of it,
        // so a coverage change in the run history can be attributed to -- and
        // diffed against -- the harness revision that produced it.
        let harness_source = read_current_harness_source(&workspace);
        let harness_rev = harness_source.as_ref().map(|src| {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(src.as_bytes());
            format!("{:x}", h.finalize())[..12].to_owned()
        });
        // Record the run so campaigns survive restarts (best-effort).
        let mut run_record = self.store.as_ref().map(|_| {
            let mut rec = RunRecord::new(
                project.to_string_lossy().to_string(),
                engine,
                Some(run_cfg.clone()),
                Utc::now(),
            );
            rec.status = RunStatus::Running;
            rec
        });
        if let Some(rec) = run_record.as_mut() {
            rec.harness_rev = harness_rev;
        }
        if let (Some(store), Some(rec)) = (&self.store, &run_record) {
            if let Err(e) = store.insert_run(rec).await {
                tracing::warn!("failed to record run start: {e}");
            }
            if let Some(src) = &harness_source {
                if let Err(e) = store.set_run_harness_source(rec.id, src).await {
                    tracing::warn!("failed to persist harness source: {e}");
                }
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
        // Coverage-guided feedback: watch edge readings for stagnation and, once
        // coverage plateaus past the threshold, surface a proposal to iterate.
        // Wrap `on_progress` so every event still flows to the caller unchanged.
        let feedback =
            CoverageFeedback::new(crate::config::coverage_stagnation_secs(), on_progress);
        // Accumulate an intra-run coverage/throughput time series live, so the
        // run's coverage curve can be charted later. Each fuzzer stats line emits
        // an EdgesCovered then an ExecsPerSec event; pair them and stamp the
        // elapsed time.
        let series: std::sync::Arc<std::sync::Mutex<Vec<(f64, u64, f64)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_edges = std::sync::atomic::AtomicU64::new(0);
        let run_started = std::time::Instant::now();
        let series_w = std::sync::Arc::clone(&series);
        let watched = |p: FuzzProgress| {
            use std::sync::atomic::Ordering::Relaxed;
            match &p {
                FuzzProgress::EdgesCovered(v) => {
                    feedback.on_edges(*v);
                    last_edges.store(*v, Relaxed);
                }
                FuzzProgress::ExecsPerSec(v) => {
                    let t = run_started.elapsed().as_secs_f64();
                    let e = last_edges.load(Relaxed);
                    if let Ok(mut s) = series_w.lock() {
                        s.push((t, e, *v));
                    }
                }
                _ => {}
            }
            on_progress(p);
        };
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
                &watched,
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
        // Persist the run's peak coverage + throughput so run history can chart
        // real trends over time (not just live in the frontend's memory).
        if let (Some(store), Some(rec)) = (&self.store, &run_record) {
            if let Err(e) = store
                .set_run_stats(rec.id, edges, execs, u64::from(crashes))
                .await
            {
                tracing::warn!("failed to persist run stats: {e}");
            }
            // Persist the (downsampled) intra-run coverage curve.
            let raw = series.lock().map(|s| s.clone()).unwrap_or_default();
            let samples: Vec<CoverageSample> = downsample(&raw, 150)
                .into_iter()
                .map(|(t, e, x)| CoverageSample {
                    t,
                    edges: e,
                    execs: x,
                })
                .collect();
            if !samples.is_empty() {
                if let Ok(json) = serde_json::to_string(&samples) {
                    if let Err(e) = store.set_run_samples(rec.id, &json).await {
                        tracing::warn!("failed to persist run samples: {e}");
                    }
                }
            }
        }
        // Auto-revert policy: if this run's harness revision regressed coverage
        // past the threshold versus the previous run for this target, restore
        // that last-good revision (HITL-gated recompile). Skipped for cancelled
        // runs, whose truncated coverage is not a fair comparison.
        let auto_revert = if was_cancelled {
            None
        } else {
            let this_rev = run_record.as_ref().and_then(|r| r.harness_rev.clone());
            self.maybe_auto_revert(project, target, run_id, edges, this_rev.as_deref())
                .await
        };
        Ok(RunSummary {
            edges,
            execs,
            crashes: u64::from(crashes),
            stagnation: feedback.proposal(),
            auto_revert,
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

        // Register the cancellation token so the UI Stop button (which fires
        // `cancel_all_runs`) and `cancel_run` can tear down a long KVM campaign.
        // `ActiveRunGuard` removes it again even if this future is aborted.
        let cancel = CancellationToken::new();
        let run_id = Uuid::new_v4();
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.insert(run_id, cancel.clone());
        }
        let _active_run_guard = ActiveRunGuard {
            active_runs: Arc::clone(&self.active_runs),
            run_id,
        };
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
            // Target source context lets the model infer a root cause and fix.
            let source_context = gather_source_context(&workspace);
            for crash in deduped.iter_mut().take(MAX_BUG_REPORT_DRAFTS) {
                let bridge = LlmProviderBridge::new(Arc::clone(&pool))
                    .with_diagnostics(Arc::clone(&self.diagnostics), "triage_report");
                let log = logs
                    .get(&crash.input_path)
                    .filter(|l| !l.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| crash.summary.clone());
                match hf_crash::draft_report(
                    crash,
                    &log,
                    source_context.as_deref(),
                    Box::new(bridge),
                )
                .await
                {
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

    /// Document formats this host can export a report to (see
    /// [`crate::report_export::available_formats`]).
    #[must_use]
    pub fn report_formats(&self) -> Vec<String> {
        crate::report_export::available_formats()
    }

    /// Compose the report for `target` and write it to `out_path` in `format`.
    /// Markdown and HTML always work; PDF/DOCX require pandoc (and, for PDF, a
    /// PDF engine).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if composition, format parsing, or the export
    /// (IO / external tool) fails.
    pub async fn export_report(
        &self,
        project: &Path,
        target: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        let markdown = self.generate_report(project, target).await?;
        let title = format!("hobot_fuzz report — {target}");
        crate::report_export::write_report(&markdown, &title, fmt, out_path)
    }

    /// Write already-composed report `markdown` (e.g. a saved draft) to
    /// `out_path` in `format`, without recomposing it.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on unknown format or export failure.
    pub fn export_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        crate::report_export::write_report(markdown, title, fmt, out_path)
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
        // The actual crash inputs, including AFL++'s nested
        // out/<instance>/crashes/ layout, so each casrep resolves to a real file.
        let crash_inputs = collect_crash_inputs(&out_dir);
        let mut crashes = reports
            .into_iter()
            .map(|(path, casr)| {
                let input_path = casrep_input_path(&out_dir, &path, &crash_inputs);
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

    /// Coverage-based corpus minimization: run each input through `afl-showmap`
    /// in the sandbox to fingerprint the edges it covers, then drop inputs whose
    /// coverage is already represented by another. This is a true distillation
    /// (keep one input per distinct coverage set), unlike `corpus_prune` which,
    /// absent coverage data, can only collapse byte-identical files.
    ///
    /// Inputs whose coverage cannot be measured (the binary is missing, or the
    /// engine is not AFL-instrumented so `afl-showmap` yields nothing) keep a
    /// `None` coverage hash and fall back to content-dedup -- so this never
    /// collapses two genuinely distinct inputs under an empty key.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus cannot be read.
    pub async fn corpus_prune_coverage(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<MinimizeOutcome, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let mut corpus = hf_corpus::list(&corpus_dir)?;
        let before = corpus.entries.len();

        let bin = format!("fuzz_{target}");
        let binary = workspace.join(&bin);
        if binary.exists() {
            let binary_container = format!("/work/{bin}");
            let limits = hf_core::runtime::ResourceLimits {
                max_mem_mb: 2048,
                max_cpus: 1,
                max_duration_secs: 30,
                env: std::collections::HashMap::new(),
                ptrace: false,
            };
            for entry in &mut corpus.entries {
                let input_container = container_input_path(&workspace, &entry.path);
                let args =
                    hf_engine::showmap::build_showmap_args(&binary_container, &input_container);
                if let Ok(result) = self.runtime.run_command(&args, &workspace, &limits).await {
                    if let Some(hash) = hf_engine::showmap::coverage_hash(&result.stdout) {
                        entry.coverage_hash = Some(hash);
                    }
                }
            }
        }

        let pruned = hf_corpus::prune(corpus)?;
        let after = pruned.entries.len();
        let target_id = self
            .resolve_target_id(project, target, TargetLanguage::C)
            .await;
        self.persist_corpus(target_id, &pruned).await;
        Ok(MinimizeOutcome { before, after })
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

/// Outcome of an end-to-end harness generation with automatic repair: the
/// compiled harness plus how many repair attempts it took to get there.
#[derive(Debug, Clone)]
pub struct HarnessGenOutcome {
    pub status: HarnessStatus,
    pub binary_name: String,
    pub workspace: PathBuf,
    /// Number of LLM repair passes applied before the harness compiled (0 when
    /// the first draft built cleanly).
    pub repairs_used: usize,
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

/// Outcome of an autonomous end-to-end campaign
/// ([`ServiceContainer::run_campaign`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CampaignOutcome {
    /// The target the campaign fuzzed (chosen automatically when not supplied).
    pub target: String,
    /// Harness build status after generation + repair.
    pub harness_status: HarnessStatus,
    /// Number of LLM repair passes the harness needed.
    pub repairs_used: usize,
    /// Unique crashes surfaced by the final triage.
    pub crashes: usize,
    /// Peak edge coverage observed across the campaign's runs.
    pub edges: u64,
    /// How many run -> triage iterations the campaign performed.
    pub iterations: usize,
    /// How many iterations triggered the auto-revert policy (a harness revision
    /// regressed coverage past the threshold). Counts both applied reverts and
    /// notify-only detections, so headless history surfaces self-healing.
    pub auto_reverts: usize,
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

/// One point on a run's intra-run coverage/throughput curve.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageSample {
    /// Seconds elapsed since the run started.
    pub t: f64,
    /// Edge coverage at that moment.
    pub edges: u64,
    /// Executions/second at that moment.
    pub execs: f64,
}

/// Reduce a time series to at most `cap` points by uniform stride, always
/// keeping the last sample so the curve reaches its true end.
fn downsample(series: &[(f64, u64, f64)], cap: usize) -> Vec<(f64, u64, f64)> {
    if series.len() <= cap || cap == 0 {
        return series.to_vec();
    }
    let stride = series.len().div_ceil(cap);
    let mut out: Vec<(f64, u64, f64)> = series.iter().step_by(stride).copied().collect();
    if let Some(last) = series.last() {
        if out.last() != Some(last) {
            out.push(*last);
        }
    }
    out
}

/// The auto-revert decision, isolated from the async plumbing so its rules are
/// unit-testable. Returns `Some(drop_pct)` when the policy should restore the
/// previous harness: the revision changed (`prev_rev != this_rev`), there is a
/// non-zero baseline, coverage dropped, and the drop meets the threshold.
/// Returns `None` otherwise.
fn auto_revert_decision(
    prev_rev: &str,
    this_rev: &str,
    prev_edges: u64,
    this_edges: u64,
    threshold_pct: f64,
) -> Option<f64> {
    // Only a genuine revision change can be a revision regression; an unchanged
    // harness covering fewer edges is run-to-run noise.
    if prev_rev == this_rev {
        return None;
    }
    // No baseline, or coverage held/improved -> nothing to revert.
    if prev_edges == 0 || this_edges >= prev_edges {
        return None;
    }
    let drop_pct = (prev_edges - this_edges) as f64 / prev_edges as f64 * 100.0;
    (drop_pct >= threshold_pct).then_some(drop_pct)
}

/// One run in the persisted run history (see [`ServiceContainer::run_history`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunHistoryItem {
    pub id: String,
    pub project_root: String,
    pub engine: String,
    pub status: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub duration_secs: Option<i64>,
    pub crashes: usize,
    /// Peak edge coverage, once the run finished (None for older/pending runs).
    pub edges: Option<u64>,
    /// Peak executions/second, once the run finished.
    pub execs: Option<f64>,
    /// Short hash of the harness revision the run used.
    pub harness_rev: Option<String>,
}

/// A fuzz run summary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSummary {
    pub edges: u64,
    pub execs: f64,
    pub crashes: u64,
    /// A coverage-stagnation proposal surfaced during the run (e.g. regenerate
    /// the harness), or `None` if coverage kept progressing. Lets a presentation
    /// layer offer an iterate-next affordance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stagnation: Option<hf_coverage::StagnationProposal>,
    /// Set when the auto-revert policy fired: this run's harness regressed
    /// coverage past the configured threshold, so an earlier (last-good)
    /// revision was restored and recompiled. Lets a presentation layer surface
    /// the automatic action. `None` when the policy is off or did not trigger.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_revert: Option<AutoRevertOutcome>,
}

/// The outcome of the auto-revert policy firing for a finished run: its harness
/// revision changed and coverage dropped past the threshold, so the previous
/// run's (last-good) harness was restored and recompiled.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AutoRevertOutcome {
    /// The id of the earlier run whose harness was (or would be) restored.
    pub reverted_to_run: String,
    /// The regressed run's harness revision (the one that was replaced).
    pub from_rev: String,
    /// The restored run's harness revision.
    pub to_rev: String,
    /// Peak edge coverage of the restored (previous) run.
    pub previous_edges: u64,
    /// Peak edge coverage of the regressed run.
    pub regressed_edges: u64,
    /// The percent coverage drop that triggered the revert.
    pub drop_pct: f64,
    /// `true` when the harness was actually restored and recompiled; `false`
    /// when the policy is in notify-only mode and only reported the regression.
    pub reverted: bool,
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

/// Coverage-guided feedback for a live fuzz run.
///
/// Feeds each streamed edge reading into a [`hf_coverage::CoverageTracker`] and,
/// the first time coverage has been flat for longer than `threshold_secs`,
/// surfaces a [`StagnationProposal`](hf_coverage::StagnationProposal) to the user
/// (a live log line now, and on the final [`RunSummary`]). This realizes the
/// coverage feedback loop from `docs/design/corpus-coverage-design.md` §4: we
/// detect stagnation and *propose* iterating (a new harness / dictionary / seed)
/// rather than regenerating a harness autonomously, which would bypass the
/// human-in-the-loop review that harness execution requires (AGENTS.md §2.12).
struct CoverageFeedback<'a> {
    tracker: std::sync::Mutex<hf_coverage::CoverageTracker>,
    /// Latched proposal: `Some` once surfaced, so it is proposed at most once.
    proposal: std::sync::Mutex<Option<hf_coverage::StagnationProposal>>,
    threshold_secs: u64,
    emit: &'a (dyn Fn(FuzzProgress) + Send + Sync),
}

impl<'a> CoverageFeedback<'a> {
    fn new(threshold_secs: u64, emit: &'a (dyn Fn(FuzzProgress) + Send + Sync)) -> Self {
        Self {
            tracker: std::sync::Mutex::new(hf_coverage::CoverageTracker::new()),
            proposal: std::sync::Mutex::new(None),
            threshold_secs,
            emit,
        }
    }

    /// Record a cumulative edge count from a stat pulse and, on the first
    /// stagnation, emit and latch a proposal.
    fn on_edges(&self, edges: u64) {
        let Ok(mut tracker) = self.tracker.lock() else {
            return;
        };
        tracker.update(&hf_core::coverage::CoverageReport {
            run_id: Uuid::nil(),
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        });
        // Only the first stagnation is surfaced.
        if self.proposal.lock().is_ok_and(|p| p.is_some()) {
            return;
        }
        if let Some(proposal) = hf_coverage::propose_action(&tracker, self.threshold_secs) {
            (self.emit)(FuzzProgress::LogLine(format!(
                "[coverage] no new edges for {}s -- {}",
                tracker.stagnation_secs(),
                describe_proposal(&proposal),
            )));
            if let Ok(mut slot) = self.proposal.lock() {
                *slot = Some(proposal);
            }
        }
    }

    /// The proposal surfaced during the run, if any.
    fn proposal(&self) -> Option<hf_coverage::StagnationProposal> {
        self.proposal.lock().ok().and_then(|p| p.clone())
    }
}

/// A short, user-facing description of a stagnation proposal for the run log.
fn describe_proposal(proposal: &hf_coverage::StagnationProposal) -> &'static str {
    match proposal {
        hf_coverage::StagnationProposal::NewHarness => {
            "consider regenerating the harness to reach new code paths"
        }
        hf_coverage::StagnationProposal::CustomMutator => {
            "consider adding a dictionary or custom mutator"
        }
        hf_coverage::StagnationProposal::Stop => "consider stopping this target",
    }
}

/// Pick the harness id a run should be linked to from the harnesses persisted
/// for its target. Prefers a harness built for the same engine, then any
/// harness; returns `None` when the target has no persisted harness yet.
fn select_run_harness(harnesses: &[Harness], engine: EngineKind) -> Option<Uuid> {
    harnesses
        .iter()
        .find(|h| h.engine == engine)
        .or_else(|| harnesses.first())
        .map(|h| h.id)
}

#[cfg(test)]
mod harness_link_tests {
    use super::{select_run_harness, EngineKind, Harness};
    use hf_core::harness::{BuildCommand, HarnessStatus};
    use hf_core::target::{Sanitizer, TargetLanguage};
    use uuid::Uuid;

    fn harness(engine: EngineKind) -> Harness {
        Harness {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            engine,
            source: String::new(),
            language: TargetLanguage::C,
            build_cmd: BuildCommand {
                compiler: String::new(),
                args: Vec::new(),
                output: std::path::PathBuf::new(),
            },
            sanitizer: Sanitizer::Address,
            status: HarnessStatus::Compiled,
            smoke_run: None,
        }
    }

    #[test]
    fn prefers_the_harness_for_the_running_engine() {
        let afl = harness(EngineKind::AflPlusPlus);
        let libfuzzer = harness(EngineKind::LibFuzzer);
        let harnesses = vec![afl.clone(), libfuzzer.clone()];
        assert_eq!(
            select_run_harness(&harnesses, EngineKind::LibFuzzer),
            Some(libfuzzer.id)
        );
    }

    #[test]
    fn falls_back_to_any_harness_when_engine_absent() {
        let afl = harness(EngineKind::AflPlusPlus);
        let harnesses = vec![afl.clone()];
        assert_eq!(
            select_run_harness(&harnesses, EngineKind::LibFuzzer),
            Some(afl.id)
        );
    }

    #[test]
    fn returns_none_without_any_harness() {
        assert_eq!(select_run_harness(&[], EngineKind::LibFuzzer), None);
    }
}

#[cfg(test)]
mod casrep_path_tests {
    use super::casrep_input_path;
    use std::path::{Path, PathBuf};

    #[test]
    fn resolves_afl_nested_crash_input() {
        // AFL++ nests the input under out/<instance>/crashes/; the casrep sits in
        // casr_out. The resolved path must point at the real nested file.
        let out = Path::new("/work/out");
        let nested = PathBuf::from("/work/out/default/crashes/id:000001,sig:06");
        let inputs = vec![nested.clone()];
        let casrep = Path::new("/work/casr_out/id:000001,sig:06.casrep");
        assert_eq!(casrep_input_path(out, casrep, &inputs), nested);
    }

    #[test]
    fn falls_back_to_flat_layout_for_libfuzzer() {
        // libFuzzer crashes sit directly in out/; when the input list does not
        // contain a match, fall back to out/<name>.
        let out = Path::new("/work/out");
        let casrep = Path::new("/work/casr_out/crash-abc.casrep");
        assert_eq!(
            casrep_input_path(out, casrep, &[]),
            PathBuf::from("/work/out/crash-abc")
        );
    }
}

#[cfg(test)]
mod coverage_feedback_tests {
    use super::{CoverageFeedback, FuzzProgress};
    use hf_coverage::StagnationProposal;
    use std::sync::Mutex;

    #[test]
    fn proposes_once_when_edges_plateau() {
        let emitted: Mutex<Vec<FuzzProgress>> = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        // threshold 0: the first flat pulse after the initial reading is stagnant.
        let fb = CoverageFeedback::new(0, &emit);
        fb.on_edges(100); // first reading -- never stagnant (needs >1 update)
        assert_eq!(fb.proposal(), None);
        fb.on_edges(100); // flat -> stagnant -> propose
        fb.on_edges(100); // still flat -> must NOT propose again (latched)

        assert_eq!(fb.proposal(), Some(StagnationProposal::NewHarness));
        let log_lines = emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|p| matches!(p, FuzzProgress::LogLine(_)))
            .count();
        assert_eq!(log_lines, 1, "the proposal must be surfaced exactly once");
    }

    #[test]
    fn no_proposal_on_a_single_reading() {
        let emit = |_p: FuzzProgress| {};
        let fb = CoverageFeedback::new(0, &emit);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }

    #[test]
    fn threshold_gates_the_proposal() {
        let emit = |_p: FuzzProgress| {};
        // A high threshold is not reached in the test's wall-clock window, so a
        // flat plateau does not (yet) propose.
        let fb = CoverageFeedback::new(3600, &emit);
        fb.on_edges(100);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }
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
        super::workspace_root().join(super::project_slug(project))
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
    fn projects_sharing_a_basename_get_distinct_workspaces() {
        // Two different projects with the same directory name must not share a
        // workspace, or one's compiled binary/corpus/crashes would be used for
        // the other's runs/triage.
        let a = workspace_dir(Path::new("/a/libfoo"), "parse");
        let b = workspace_dir(Path::new("/b/libfoo"), "parse");
        assert_ne!(a, b, "same-basename projects collided");
    }

    #[test]
    fn same_project_maps_to_a_stable_workspace() {
        // The slug must be deterministic so compile -> run -> triage across
        // separate invocations all resolve to the same on-disk workspace.
        let project = Path::new("/home/user/myproj");
        assert_eq!(
            workspace_dir(project, "parse_json"),
            workspace_dir(project, "parse_json")
        );
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
mod dictionary_tests {
    use super::build_workspace_dictionary;

    #[test]
    fn builds_dictionary_from_source_literals_excluding_harness() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("parse.c"),
            "int f(){ return strcmp(s, \"MAGIC\"); }",
        )
        .unwrap();
        // The generated harness literals must NOT pollute the dictionary.
        std::fs::write(
            dir.path().join("harness.c"),
            "int LLVMFuzzerTestOneInput(){ puts(\"HARNESS_ONLY\"); return 0; }",
        )
        .unwrap();

        let path = build_workspace_dictionary(dir.path(), "t.dict").expect("dict built");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"MAGIC\""), "missing target literal: {body}");
        assert!(
            !body.contains("HARNESS_ONLY"),
            "harness literal leaked: {body}"
        );
    }

    #[test]
    fn returns_none_when_no_literals() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.c"), "int f(){ return 0; }").unwrap();
        assert!(build_workspace_dictionary(dir.path(), "t.dict").is_none());
    }
}

#[cfg(test)]
mod rust_staging_tests {
    use super::copy_project_sources;

    #[test]
    fn stages_rust_crate_manifest_and_src_tree() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("Cargo.toml"),
            "[package]\nname = \"lib\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(project.path().join("src").join("inner")).unwrap();
        std::fs::write(project.path().join("src").join("lib.rs"), "pub fn f() {}").unwrap();
        std::fs::write(
            project.path().join("src").join("inner").join("mod.rs"),
            "// nested",
        )
        .unwrap();

        copy_project_sources(project.path(), workspace.path());

        assert!(workspace.path().join("Cargo.toml").is_file());
        assert!(workspace.path().join("src").join("lib.rs").is_file());
        // The src/ tree is copied recursively so multi-file crates build.
        assert!(workspace
            .path()
            .join("src")
            .join("inner")
            .join("mod.rs")
            .is_file());
    }

    #[test]
    fn non_rust_project_stages_no_crate() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("parse.c"), "int f(){ return 0; }").unwrap();

        copy_project_sources(project.path(), workspace.path());

        // C sources copy; no Cargo.toml means no Rust staging.
        assert!(workspace.path().join("parse.c").is_file());
        assert!(!workspace.path().join("Cargo.toml").exists());
        assert!(!workspace.path().join("src").exists());
    }
}

#[cfg(test)]
mod downsample_tests {
    use super::downsample;

    #[test]
    fn keeps_short_series_intact() {
        let s = vec![(0.0, 1, 10.0), (1.0, 2, 20.0)];
        assert_eq!(downsample(&s, 10).len(), 2);
    }

    #[test]
    fn caps_and_keeps_last() {
        let s: Vec<(f64, u64, f64)> = (0..100).map(|i| (i as f64, i as u64, 0.0)).collect();
        let out = downsample(&s, 10);
        assert!(out.len() <= 11, "capped near the target, got {}", out.len());
        assert_eq!(out.last().unwrap().1, 99, "always keeps the final sample");
    }
}

#[cfg(test)]
mod auto_revert_tests {
    use super::auto_revert_decision;

    #[test]
    fn fires_when_changed_harness_drops_coverage_past_threshold() {
        // 1000 -> 700 edges is a 30% drop with a changed revision.
        let drop = auto_revert_decision("old", "new", 1000, 700, 20.0);
        assert!(matches!(drop, Some(p) if (p - 30.0).abs() < f64::EPSILON));
    }

    #[test]
    fn does_not_fire_when_harness_unchanged() {
        // Same revision: a coverage dip is noise, not a revision regression.
        assert!(auto_revert_decision("same", "same", 1000, 100, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_below_threshold() {
        // 1000 -> 900 is only a 10% drop; threshold is 20%.
        assert!(auto_revert_decision("old", "new", 1000, 900, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_when_coverage_held_or_improved() {
        assert!(auto_revert_decision("old", "new", 1000, 1000, 20.0).is_none());
        assert!(auto_revert_decision("old", "new", 1000, 1200, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_without_a_baseline() {
        assert!(auto_revert_decision("old", "new", 0, 0, 20.0).is_none());
    }

    #[test]
    fn fires_exactly_at_threshold() {
        let drop = auto_revert_decision("old", "new", 100, 80, 20.0);
        assert!(matches!(drop, Some(p) if (p - 20.0).abs() < f64::EPSILON));
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
