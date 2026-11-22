//! Crash bisection: find the first commit at which a triaged crash input
//! crashes under the promoted harness.
//!
//! See `docs/design/crash-bisection-design.md`. History is read as stored git
//! objects (`ls-tree` + `cat-file`), so no checkout, index write, filter or
//! hook runs and the operator's repository is not changed. Every build and
//! replay happens in the sandbox, in a directory that belongs to the bisection
//! and is removed when its commit has been tested.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::target::TargetLanguage;
use hf_guardrails::Action;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use super::project_identity::project_slug;
use super::workspace::{ensure_workspace_directory, prepare_configured_workspace_root};
use super::ServiceContainer;

/// Commits one bisection may range over.
pub const MAX_CANDIDATES: usize = 4096;
/// Commits one bisection may build and replay.
pub const MAX_TESTED: usize = 40;

/// Files materialized from one commit.
const MAX_TREE_FILES: usize = 20_000;
/// Bytes of one materialized file.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Bytes materialized from one commit.
const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024;
/// Bytes of the `ls-tree` listing read for one commit.
const MAX_LISTING_BYTES: usize = 64 * 1024 * 1024;
/// Bytes of the crash input replayed at each commit.
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const GIT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_TREE_TIMEOUT: Duration = Duration::from_secs(300);
/// The replayed input's name inside a bisect directory.
const INPUT_NAME: &str = "bisect-crash-input";

/// Source and header suffixes materialized from a commit: the set a live
/// build stages from the project.
const SOURCE_EXTENSIONS: [&str; 8] = ["c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx"];
/// Directory names a live build never stages.
const SKIPPED_DIRECTORIES: [&str; 4] = [".git", "target", "build", "node_modules"];

/// What replaying the crash input at one commit showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BisectVerdict {
    /// The replay completed without a crash.
    Good,
    /// The replay crashed.
    Bad,
    /// The commit could not be built or replayed; it counts as neither.
    Skip,
}

/// One commit the bisection built and replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BisectStep {
    pub commit: String,
    pub verdict: BisectVerdict,
    /// For a skip, the first line of the reason; otherwise empty.
    pub note: String,
}

/// Where the search ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BisectResult {
    /// The first commit at which the input crashes.
    FirstBad { commit: String, subject: String },
    /// The first crashing commit is one of these (oldest first); the others
    /// could not be built or replayed, or the build budget ran out.
    Undecided { commits: Vec<String> },
}

/// The report of one bisection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BisectOutcome {
    /// The resolved commit the input does not crash at.
    pub good: String,
    /// The resolved commit the input crashes at.
    pub bad: String,
    /// Commits between them on the first-parent path, `bad` included.
    pub candidates: usize,
    pub result: BisectResult,
    /// Every commit built and replayed, in the order tested.
    pub steps: Vec<BisectStep>,
}

fn invalid(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(message.into())
}

/// Accept a revision only when it cannot be read as a git option or range
/// and holds no character outside the names git itself produces.
fn validate_revision(revision: &str) -> Result<(), ClassifiedError> {
    let admitted = !revision.is_empty()
        && revision.len() <= 200
        && !revision.starts_with('-')
        && !revision.contains("..")
        && !revision.contains("@{")
        && revision.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b'~' | b'^')
        });
    if admitted {
        Ok(())
    } else {
        Err(invalid(format!(
            "'{revision}' is not an accepted revision: use a commit id, branch or tag name, \
             optionally with ~N or ^N"
        )))
    }
}

/// One blob of a commit's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeFile {
    object: String,
    size: u64,
    path: PathBuf,
}

/// Whether a tree path is a source a live build would stage: a relative path
/// of plain components, outside the never-staged directories, with a source
/// or header suffix.
fn admitted_path(path: &str) -> Option<PathBuf> {
    let candidate = Path::new(path);
    let plain = candidate
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    if path.is_empty() || !plain || path.contains('\\') {
        return None;
    }
    let skipped = candidate.components().any(|component| {
        SKIPPED_DIRECTORIES
            .iter()
            .any(|name| component.as_os_str() == std::ffi::OsStr::new(name))
    });
    let is_source = candidate
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension));
    (!skipped && is_source).then(|| candidate.to_path_buf())
}

/// Parse `git ls-tree -r -z --long` output into the files to materialize.
/// Entries are `<mode> <type> <object> <size>\t<path>\0`. Symbolic links
/// (mode 120000), submodules and non-source paths are left out.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when the tree exceeds a
/// materialization bound.
fn parse_tree_listing(listing: &[u8]) -> Result<Vec<TreeFile>, ClassifiedError> {
    let mut files = Vec::new();
    let mut total = 0_u64;
    for entry in listing.split(|byte| *byte == 0) {
        let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
            continue;
        };
        let (Ok(header), Ok(path)) = (
            std::str::from_utf8(&entry[..tab]),
            std::str::from_utf8(&entry[tab + 1..]),
        ) else {
            continue;
        };
        let mut fields = header.split_ascii_whitespace();
        let (Some(mode), Some(kind), Some(object), Some(size)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if kind != "blob" || !matches!(mode, "100644" | "100755") {
            continue;
        }
        let Some(path) = admitted_path(path) else {
            continue;
        };
        let Ok(size) = size.parse::<u64>() else {
            continue;
        };
        if !object.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        if size > MAX_FILE_BYTES {
            return Err(invalid(format!(
                "source file {} is larger than the 16 MiB bisection limit",
                path.display()
            )));
        }
        total += size;
        if files.len() == MAX_TREE_FILES || total > MAX_TREE_BYTES {
            return Err(invalid(
                "the commit holds more source than a bisection materializes \
                 (20000 files or 512 MiB)",
            ));
        }
        files.push(TreeFile {
            object: object.to_owned(),
            size,
            path,
        });
    }
    Ok(files)
}

fn git(project: &Path) -> tokio::process::Command {
    let mut command = hf_runtime::scrubbed_tokio_command("git");
    command
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(project)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    command
}

/// Run one read-only git query and return its bounded stdout.
async fn git_output(
    project: &Path,
    args: &[&str],
    max_bytes: usize,
    what: &str,
) -> Result<Vec<u8>, ClassifiedError> {
    let failed = |reason: String| invalid(format!("git could not {what}: {reason}"));
    let mut child = git(project)
        .args(args)
        .spawn()
        .map_err(|error| failed(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ClassifiedError::Internal("git stdout pipe is unavailable".to_owned()))?;
    let read = async {
        let mut bytes = Vec::new();
        stdout
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| failed(error.to_string()))?;
        if bytes.len() > max_bytes {
            return Err(failed("its output exceeds the size limit".to_owned()));
        }
        let status = child
            .wait()
            .await
            .map_err(|error| failed(error.to_string()))?;
        if !status.success() {
            return Err(failed("the command reported failure".to_owned()));
        }
        Ok(bytes)
    };
    tokio::time::timeout(GIT_QUERY_TIMEOUT, read)
        .await
        .map_err(|_| failed("it timed out".to_owned()))?
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The full id of the commit `revision` names.
async fn resolve_commit(project: &Path, revision: &str) -> Result<String, ClassifiedError> {
    validate_revision(revision)?;
    let spec = format!("{revision}^{{commit}}");
    let bytes = git_output(
        project,
        &["rev-parse", "--verify", "--quiet", &spec],
        256,
        &format!("resolve revision '{revision}'"),
    )
    .await?;
    let id = first_line(&bytes);
    if id.len() >= 40 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(id)
    } else {
        Err(invalid(format!(
            "revision '{revision}' does not name a commit"
        )))
    }
}

/// The commits after `good` up to and including `bad` on the first-parent
/// path, oldest first.
async fn candidate_commits(
    project: &Path,
    good: &str,
    bad: &str,
) -> Result<Vec<String>, ClassifiedError> {
    let ancestor = git(project)
        .args(["merge-base", "--is-ancestor", good, bad])
        .stdout(std::process::Stdio::null())
        .status();
    let ancestor = tokio::time::timeout(GIT_QUERY_TIMEOUT, ancestor)
        .await
        .map_err(|_| invalid("git timed out comparing the two revisions"))?
        .map_err(|error| invalid(format!("git could not compare the two revisions: {error}")))?;
    if !ancestor.success() {
        return Err(invalid(
            "the good revision is not an ancestor of the bad revision, so there is no \
             history between them to bisect",
        ));
    }
    let range = format!("{good}..{bad}");
    let bytes = git_output(
        project,
        &["rev-list", "--first-parent", "--reverse", &range],
        (MAX_CANDIDATES + 1) * 65,
        "list the commits between the two revisions",
    )
    .await?;
    let commits: Vec<String> = String::from_utf8_lossy(&bytes)
        .lines()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    if commits.is_empty() {
        return Err(invalid(
            "there is no commit between the good and the bad revision",
        ));
    }
    if commits.len() > MAX_CANDIDATES {
        return Err(invalid(format!(
            "more than {MAX_CANDIDATES} commits lie between the two revisions; narrow the range"
        )));
    }
    Ok(commits)
}

async fn commit_subject(project: &Path, commit: &str) -> String {
    git_output(
        project,
        &["log", "-1", "--format=%s", commit],
        4096,
        "read the commit subject",
    )
    .await
    .map(|bytes| first_line(&bytes))
    .unwrap_or_default()
}

/// Write the admitted source files of `commit` under `destination`, reading
/// them as stored objects.
async fn materialize_commit(
    project: &Path,
    commit: &str,
    destination: &Path,
) -> Result<usize, ClassifiedError> {
    let listing = git_output(
        project,
        &["ls-tree", "-r", "-z", "--long", commit],
        MAX_LISTING_BYTES,
        "list the commit's files",
    )
    .await?;
    let files = parse_tree_listing(&listing)?;
    let failed = |reason: String| invalid(format!("git could not read the commit: {reason}"));
    let mut child = git(project)
        .args(["cat-file", "--batch"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| failed(error.to_string()))?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(ClassifiedError::Internal(
            "git cat-file pipes are unavailable".to_owned(),
        ));
    };
    let mut request = String::with_capacity(files.len() * 41);
    for file in &files {
        request.push_str(&file.object);
        request.push('\n');
    }
    // Requests are written from their own task: git answers while it reads,
    // and a single task doing both would stall once a pipe filled.
    let writer = tokio::spawn(async move {
        // A write error means git exited early; the reader reports that.
        let _ = stdin.write_all(request.as_bytes()).await;
    });
    let read = async {
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut header = String::new();
        for file in &files {
            header.clear();
            reader
                .read_line(&mut header)
                .await
                .map_err(|error| failed(error.to_string()))?;
            let expected = format!("{} blob {}", file.object, file.size);
            if header.trim_end() != expected {
                return Err(failed(format!(
                    "unexpected object header for {}",
                    file.path.display()
                )));
            }
            // The size is bounded by `parse_tree_listing`.
            let mut content = vec![0_u8; file.size as usize + 1];
            reader
                .read_exact(&mut content)
                .await
                .map_err(|error| failed(error.to_string()))?;
            content.pop();
            let path = destination.join(&file.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| ClassifiedError::Internal(format!("mkdir: {error}")))?;
            }
            std::fs::write(&path, &content).map_err(|error| {
                ClassifiedError::Internal(format!("write {}: {error}", path.display()))
            })?;
        }
        Ok(files.len())
    };
    let result = tokio::time::timeout(GIT_TREE_TIMEOUT, read)
        .await
        .map_err(|_| failed("it timed out".to_owned()))?;
    writer.abort();
    result
}

/// Decides one commit. The search is generic over it so the ordering logic
/// is tested without git or a sandbox.
pub(crate) trait CommitTester {
    async fn test(&mut self, commit: &str) -> Result<(BisectVerdict, String), ClassifiedError>;
}

/// Where a search over `commits` ended: `Ok(index)` is the first bad commit,
/// `Err(range)` the inclusive index range it lies in.
type SearchEnd = Result<usize, (usize, usize)>;

/// Binary search for the first bad commit. `commits` is oldest first and its
/// last element is already known bad; the commit before the first element is
/// already known good. A skipped commit narrows nothing; when the midpoint is
/// skipped the nearest untested commit inside the open interval is tried.
async fn search<T: CommitTester>(
    commits: &[String],
    tester: &mut T,
    steps: &mut Vec<BisectStep>,
    budget: usize,
) -> Result<SearchEnd, ClassifiedError> {
    // `good` is one past the last known-good index, so the first bad commit
    // lies in `good..=bad`.
    let mut good = 0_usize;
    let mut bad = commits.len() - 1;
    let mut skipped: HashSet<usize> = HashSet::new();
    let mut builds = 0_usize;
    while good < bad {
        let middle = good + (bad - good) / 2;
        // Untested indexes in `good..bad`, nearest the midpoint first.
        let next = (good..bad)
            .filter(|index| !skipped.contains(index))
            .min_by_key(|index| index.abs_diff(middle));
        let Some(index) = next else {
            return Ok(Err((good, bad)));
        };
        if builds == budget {
            return Ok(Err((good, bad)));
        }
        builds += 1;
        let (verdict, note) = tester.test(&commits[index]).await?;
        steps.push(BisectStep {
            commit: commits[index].clone(),
            verdict,
            note,
        });
        match verdict {
            BisectVerdict::Good => good = index + 1,
            BisectVerdict::Bad => bad = index,
            BisectVerdict::Skip => {
                skipped.insert(index);
            }
        }
    }
    Ok(Ok(bad))
}

/// Builds and replays one commit in the sandbox.
struct SandboxTester<'a> {
    runtime: &'a dyn hf_core::runtime::RuntimeAdapter,
    project: &'a Path,
    harness: &'a Harness,
    input: &'a [u8],
    /// `<workspace_root>/<project>/.bisect/<crash id>`.
    root: PathBuf,
}

impl SandboxTester<'_> {
    async fn test_in(
        &self,
        commit: &str,
        directory: &Path,
    ) -> Result<(BisectVerdict, String), ClassifiedError> {
        if let Err(error) = materialize_commit(self.project, commit, directory).await {
            return Ok((
                BisectVerdict::Skip,
                first_line(error.to_string().as_bytes()),
            ));
        }
        std::fs::write(directory.join(INPUT_NAME), self.input)
            .map_err(|error| ClassifiedError::Internal(format!("stage crash input: {error}")))?;
        let options = hf_core::runtime::SandboxOptions::default();
        let harness = Harness {
            // The companion and the mutator are extra builds the replay
            // never runs.
            cmplog: None,
            custom_mutator: None,
            ..self.harness.clone()
        };
        let compiled =
            match hf_harness::try_compile_with_options(harness, self.runtime, directory, &options)
                .await?
            {
                hf_harness::CompileResult::Ok(harness) => harness,
                hf_harness::CompileResult::Failed(failure) => {
                    let reason = failure
                        .stderr
                        .lines()
                        .find(|line| line.contains("error"))
                        .unwrap_or("the harness did not build at this commit")
                        .trim()
                        .chars()
                        .take(200)
                        .collect();
                    return Ok((BisectVerdict::Skip, reason));
                }
            };
        let binary = compiled
            .build_cmd
            .output
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| ClassifiedError::Internal("harness has no output name".to_owned()))?;
        let command = vec![format!("/work/{binary}"), format!("/work/{INPUT_NAME}")];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 30,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            ..hf_core::runtime::SandboxOptions::default()
        };
        let result = self
            .runtime
            .run_command_opts(&command, directory, &limits, &sandbox)
            .await?;
        if result.termination != hf_core::runtime::CommandTermination::Completed {
            return Ok((
                BisectVerdict::Skip,
                "the replay did not complete within its limits".to_owned(),
            ));
        }
        let output = format!("{}\n{}", result.stdout, result.stderr);
        if hf_crash::looks_like_crash(&output) {
            Ok((BisectVerdict::Bad, String::new()))
        } else {
            Ok((BisectVerdict::Good, String::new()))
        }
    }
}

impl CommitTester for SandboxTester<'_> {
    async fn test(&mut self, commit: &str) -> Result<(BisectVerdict, String), ClassifiedError> {
        let directory = ensure_workspace_directory(&self.root, Path::new(commit))?;
        let outcome = self.test_in(commit, &directory).await;
        // The directory holds another revision's sources and an executed
        // binary; nothing later reads it.
        if let Err(error) = std::fs::remove_dir_all(&directory) {
            tracing::warn!(%error, "could not remove a bisection directory");
        }
        outcome
    }
}

impl ServiceContainer {
    /// Find the first commit between `good` and `bad` (default `HEAD`) at
    /// which the input of `crash_id` crashes under the active promoted
    /// harness of `target`.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] when the crash does not belong
    /// to the project and target, the harness is not a promoted C or C++
    /// harness, a revision is not accepted or does not resolve, `good` is not
    /// an ancestor of `bad`, the input crashes at `good`, or it does not
    /// crash at `bad`. Returns the approval gate's error when compiling or
    /// running is refused, and sandbox errors from the runtime.
    pub async fn bisect_crash(
        &self,
        project: &Path,
        target: &str,
        crash_id: &str,
        good: &str,
        bad: Option<&str>,
    ) -> Result<BisectOutcome, ClassifiedError> {
        let id =
            Uuid::parse_str(crash_id).map_err(|error| invalid(format!("bad crash id: {error}")))?;
        self.ensure_crash_owned_by_project(project, id).await?;
        let store = self
            .store()
            .ok_or_else(|| invalid("bisection requires the persistent service store"))?;
        let crash = store
            .get_crash(id)
            .await?
            .ok_or_else(|| invalid(format!("finding {id} not found")))?;
        let run = store
            .get_run(crash.run_id)
            .await?
            .ok_or_else(|| invalid(format!("finding {id} names a missing run")))?;
        if self.resolve_target_id_any_language(project, target).await? != crash.target_id {
            return Err(invalid(format!(
                "finding {id} does not belong to target '{target}'"
            )));
        }
        let harness = self.active_harness(project, target, run.engine).await?;
        require_bisectable(&harness)?;
        let input = read_crash_input(&crash.input_path)?;

        let good = resolve_commit(project, good).await?;
        let bad = resolve_commit(project, bad.unwrap_or("HEAD")).await?;
        let commits = candidate_commits(project, &good, &bad).await?;

        self.authorize_recorded(Action::CompileHarness, "bisect_crash", Some(project))
            .await?;
        self.authorize_recorded(Action::RunHarness, "bisect_crash", Some(project))
            .await?;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let root = ensure_workspace_directory(
            &prepare_configured_workspace_root()?,
            &PathBuf::from(project_slug(project))
                .join(".bisect")
                .join(id.to_string()),
        )?;
        let mut tester = SandboxTester {
            runtime: self.runtime.as_ref(),
            project,
            harness: &harness,
            input: &input,
            root: root.clone(),
        };
        let mut steps = Vec::new();
        let outcome = run_bisection(project, &good, &bad, &commits, &mut tester, &mut steps).await;
        if let Err(error) = std::fs::remove_dir_all(&root) {
            tracing::warn!(%error, "could not remove the bisection root");
        }
        Ok(BisectOutcome {
            good,
            bad,
            candidates: commits.len(),
            result: outcome?,
            steps,
        })
    }
}

/// Check both ends, then search between them.
async fn run_bisection<T: CommitTester>(
    project: &Path,
    good: &str,
    bad: &str,
    commits: &[String],
    tester: &mut T,
    steps: &mut Vec<BisectStep>,
) -> Result<BisectResult, ClassifiedError> {
    for (commit, expected) in [(bad, BisectVerdict::Bad), (good, BisectVerdict::Good)] {
        let (verdict, note) = tester.test(commit).await?;
        steps.push(BisectStep {
            commit: commit.to_owned(),
            verdict,
            note: note.clone(),
        });
        if verdict != expected {
            return Err(invalid(end_mismatch(commit, expected, verdict, &note)));
        }
    }
    Ok(
        match search(commits, tester, steps, MAX_TESTED.saturating_sub(2)).await? {
            Ok(index) => BisectResult::FirstBad {
                subject: commit_subject(project, &commits[index]).await,
                commit: commits[index].clone(),
            },
            Err((first, last)) => BisectResult::Undecided {
                commits: commits[first..=last].to_vec(),
            },
        },
    )
}

fn end_mismatch(
    commit: &str,
    expected: BisectVerdict,
    observed: BisectVerdict,
    note: &str,
) -> String {
    let short = &commit[..commit.len().min(12)];
    match (expected, observed) {
        (BisectVerdict::Bad, BisectVerdict::Good) => format!(
            "the input does not crash at the bad revision {short}; there is nothing to bisect"
        ),
        (BisectVerdict::Good, BisectVerdict::Bad) => format!(
            "the input already crashes at the good revision {short}; choose an older good revision"
        ),
        _ => format!(
            "revision {short} could not be built or replayed, so it cannot anchor the bisection: \
             {note}"
        ),
    }
}

fn require_bisectable(harness: &Harness) -> Result<(), ClassifiedError> {
    if !matches!(harness.language, TargetLanguage::C | TargetLanguage::Cpp)
        || !matches!(
            harness.engine,
            EngineKind::LibFuzzer | EngineKind::AflPlusPlus | EngineKind::Honggfuzz
        )
    {
        return Err(invalid(
            "bisection supports C and C++ harnesses on libFuzzer, AFL++ and honggfuzz",
        ));
    }
    if harness.status != HarnessStatus::Promoted {
        return Err(invalid(
            "bisection replays the promoted harness; the active revision is not promoted",
        ));
    }
    Ok(())
}

fn read_crash_input(path: &Path) -> Result<Vec<u8>, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("the crash input is not available: {error}")))?;
    if !metadata.is_file() {
        return Err(invalid("the crash input is not a regular file"));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(invalid(
            "the crash input is larger than the 64 MiB bisection limit",
        ));
    }
    std::fs::read(path).map_err(|error| invalid(format!("cannot read the crash input: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tester scripted by commit name: `g*` good, `b*` bad, `s*` skip.
    struct Scripted {
        asked: Vec<String>,
    }

    impl CommitTester for Scripted {
        async fn test(&mut self, commit: &str) -> Result<(BisectVerdict, String), ClassifiedError> {
            self.asked.push(commit.to_owned());
            Ok(match commit.as_bytes()[0] {
                b'g' => (BisectVerdict::Good, String::new()),
                b'b' => (BisectVerdict::Bad, String::new()),
                _ => (BisectVerdict::Skip, "does not build".to_owned()),
            })
        }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    async fn run(commits: &[&str], budget: usize) -> (SearchEnd, Vec<String>) {
        let commits = names(commits);
        let mut tester = Scripted { asked: Vec::new() };
        let mut steps = Vec::new();
        let end = search(&commits, &mut tester, &mut steps, budget)
            .await
            .unwrap();
        assert_eq!(steps.len(), tester.asked.len());
        (end, tester.asked)
    }

    #[tokio::test]
    async fn the_search_finds_the_first_bad_commit_in_logarithmic_steps() {
        let commits: Vec<String> = (0..1000)
            .map(|index| format!("{}{index}", if index < 613 { 'g' } else { 'b' }))
            .collect();
        let borrowed: Vec<&str> = commits.iter().map(String::as_str).collect();
        let (end, asked) = run(&borrowed, MAX_TESTED).await;
        assert_eq!(end, Ok(613));
        assert!(asked.len() <= 10, "{} builds", asked.len());
    }

    #[tokio::test]
    async fn the_ends_of_the_range_are_found() {
        assert_eq!(run(&["b0"], MAX_TESTED).await, (Ok(0), Vec::new()));
        assert_eq!(run(&["b0", "b1", "b2"], MAX_TESTED).await.0, Ok(0));
        assert_eq!(run(&["g0", "g1", "b2"], MAX_TESTED).await.0, Ok(2));
    }

    #[tokio::test]
    async fn a_skipped_midpoint_is_stepped_around() {
        let (end, asked) = run(&["g0", "g1", "s2", "g3", "b4"], MAX_TESTED).await;
        assert_eq!(end, Ok(4));
        assert!(asked.contains(&"s2".to_owned()));
    }

    #[tokio::test]
    async fn a_skip_just_before_the_first_bad_commit_stays_undecided() {
        // s2 could not be tested, so the first bad commit is s2 or b3.
        let (end, _) = run(&["g0", "g1", "s2", "b3", "b4"], MAX_TESTED).await;
        assert_eq!(end, Err((2, 3)));
    }

    #[tokio::test]
    async fn commits_that_cannot_be_told_apart_are_reported_as_a_range() {
        // The first bad commit is s2, s3 or b4: neither skip can be decided.
        let (end, _) = run(&["g0", "g1", "s2", "s3", "b4"], MAX_TESTED).await;
        assert_eq!(end, Err((2, 4)));
    }

    #[tokio::test]
    async fn an_exhausted_build_budget_reports_the_remaining_range() {
        let commits: Vec<String> = (0..100)
            .map(|index| format!("{}{index}", if index < 70 { 'g' } else { 'b' }))
            .collect();
        let borrowed: Vec<&str> = commits.iter().map(String::as_str).collect();
        let (end, asked) = run(&borrowed, 2).await;
        assert_eq!(asked.len(), 2);
        let Err((first, last)) = end else {
            panic!("two builds cannot decide 100 commits");
        };
        assert!(first <= 70 && 70 <= last, "{first}..={last}");
    }

    #[tokio::test]
    async fn an_end_that_contradicts_the_request_stops_the_bisection() {
        let commits = names(&["g1", "b2"]);
        for (good, bad, expected) in [
            ("g0", "g9", "does not crash at the bad revision"),
            ("b0", "b9", "already crashes at the good revision"),
            ("g0", "s9", "could not be built or replayed"),
        ] {
            let mut tester = Scripted { asked: Vec::new() };
            let mut steps = Vec::new();
            let error = run_bisection(Path::new("."), good, bad, &commits, &mut tester, &mut steps)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn revisions_that_could_be_options_or_ranges_are_refused() {
        for accepted in [
            "HEAD",
            "HEAD~3",
            "main^2",
            "v1.2.0",
            "feature/x-1",
            "0123abc",
        ] {
            validate_revision(accepted).unwrap();
        }
        for refused in [
            "",
            "--upload-pack=x",
            "-n",
            "a..b",
            "a b",
            "x;y",
            "$(id)",
            "HEAD@{1}",
            "a:b",
        ] {
            assert!(validate_revision(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn only_regular_source_files_inside_the_tree_are_materialized() {
        let listing = b"100644 blob aaaa      12\tsrc/parse.c\0\
            100755 blob bbbb       3\tinclude/api.h\0\
            120000 blob cccc       9\tsrc/link.c\0\
            160000 commit dddd       -\tvendor/lib\0\
            100644 blob eeee       5\tREADME.md\0\
            100644 blob ffff       5\tbuild/gen.c\0\
            100644 blob 1111       5\t../escape.c\0\
            100644 blob 2222       5\t/abs.c\0\
            100644 blob zzzz       5\tsrc/bad_object.c\0";
        let files = parse_tree_listing(listing).unwrap();
        assert_eq!(
            files,
            vec![
                TreeFile {
                    object: "aaaa".to_owned(),
                    size: 12,
                    path: PathBuf::from("src/parse.c"),
                },
                TreeFile {
                    object: "bbbb".to_owned(),
                    size: 3,
                    path: PathBuf::from("include/api.h"),
                },
            ]
        );
    }

    #[test]
    fn a_tree_over_a_materialization_bound_is_refused() {
        let big = format!("100644 blob aaaa {}\tsrc/big.c\0", MAX_FILE_BYTES + 1);
        assert!(parse_tree_listing(big.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("16 MiB"));
    }

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn commit_all(repo: &Path, message: &str) {
        for args in [
            vec!["add", "-A"],
            vec![
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                message,
            ],
        ] {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(&args)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        }
    }

    #[tokio::test]
    async fn history_is_read_as_objects_without_touching_the_checkout() {
        if !git_available() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["init", "-q", "-b", "main"])
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/parse.c"), "int v(void){return 1;}\n").unwrap();
        std::fs::write(repo.path().join("notes.txt"), "not a source\n").unwrap();
        commit_all(repo.path(), "first");
        std::fs::write(repo.path().join("src/parse.c"), "int v(void){return 2;}\n").unwrap();
        std::fs::write(repo.path().join("src/extra.h"), "#define X 1\n").unwrap();
        commit_all(repo.path(), "second subject");
        // An uncommitted edit must neither be read nor disturbed.
        std::fs::write(repo.path().join("src/parse.c"), "int v(void){return 3;}\n").unwrap();

        let good = resolve_commit(repo.path(), "HEAD~1").await.unwrap();
        let bad = resolve_commit(repo.path(), "HEAD").await.unwrap();
        assert_eq!(good.len(), 40);
        let commits = candidate_commits(repo.path(), &good, &bad).await.unwrap();
        assert_eq!(commits, vec![bad.clone()]);
        assert_eq!(commit_subject(repo.path(), &bad).await, "second subject");
        assert!(candidate_commits(repo.path(), &bad, &good).await.is_err());
        assert!(resolve_commit(repo.path(), "no-such-branch").await.is_err());

        let out = tempfile::tempdir().unwrap();
        let old = out.path().join("old");
        let new = out.path().join("new");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        assert_eq!(
            materialize_commit(repo.path(), &good, &old).await.unwrap(),
            1
        );
        assert_eq!(
            materialize_commit(repo.path(), &bad, &new).await.unwrap(),
            2
        );
        assert_eq!(
            std::fs::read_to_string(old.join("src/parse.c")).unwrap(),
            "int v(void){return 1;}\n"
        );
        assert_eq!(
            std::fs::read_to_string(new.join("src/parse.c")).unwrap(),
            "int v(void){return 2;}\n"
        );
        assert_eq!(
            std::fs::read_to_string(new.join("src/extra.h")).unwrap(),
            "#define X 1\n"
        );
        assert!(!old.join("notes.txt").exists());
        assert_eq!(
            std::fs::read_to_string(repo.path().join("src/parse.c")).unwrap(),
            "int v(void){return 3;}\n",
            "the working tree is untouched"
        );
    }

    const LIVE_HARNESS: &str = "#include <stddef.h>\n#include <stdint.h>\nint parse(const uint8_t *data, size_t size);\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    parse(data, size);\n    return 0;\n}\n";
    const LIVE_SAFE: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\nint parse(const uint8_t *data, size_t size) {\n    char buffer[8];\n    if (size > sizeof buffer) {\n        return -1;\n    }\n    memcpy(buffer, data, size);\n    return buffer[0];\n}\n";
    const LIVE_BROKEN: &str = "this does not compile\n";
    const LIVE_UNSAFE: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\nint parse(const uint8_t *data, size_t size) {\n    char buffer[8];\n    memcpy(buffer, data, size);\n    return buffer[0];\n}\n";

    /// Bisects a planted stack overflow over a real repository in the real
    /// sandbox: seven commits, one that does not build, the overflow
    /// introduced at the fifth.
    #[tokio::test]
    #[ignore = "requires git, a local Docker daemon, and the pinned sandbox image"]
    async fn live_bisection_finds_the_commit_that_introduced_a_planted_overflow() {
        assert!(git_available() && hf_runtime::docker_daemon_ready());
        let repo = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["init", "-q", "-b", "main"])
            .status()
            .unwrap();
        assert!(status.success());
        let history = [
            (LIVE_SAFE, "add the parser"),
            (LIVE_SAFE, "document the parser"),
            (LIVE_BROKEN, "work in progress"),
            (LIVE_SAFE, "restore the parser"),
            (LIVE_UNSAFE, "simplify the length handling"),
            (LIVE_UNSAFE, "tidy"),
            (LIVE_UNSAFE, "release notes"),
        ];
        for (index, (source, message)) in history.iter().enumerate() {
            std::fs::write(repo.path().join("parse.c"), source).unwrap();
            std::fs::write(repo.path().join("CHANGES.txt"), format!("{index}\n")).unwrap();
            commit_all(repo.path(), message);
        }
        let good = resolve_commit(repo.path(), "HEAD~6").await.unwrap();
        let bad = resolve_commit(repo.path(), "HEAD").await.unwrap();
        let introduced = resolve_commit(repo.path(), "HEAD~2").await.unwrap();
        let commits = candidate_commits(repo.path(), &good, &bad).await.unwrap();
        assert_eq!(commits.len(), 6);

        let workspace = tempfile::tempdir().unwrap();
        let runtime = hf_runtime::docker::DockerRuntime::new(
            hf_runtime::RuntimeConfig::default(),
            workspace.path(),
        );
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            engine: EngineKind::LibFuzzer,
            source: LIVE_HARNESS.to_owned(),
            language: TargetLanguage::C,
            build_cmd: hf_harness::build_command_for_source(
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                "fuzz_parse",
                hf_core::target::Sanitizer::Address,
                LIVE_HARNESS,
            )
            .unwrap(),
            sanitizer: hf_core::target::Sanitizer::Address,
            status: HarnessStatus::Promoted,
            smoke_run: None,
            cmplog: None,
            custom_mutator: None,
        };
        let input = [b'A'; 64];
        let mut tester = SandboxTester {
            runtime: &runtime,
            project: repo.path(),
            harness: &harness,
            input: &input,
            root: workspace.path().to_path_buf(),
        };
        let mut steps = Vec::new();
        let result = run_bisection(repo.path(), &good, &bad, &commits, &mut tester, &mut steps)
            .await
            .unwrap();
        for step in &steps {
            println!("{:?} {} {}", step.verdict, &step.commit[..12], step.note);
        }
        assert_eq!(
            result,
            BisectResult::FirstBad {
                commit: introduced,
                subject: "simplify the length handling".to_owned(),
            }
        );
        assert!(steps.len() <= 6, "{} builds", steps.len());
        // A commit the compiler rejects is skipped with the compiler's reason.
        let broken = resolve_commit(repo.path(), "HEAD~4").await.unwrap();
        let (verdict, note) = tester.test(&broken).await.unwrap();
        assert_eq!(verdict, BisectVerdict::Skip);
        assert!(note.contains("error"), "{note}");
        // Every per-commit directory was removed, and the checkout is intact.
        assert_eq!(std::fs::read_dir(workspace.path()).unwrap().count(), 0);
        assert_eq!(
            std::fs::read_to_string(repo.path().join("parse.c")).unwrap(),
            LIVE_UNSAFE
        );
    }
}
