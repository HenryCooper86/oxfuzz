//! Internal-team workbench summaries and export intents.
//!
//! This module is read-only over fuzz artifacts: it aggregates persisted
//! targets, harnesses, runs, crashes, and corpus metadata into dashboard-ready
//! DTOs. It does not build harnesses, run fuzzers, or publish bug reports.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use hf_core::crash::Crash;
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::target::TargetCandidate;
use hf_storage::{RunRecord, RunStatus, Store};
use serde::Serialize;
use uuid::Uuid;

/// Aggregate counts for the internal dashboard.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WorkbenchTotals {
    pub projects: usize,
    pub targets: usize,
    pub harnesses: usize,
    pub harnesses_needing_review: usize,
    pub runs: usize,
    pub active_runs: usize,
    pub crashes: usize,
    pub corpus_entries: usize,
}

/// Service-owned readiness summary for the current workbench scope.
#[derive(Debug, Clone, Serialize)]
pub struct WorkbenchReadiness {
    pub state: String,
    pub score: u8,
    pub headline: String,
    pub detail: String,
    pub blockers: Vec<String>,
}

/// One recent fuzz run row for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct WorkbenchRun {
    pub id: String,
    pub project_root: String,
    pub engine: String,
    pub status: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub crash_count: usize,
}

/// One high-priority fuzzing target row.
#[derive(Debug, Clone, Serialize)]
pub struct WorkbenchTarget {
    pub id: String,
    pub project_root: String,
    pub symbol: String,
    pub language: String,
    pub fit_score: f64,
    pub rationale: String,
}

/// A generated harness awaiting review or promotion.
#[derive(Debug, Clone, Serialize)]
pub struct HarnessReviewItem {
    pub harness_id: String,
    pub target_id: String,
    pub project_root: String,
    pub target_symbol: String,
    pub engine: String,
    pub language: String,
    pub status: String,
    pub build_output: String,
    pub smoke_passed: bool,
    pub smoke_execs_per_sec: f64,
    pub needs_review: bool,
    pub next_action: String,
    pub source_preview: String,
}

/// One crash that may need a human-created issue.
#[derive(Debug, Clone, Serialize)]
pub struct CrashReviewItem {
    pub crash_id: String,
    pub run_id: String,
    pub target_id: String,
    pub target_symbol: String,
    pub kind: String,
    pub summary: String,
    pub severity: String,
    pub minimized: bool,
    pub has_bug_report: bool,
}

/// Dashboard data for the active project or whole database.
#[derive(Debug, Clone, Serialize)]
pub struct WorkbenchDashboard {
    pub active_project: Option<String>,
    pub active_target: Option<String>,
    pub totals: WorkbenchTotals,
    pub recent_runs: Vec<WorkbenchRun>,
    pub top_targets: Vec<WorkbenchTarget>,
    pub harness_reviews: Vec<HarnessReviewItem>,
    pub crash_reviews: Vec<CrashReviewItem>,
    pub readiness: WorkbenchReadiness,
    pub next_actions: Vec<String>,
}

/// A human-reviewable GitLab issue draft for one crash.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabIssueExport {
    pub crash_id: String,
    pub title: String,
    pub description: String,
    pub labels: Vec<String>,
    pub project_web_url: Option<String>,
    pub issue_url: Option<String>,
}

/// Build dashboard data from persisted store state.
pub async fn dashboard(
    store: Option<&Store>,
    active_project: Option<&Path>,
    active_target: Option<&str>,
) -> WorkbenchDashboard {
    let project_filter = active_project.map(path_key);
    let project_filter_ref = project_filter.as_deref();

    let Some(store) = store else {
        return empty_dashboard(
            project_filter,
            active_target,
            "Initialize persistence to start tracking team fuzzing work.",
        );
    };

    // With a store but no project selected, the workbench has no scope: return
    // an empty, project-prompt dashboard rather than a whole-database aggregate.
    // Showing global counts here is what made the header read "No active project
    // selected" while tabs still listed unrelated targets/harnesses/crashes. The
    // intentional cross-project view lives in the Artifacts screen.
    if project_filter_ref.is_none() {
        return empty_dashboard(
            None,
            active_target,
            "Select a project to view its fuzzing workbench.",
        );
    }

    let targets = store.list_all_targets().await.unwrap_or_default();
    let runs = store
        .list_runs(project_filter_ref)
        .await
        .unwrap_or_default();
    let harnesses = store.list_all_harnesses().await.unwrap_or_default();
    let harness_to_target: HashMap<Uuid, Uuid> =
        harnesses.iter().map(|h| (h.id, h.target_id)).collect();
    let crashes = store.list_all_crashes().await.unwrap_or_default();
    let corpus_entries = store.list_all_corpus_entries().await.unwrap_or_default();

    let project_scoped_targets: Vec<TargetCandidate> = targets
        .iter()
        .filter(|t| project_matches(t.project_root.as_path(), project_filter_ref))
        .cloned()
        .collect();
    let target_ids_for_project: HashSet<Uuid> =
        project_scoped_targets.iter().map(|t| t.id).collect();

    let filtered_targets: Vec<TargetCandidate> = targets
        .iter()
        .filter(|t| {
            project_matches(t.project_root.as_path(), project_filter_ref)
                && active_target.is_none_or(|symbol| t.symbol == symbol)
        })
        .cloned()
        .collect();
    let target_ids_for_active_target: HashSet<Uuid> =
        filtered_targets.iter().map(|t| t.id).collect();

    let filtered_runs: Vec<RunRecord> = runs
        .into_iter()
        .filter(|r| {
            active_target.is_none_or(|_| {
                r.config
                    .as_ref()
                    .and_then(|config| harness_to_target.get(&config.harness_id))
                    .is_some_and(|target_id| target_ids_for_active_target.contains(target_id))
            })
        })
        .collect();

    let filtered_harnesses: Vec<Harness> = harnesses
        .into_iter()
        .filter(|h| project_filter_ref.is_none() || target_ids_for_project.contains(&h.target_id))
        .filter(|h| {
            active_target.is_none_or(|symbol| {
                targets
                    .iter()
                    .find(|t| t.id == h.target_id)
                    .is_some_and(|t| t.symbol == symbol)
            })
        })
        .collect();

    let filtered_crashes: Vec<Crash> = crashes
        .into_iter()
        .filter(|c| project_filter_ref.is_none() || target_ids_for_project.contains(&c.target_id))
        .filter(|c| {
            active_target.is_none_or(|symbol| {
                targets
                    .iter()
                    .find(|t| t.id == c.target_id)
                    .is_some_and(|t| t.symbol == symbol)
            })
        })
        .collect();

    let target_by_id: HashMap<Uuid, TargetCandidate> =
        targets.iter().map(|t| (t.id, t.clone())).collect();
    let crash_count_by_run = crash_count_by_run(&filtered_crashes);
    // A project is always selected past the early return above, so the count is
    // 0 or 1 depending on whether this project has any persisted work.
    let project_count =
        usize::from(!project_scoped_targets.is_empty() || !filtered_runs.is_empty());

    let harness_reviews = harness_review_items(filtered_harnesses, &target_by_id);
    let crash_reviews = crash_review_items(filtered_crashes, &target_by_id);
    let corpus_entry_count = if project_filter_ref.is_some() || active_target.is_some() {
        let mut count = 0;
        for target in &filtered_targets {
            count += store
                .list_corpus_entries(target.id)
                .await
                .unwrap_or_default()
                .len();
        }
        count
    } else {
        corpus_entries.len()
    };
    let active_runs = filtered_runs
        .iter()
        .filter(|r| matches!(r.status, RunStatus::Pending | RunStatus::Running))
        .count();

    let totals = WorkbenchTotals {
        projects: project_count,
        targets: filtered_targets.len(),
        harnesses: harness_reviews.len(),
        harnesses_needing_review: harness_reviews.iter().filter(|h| h.needs_review).count(),
        runs: filtered_runs.len(),
        active_runs,
        crashes: crash_reviews.len(),
        corpus_entries: corpus_entry_count,
    };
    let readiness = readiness_summary(&totals, true);

    let recent_runs = filtered_runs
        .into_iter()
        .take(8)
        .map(|r| run_view(r, &crash_count_by_run))
        .collect();
    let top_targets = filtered_targets
        .into_iter()
        .take(8)
        .map(target_view)
        .collect();
    let next_actions = next_actions(&totals);

    WorkbenchDashboard {
        active_project: project_filter,
        active_target: active_target.map(str::to_owned),
        totals,
        recent_runs,
        top_targets,
        harness_reviews,
        crash_reviews,
        readiness,
        next_actions,
    }
}

/// List reviewable harnesses only.
pub async fn harness_review_queue(
    store: Option<&Store>,
    active_project: Option<&Path>,
    active_target: Option<&str>,
) -> Vec<HarnessReviewItem> {
    dashboard(store, active_project, active_target)
        .await
        .harness_reviews
}

/// Build a GitLab issue draft for a persisted crash.
pub async fn gitlab_issue_export(
    store: Option<&Store>,
    project: &Path,
    crash_id: &str,
) -> Result<GitLabIssueExport, ClassifiedError> {
    let store =
        store.ok_or_else(|| ClassifiedError::Storage("no database configured".to_owned()))?;
    let crashes = store
        .list_all_crashes()
        .await
        .map_err(ClassifiedError::from)?;
    let crash = crashes
        .into_iter()
        .find(|c| c.id.to_string() == crash_id)
        .ok_or_else(|| ClassifiedError::Validation(format!("crash not found: {crash_id}")))?;
    let targets = store.list_all_targets().await.unwrap_or_default();
    let target = targets.iter().find(|t| t.id == crash.target_id);
    let title = issue_title(&crash, target);
    let description = issue_description(&crash, target);
    let labels = vec![
        "hobot-fuzz".to_owned(),
        "fuzzing".to_owned(),
        "crash".to_owned(),
    ];
    let project_web_url = gitlab_project_url(project);
    let issue_url = project_web_url
        .as_ref()
        .map(|base| issue_url(base, &title, &description, &labels));

    Ok(GitLabIssueExport {
        crash_id: crash.id.to_string(),
        title,
        description,
        labels,
        project_web_url,
        issue_url,
    })
}

fn empty_dashboard(
    active_project: Option<String>,
    active_target: Option<&str>,
    next_action: &str,
) -> WorkbenchDashboard {
    WorkbenchDashboard {
        active_project,
        active_target: active_target.map(str::to_owned),
        totals: WorkbenchTotals::default(),
        recent_runs: Vec::new(),
        top_targets: Vec::new(),
        harness_reviews: Vec::new(),
        crash_reviews: Vec::new(),
        readiness: readiness_summary(&WorkbenchTotals::default(), false),
        next_actions: vec![next_action.to_owned()],
    }
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn project_matches(project: &Path, filter: Option<&str>) -> bool {
    filter.is_none_or(|f| project.to_string_lossy() == f)
}

fn crash_count_by_run(crashes: &[Crash]) -> BTreeMap<Uuid, usize> {
    let mut out = BTreeMap::new();
    for crash in crashes {
        *out.entry(crash.run_id).or_insert(0) += 1;
    }
    out
}

fn run_view(run: RunRecord, crash_count_by_run: &BTreeMap<Uuid, usize>) -> WorkbenchRun {
    WorkbenchRun {
        id: run.id.to_string(),
        project_root: run.project_root,
        engine: format!("{:?}", run.engine),
        status: format!("{:?}", run.status),
        started_at: format_ts(run.started_at),
        ended_at: run.ended_at.map(format_ts),
        crash_count: crash_count_by_run.get(&run.id).copied().unwrap_or_default(),
    }
}

fn target_view(target: TargetCandidate) -> WorkbenchTarget {
    WorkbenchTarget {
        id: target.id.to_string(),
        project_root: target.project_root.to_string_lossy().to_string(),
        symbol: target.symbol,
        language: format!("{:?}", target.language),
        fit_score: target.fit_score,
        rationale: target.rationale,
    }
}

fn harness_review_items(
    harnesses: Vec<Harness>,
    target_by_id: &HashMap<Uuid, TargetCandidate>,
) -> Vec<HarnessReviewItem> {
    let mut items: Vec<HarnessReviewItem> = harnesses
        .into_iter()
        .map(|h| {
            let target = target_by_id.get(&h.target_id);
            let smoke = h.smoke_run.as_ref();
            let needs_review = matches!(
                h.status,
                HarnessStatus::Draft | HarnessStatus::Compiled | HarnessStatus::SmokePassed
            );
            HarnessReviewItem {
                harness_id: h.id.to_string(),
                target_id: h.target_id.to_string(),
                project_root: target
                    .map(|t| t.project_root.to_string_lossy().to_string())
                    .unwrap_or_default(),
                target_symbol: target.map_or_else(|| "unknown".to_owned(), |t| t.symbol.clone()),
                engine: format!("{:?}", h.engine),
                language: format!("{:?}", h.language),
                status: format!("{:?}", h.status),
                build_output: h.build_cmd.output.to_string_lossy().to_string(),
                smoke_passed: smoke.is_some_and(|s| s.passed),
                smoke_execs_per_sec: smoke.map_or(0.0, |s| s.execs_per_sec),
                needs_review,
                next_action: next_harness_action(h.status, smoke.is_some_and(|s| s.passed)),
                source_preview: source_preview(&h.source),
            }
        })
        .collect();
    items.sort_by_key(|h| (!h.needs_review, h.target_symbol.clone()));
    items
}

fn crash_review_items(
    crashes: Vec<Crash>,
    target_by_id: &HashMap<Uuid, TargetCandidate>,
) -> Vec<CrashReviewItem> {
    crashes
        .into_iter()
        .map(|c| {
            let target_symbol = target_by_id
                .get(&c.target_id)
                .map_or_else(|| "unknown".to_owned(), |t| t.symbol.clone());
            let severity = c.casr.as_ref().map_or_else(
                || "Unclassified".to_owned(),
                |r| format!("{:?}", r.severity),
            );
            CrashReviewItem {
                crash_id: c.id.to_string(),
                run_id: c.run_id.to_string(),
                target_id: c.target_id.to_string(),
                target_symbol,
                kind: format!("{:?}", c.kind),
                summary: c.summary,
                severity,
                minimized: c.minimized,
                has_bug_report: c.bug_report.is_some(),
            }
        })
        .collect()
}

fn next_harness_action(status: HarnessStatus, smoke_passed: bool) -> String {
    match (status, smoke_passed) {
        (HarnessStatus::Draft, _) => "Compile in sandbox".to_owned(),
        (HarnessStatus::Compiled, false) => "Run smoke fuzz".to_owned(),
        (HarnessStatus::Compiled, true) | (HarnessStatus::SmokePassed, _) => {
            "Review and approve for campaign".to_owned()
        }
        (HarnessStatus::Promoted, _) => "Ready for scheduled runs".to_owned(),
        (HarnessStatus::Failed, _) => "Fix build or regenerate".to_owned(),
    }
}

fn source_preview(source: &str) -> String {
    source.lines().take(10).collect::<Vec<_>>().join("\n")
}

fn next_actions(totals: &WorkbenchTotals) -> Vec<String> {
    let mut actions = Vec::new();
    if totals.targets == 0 {
        actions.push("Run target discovery on an internal project.".to_owned());
    }
    if totals.harnesses_needing_review > 0 {
        actions.push(format!(
            "Review {} generated harness{} before full fuzzing.",
            totals.harnesses_needing_review,
            if totals.harnesses_needing_review == 1 {
                ""
            } else {
                "es"
            }
        ));
    }
    if totals.crashes > 0 {
        actions.push(format!(
            "Export or assign {} crash{} for triage.",
            totals.crashes,
            if totals.crashes == 1 { "" } else { "es" }
        ));
    }
    if totals.runs == 0 && totals.targets > 0 {
        actions.push("Schedule a short smoke campaign for the highest-ranked target.".to_owned());
    }
    if actions.is_empty() {
        actions.push("No urgent work queued; schedule deeper nightly campaigns.".to_owned());
    }
    actions
}

fn readiness_summary(totals: &WorkbenchTotals, store_configured: bool) -> WorkbenchReadiness {
    if !store_configured {
        return WorkbenchReadiness {
            state: "setup_required".to_owned(),
            score: 0,
            headline: "Persistence setup required".to_owned(),
            detail: "Initialize persistence before tracking targets, harnesses, runs, and crashes."
                .to_owned(),
            blockers: vec!["Persistence is not initialized.".to_owned()],
        };
    }

    let mut blockers = Vec::new();
    if totals.targets == 0 {
        blockers.push("No fuzzing targets discovered.".to_owned());
    }
    if totals.targets > 0 && totals.harnesses == 0 {
        blockers.push("No generated harnesses exist for discovered targets.".to_owned());
    }
    if totals.harnesses_needing_review > 0 {
        blockers.push(format!(
            "{} generated harness{} need human approval.",
            totals.harnesses_needing_review,
            plural_suffix(totals.harnesses_needing_review),
        ));
    }
    if totals.harnesses > 0 && totals.harnesses_needing_review == 0 && totals.runs == 0 {
        blockers.push("No fuzzing campaign history exists yet.".to_owned());
    }
    if totals.crashes > 0 {
        blockers.push(format!(
            "{} crash{} need triage or issue export.",
            totals.crashes,
            plural_suffix(totals.crashes),
        ));
    }

    let mut score = 10_u16;
    if totals.targets > 0 {
        score += 25;
    }
    if totals.harnesses > 0 {
        score += 20;
    }
    if totals.harnesses > 0 && totals.harnesses_needing_review == 0 {
        score += 15;
    }
    if totals.runs > 0 {
        score += 15;
    }
    if totals.runs > 0 && totals.crashes == 0 {
        score += 15;
    }
    if totals.active_runs > 0 {
        score = (score + 5).min(100);
    }

    let (state, headline, detail) = if totals.targets == 0 {
        (
            "setup_required",
            "Discovery needed",
            "Run target discovery before creating harnesses or campaigns.",
        )
    } else if totals.harnesses == 0 {
        (
            "harness_required",
            "Harness generation needed",
            "Generate a sandbox-built harness for the highest-ranked target.",
        )
    } else if totals.harnesses_needing_review > 0 {
        (
            "review_required",
            "Harness review required",
            "Approve generated harnesses before full fuzzing campaigns.",
        )
    } else if totals.crashes > 0 {
        (
            "triage_required",
            "Crash triage required",
            "Triage crashes and export issue drafts before expanding campaign scope.",
        )
    } else if totals.active_runs > 0 {
        (
            "active",
            "Campaign running",
            "Monitor the active fuzzing campaign and review new findings as they land.",
        )
    } else if totals.runs == 0 {
        (
            "campaign_ready",
            "Ready for smoke campaign",
            "Start a short sandboxed fuzz run to establish baseline stability.",
        )
    } else {
        (
            "ready",
            "Ready for deeper campaigns",
            "The selected scope has targets, reviewed harnesses, and campaign history.",
        )
    };

    WorkbenchReadiness {
        state: state.to_owned(),
        score: u8::try_from(score.min(100)).unwrap_or(100),
        headline: headline.to_owned(),
        detail: detail.to_owned(),
        blockers,
    }
}

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn issue_title(crash: &Crash, target: Option<&TargetCandidate>) -> String {
    if let Some(report) = &crash.bug_report {
        return report.title.clone();
    }
    let target_name = target.map_or("unknown", |t| t.symbol.as_str());
    let summary = if crash.summary.is_empty() {
        format!("{:?}", crash.kind)
    } else {
        crash.summary.clone()
    };
    format!("[hobot_fuzz] {target_name}: {summary}")
}

fn issue_description(crash: &Crash, target: Option<&TargetCandidate>) -> String {
    let target_name = target.map_or("unknown".to_owned(), |t| t.symbol.clone());
    let project_root = target
        .map(|t| t.project_root.to_string_lossy().to_string())
        .unwrap_or_default();
    let severity = crash.casr.as_ref().map_or_else(
        || "Unclassified".to_owned(),
        |c| format!("{:?}", c.severity),
    );
    let mut body = String::new();
    body.push_str("## Summary\n\n");
    if crash.summary.is_empty() {
        body.push_str("Crash found by hobot_fuzz.\n\n");
    } else {
        body.push_str(&crash.summary);
        body.push_str("\n\n");
    }
    body.push_str("## Fuzzing Context\n\n");
    let _ = writeln!(body, "- Target: `{target_name}`");
    if !project_root.is_empty() {
        let _ = writeln!(body, "- Project: `{project_root}`");
    }
    let _ = writeln!(body, "- Crash kind: `{:?}`", crash.kind);
    let _ = writeln!(body, "- Severity: `{severity}`");
    let _ = writeln!(body, "- Crash id: `{}`", crash.id);
    let _ = writeln!(body, "- Run id: `{}`", crash.run_id);
    let _ = writeln!(body, "- Input: `{}`", crash.input_path.display());
    let _ = writeln!(body, "- Minimized: `{}`", crash.minimized);
    if !crash.stack_signature.is_empty() {
        let _ = writeln!(body, "- Stack signature: `{}`", crash.stack_signature);
    }
    if let Some(report) = &crash.bug_report {
        body.push_str("\n## Draft Bug Report\n\n");
        body.push_str(&report.summary);
        body.push_str("\n\n### Reproduction\n\n");
        body.push_str(&report.repro_steps);
        body.push('\n');
    }
    if let Some(casr) = &crash.casr {
        body.push_str("\n## CASR Stack\n\n```text\n");
        body.push_str(&casr.stack.join("\n"));
        body.push_str("\n```\n");
    }
    body
}

fn gitlab_project_url(project: &Path) -> Option<String> {
    if let (Ok(base), Ok(path)) = (
        std::env::var("HF_GITLAB_URL"),
        std::env::var("HF_GITLAB_PROJECT"),
    ) {
        return Some(format!(
            "{}/{}",
            base.trim_end_matches('/'),
            path.trim_matches('/')
        ));
    }

    let project_arg = project.to_string_lossy().to_string();
    let output = std::process::Command::new("git")
        .args(["-C", project_arg.as_str(), "remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let remote = String::from_utf8_lossy(&output.stdout);
    remote_to_web_url(remote.trim())
}

fn remote_to_web_url(remote: &str) -> Option<String> {
    if remote.is_empty() {
        return None;
    }
    if let Some(rest) = remote.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        return Some(format!("https://{host}/{}", trim_git(path)));
    }
    if let Some(rest) = remote.strip_prefix("ssh://git@") {
        let (host, path) = rest.split_once('/')?;
        return Some(format!("https://{host}/{}", trim_git(path)));
    }
    if remote.starts_with("http://") || remote.starts_with("https://") {
        return Some(trim_git(remote).to_owned());
    }
    None
}

fn trim_git(path: &str) -> &str {
    path.trim_end_matches(".git").trim_matches('/')
}

fn issue_url(base: &str, title: &str, description: &str, labels: &[String]) -> String {
    let mut url = format!(
        "{}/-/issues/new?issue%5Btitle%5D={}&issue%5Bdescription%5D={}",
        base.trim_end_matches('/'),
        percent_encode(title),
        percent_encode(description)
    );
    for label in labels {
        url.push_str("&issue%5Blabel_names%5D%5B%5D=");
        url.push_str(&percent_encode(label));
    }
    url
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn format_ts(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gitlab_ssh_remote() {
        assert_eq!(
            remote_to_web_url("git@gitlab-ce.orb.local:hobot/hobot_fuzz.git"),
            Some("https://gitlab-ce.orb.local/hobot/hobot_fuzz".to_owned())
        );
    }

    #[test]
    fn percent_encoding_handles_markdown() {
        assert_eq!(percent_encode("a b/#"), "a%20b%2F%23");
    }
}
