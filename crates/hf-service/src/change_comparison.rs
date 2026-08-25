//! Service-owned Change-Aware Pull-Request Fuzzing.
//!
//! Resolves a source diff (from a validated revision range or supplied text),
//! maps it to the discovered targets it affects, and compares retained base and
//! head run evidence. It starts no campaign, checks out no revision, and never
//! converts missing evidence into a verdict.
//!
//! See `docs/design/change-aware-pr-fuzzing-design.md`.

use hf_core::error::ClassifiedError;
use hf_storage::{RunKind, RunRecord, RunStatus, Store};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::change_impact::{
    check_comparability, classify_findings, compare_coverage, map_affected_targets,
    parse_unified_diff, AffectedTarget, ChangedFile, ClassifiedFinding, ComparabilityRefusal,
    CoverageComparison, FindingChange, TargetImpact, MAX_DIFF_BYTES,
};
use crate::container::ServiceContainer;

/// Schema version of the change-aware views.
pub const CHANGE_AWARE_SCHEMA_VERSION: u32 = 1;

/// Longest accepted git revision argument.
const MAX_REVISION_LEN: usize = 256;

/// A base and head revision to diff in the project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionRange {
    pub base: String,
    pub head: String,
}

/// Request to map a change onto the project's discovered targets. Exactly one
/// of `revisions` or `diff` must be supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeImpactRequest {
    pub project: String,
    #[serde(default)]
    pub revisions: Option<RevisionRange>,
    #[serde(default)]
    pub diff: Option<String>,
}

/// One affected target and the retained run that would baseline it.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeAwarePlanEntry {
    pub target_id: Uuid,
    pub symbol: String,
    pub impact: TargetImpact,
    pub reason_code: String,
    /// Latest comparable retained run for this target, if one exists. The plan
    /// is advisory: it starts nothing.
    pub baseline_run_id: Option<Uuid>,
}

/// Service-owned view of a change and the targets it affects.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeImpactView {
    pub schema_version: u32,
    pub files: Vec<ChangedFile>,
    pub affected: Vec<AffectedTarget>,
    pub plan: Vec<ChangeAwarePlanEntry>,
}

/// Request to compare two retained runs across a source change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionComparisonRequest {
    pub base_run_id: Uuid,
    pub head_run_id: Uuid,
    pub regression_threshold_pct: f64,
}

/// Service-owned comparison of two retained runs.
#[derive(Debug, Clone, Serialize)]
pub struct RevisionComparisonView {
    pub schema_version: u32,
    pub base_run_id: Uuid,
    pub head_run_id: Uuid,
    pub comparable: bool,
    /// The first condition that made the pair incomparable, if any.
    pub refusal: Option<ComparabilityRefusal>,
    /// Empty whenever the pair is incomparable.
    pub findings: Vec<ClassifiedFinding>,
    pub coverage: CoverageComparison,
}

/// Where a completed comparison may be published. Both destinations are
/// existing, separately configured integrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishDestination {
    IssueTracker,
    DefectDojo,
}

impl PublishDestination {
    /// Stable identifier recorded in the guardrail decision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssueTracker => "issue-tracker",
            Self::DefectDojo => "defectdojo",
        }
    }
}

/// Request to publish a completed comparison outward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishComparisonRequest {
    pub base_run_id: Uuid,
    pub head_run_id: Uuid,
    pub regression_threshold_pct: f64,
    pub destination: PublishDestination,
}

/// What was published, and where.
#[derive(Debug, Clone, Serialize)]
pub struct PublishedComparison {
    pub destination: String,
    pub introduced: usize,
    pub coverage_regressed: bool,
    /// Browser URL of the created record, when the integration returns one.
    pub url: Option<String>,
}

impl ServiceContainer {
    /// Map a source change onto the project's discovered targets and emit an
    /// advisory change-aware campaign plan.
    ///
    /// # Errors
    /// Returns a classified error when persistent storage is unavailable,
    /// neither a diff nor a revision range was supplied, a revision argument is
    /// unsafe, git could not produce the diff, or the diff is not trustworthy.
    pub async fn change_impact(
        &self,
        req: ChangeImpactRequest,
    ) -> Result<ChangeImpactView, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("change comparison requires persistent storage".to_owned())
        })?;
        let diff_text = match (req.diff, req.revisions) {
            (Some(diff), _) => diff,
            (None, Some(range)) => git_diff(&req.project, &range)?,
            (None, None) => {
                return Err(ClassifiedError::Validation(
                    "a change requires either a unified diff or a revision range".to_owned(),
                ))
            }
        };
        let parsed = parse_unified_diff(&diff_text).map_err(|rejection| {
            ClassifiedError::Validation(format!(
                "the supplied diff was not trustworthy: {}",
                serde_json::to_value(rejection)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "rejected".to_owned())
            ))
        })?;

        let targets = store
            .list_targets(&req.project)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        let affected = map_affected_targets(&parsed, &targets);

        let runs = store
            .list_runs(Some(&req.project))
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        let mut plan = Vec::new();
        for entry in &affected {
            // Unknown targets are not planned: there is no evidence that the
            // change reaches them, and inventing work would misrepresent that.
            if entry.impact == TargetImpact::Unknown {
                continue;
            }
            plan.push(ChangeAwarePlanEntry {
                target_id: entry.target_id,
                symbol: entry.symbol.clone(),
                impact: entry.impact,
                reason_code: entry.reason_code.clone(),
                baseline_run_id: self
                    .latest_baseline_run(store, &runs, entry.target_id)
                    .await,
            });
        }

        Ok(ChangeImpactView {
            schema_version: CHANGE_AWARE_SCHEMA_VERSION,
            files: parsed.files,
            affected,
            plan,
        })
    }

    /// Compare two retained runs across a source change.
    ///
    /// An incomparable pair is a result, not an error: the view names the first
    /// failed condition and carries no findings or coverage verdict.
    ///
    /// # Errors
    /// Returns a classified error when persistent storage is unavailable or
    /// either run is missing.
    pub async fn compare_revisions(
        &self,
        req: RevisionComparisonRequest,
    ) -> Result<RevisionComparisonView, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("change comparison requires persistent storage".to_owned())
        })?;
        let base = self.load_run(store, req.base_run_id).await?;
        let head = self.load_run(store, req.head_run_id).await?;
        let base_input = self.comparison_input(store, &base).await?;
        let head_input = self.comparison_input(store, &head).await?;

        if let Err(refusal) = check_comparability(&base_input, &head_input) {
            return Ok(RevisionComparisonView {
                schema_version: CHANGE_AWARE_SCHEMA_VERSION,
                base_run_id: req.base_run_id,
                head_run_id: req.head_run_id,
                comparable: false,
                refusal: Some(refusal),
                findings: Vec::new(),
                coverage: CoverageComparison::Unavailable,
            });
        }

        let signatures = |crashes: Vec<hf_core::crash::Crash>| {
            let mut list: Vec<String> = crashes
                .into_iter()
                .map(|crash| crash.stack_signature)
                .collect();
            list.sort();
            list.dedup();
            list
        };
        let base_signatures = signatures(
            store
                .list_crashes_by_run(req.base_run_id)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?,
        );
        let head_signatures = signatures(
            store
                .list_crashes_by_run(req.head_run_id)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?,
        );

        Ok(RevisionComparisonView {
            schema_version: CHANGE_AWARE_SCHEMA_VERSION,
            base_run_id: req.base_run_id,
            head_run_id: req.head_run_id,
            comparable: true,
            refusal: None,
            findings: classify_findings(&base_signatures, &head_signatures),
            coverage: compare_coverage(
                base_input.edges,
                head_input.edges,
                req.regression_threshold_pct,
            ),
        })
    }

    /// Publish a completed comparison through an existing integration.
    ///
    /// The comparison must be comparable and must actually report something.
    /// Publication is outward-facing, so it is refused unless a guardrail
    /// authorizes it; the comparison itself never publishes.
    ///
    /// # Errors
    /// Returns a classified error when the pair is incomparable, there is
    /// nothing to report, the guardrail denies the action, or the destination
    /// integration is unconfigured or rejects the request.
    pub async fn publish_change_comparison(
        &self,
        req: PublishComparisonRequest,
    ) -> Result<PublishedComparison, ClassifiedError> {
        let comparison = self
            .compare_revisions(RevisionComparisonRequest {
                base_run_id: req.base_run_id,
                head_run_id: req.head_run_id,
                regression_threshold_pct: req.regression_threshold_pct,
            })
            .await?;
        if !comparison.comparable {
            return Err(ClassifiedError::Validation(format!(
                "the base and head runs are incomparable ({}), so there is no verdict to publish",
                refusal_code(comparison.refusal)
            )));
        }
        let introduced: Vec<&ClassifiedFinding> = comparison
            .findings
            .iter()
            .filter(|entry| entry.change == FindingChange::Introduced)
            .collect();
        let regressed = matches!(comparison.coverage, CoverageComparison::Regressed { .. });
        if introduced.is_empty() && !regressed {
            return Err(ClassifiedError::Validation(
                "the comparison reports no introduced finding and no coverage regression, so there is nothing to publish".to_owned(),
            ));
        }

        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("change comparison requires persistent storage".to_owned())
        })?;
        let head = self.load_run(store, req.head_run_id).await?;
        self.authorize_recorded(
            hf_guardrails::Action::PublishChangeComparison {
                destination: req.destination.as_str().to_owned(),
            },
            "publish_change_comparison",
            Some(std::path::Path::new(&head.project_root)),
        )
        .await
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;

        let signatures: Vec<&str> = introduced
            .iter()
            .map(|entry| entry.stack_signature.as_str())
            .collect();
        let url = match req.destination {
            PublishDestination::IssueTracker => {
                self.publish_to_issue_tracker(&comparison, &signatures)
                    .await?
            }
            PublishDestination::DefectDojo => {
                self.publish_to_defectdojo(store, req.head_run_id, &signatures)
                    .await?
            }
        };
        Ok(PublishedComparison {
            destination: req.destination.as_str().to_owned(),
            introduced: introduced.len(),
            coverage_regressed: regressed,
            url,
        })
    }

    /// File the comparison as one issue, reusing the established dedup marker so
    /// a re-published comparison does not open a duplicate.
    async fn publish_to_issue_tracker(
        &self,
        comparison: &RevisionComparisonView,
        signatures: &[&str],
    ) -> Result<Option<String>, ClassifiedError> {
        let cfg = crate::issue_tracker::load_config()?;
        let token = crate::issue_tracker::resolve_token(&cfg)?;
        let client = crate::issue_tracker::IssueTrackerClient::from_config(&cfg, &token)?;
        // Dedup on the first introduced signature, matching how a single crash
        // is deduped when filed on its own.
        if let Some(first) = signatures.first() {
            if let Some(existing) = client.find_existing_issue(first).await {
                return Ok(Some(existing.url));
            }
        }
        let title = format!(
            "oxfuzz: {} finding(s) introduced by the change under test",
            signatures.len()
        );
        let body = comparison_issue_body(comparison, signatures);
        let created = client.create_issue(&title, &body, &cfg.labels).await?;
        Ok(Some(created.url))
    }

    /// Import only the introduced findings, so a comparison never re-reports
    /// crashes the base revision already had.
    async fn publish_to_defectdojo(
        &self,
        store: &Store,
        head_run_id: Uuid,
        signatures: &[&str],
    ) -> Result<Option<String>, ClassifiedError> {
        let cfg = crate::defectdojo::load_config()?;
        let token = crate::defectdojo::resolve_token(&cfg)?;
        let crashes: Vec<hf_core::crash::Crash> = store
            .list_crashes_by_run(head_run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .into_iter()
            .filter(|crash| signatures.contains(&crash.stack_signature.as_str()))
            .collect();
        if crashes.is_empty() {
            return Err(ClassifiedError::Validation(
                "no retained crash matches the introduced findings".to_owned(),
            ));
        }
        let findings = crate::defectdojo::crashes_to_generic(&crashes);
        let client = crate::defectdojo::DefectDojoClient::from_config(&cfg, &token)?;
        let import = crate::defectdojo::ImportTarget {
            product_name: cfg
                .product_name
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "oxfuzz".to_owned()),
            product_type_name: cfg.resolved_product_type(),
            engagement_name: cfg
                .engagement_name
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "Fuzzing".to_owned()),
            test_title: Some("oxfuzz: change comparison".to_owned()),
            reimport: cfg.reimport,
            auto_create: cfg.auto_create,
            // This upload carries only the introduced findings, never the
            // target's complete set, so it must not close anything.
            close_old_findings: false,
        };
        client.import(&import, &findings).await?;
        Ok(None)
    }

    async fn load_run(&self, store: &Store, run_id: Uuid) -> Result<RunRecord, ClassifiedError> {
        store
            .get_run(run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run {run_id} was not found")))
    }

    /// Reduce a retained run to the facts a comparison may rest on.
    async fn comparison_input(
        &self,
        store: &Store,
        run: &RunRecord,
    ) -> Result<crate::change_impact::RunComparisonInput, ClassifiedError> {
        Ok(crate::change_impact::RunComparisonInput {
            target_id: self.run_target(store, run).await.unwrap_or_else(Uuid::nil),
            engine: run.engine.as_str().to_owned(),
            terminal: run.status == RunStatus::Done && run.kind == RunKind::Campaign,
            source_rev: run.source_rev.clone(),
            corpus_rev: run.corpus_rev.clone(),
            sandbox_rev: run.sandbox_rev.clone(),
            edges: run.edges,
        })
    }

    /// Resolve a run's target through its persisted harness.
    async fn run_target(&self, store: &Store, run: &RunRecord) -> Option<Uuid> {
        let config = run.config.as_ref()?;
        store
            .get_harness(config.harness_id)
            .await
            .ok()
            .flatten()
            .map(|harness| harness.target_id)
    }

    /// Latest terminal campaign run for this target, as an advisory baseline.
    async fn latest_baseline_run(
        &self,
        store: &Store,
        runs: &[RunRecord],
        target_id: Uuid,
    ) -> Option<Uuid> {
        let mut best: Option<&RunRecord> = None;
        for run in runs {
            if run.status != RunStatus::Done || run.kind != RunKind::Campaign {
                continue;
            }
            if self.run_target(store, run).await != Some(target_id) {
                continue;
            }
            if best.is_none_or(|current| run.started_at > current.started_at) {
                best = Some(run);
            }
        }
        best.map(|run| run.id)
    }
}

/// Produce a diff for a validated revision range through the read-only git
/// path. Revisions are validated before they reach the command line, and the
/// command is never composed through a shell.
fn git_diff(project: &str, range: &RevisionRange) -> Result<String, ClassifiedError> {
    validate_revision(&range.base)?;
    validate_revision(&range.head)?;
    let output = hf_runtime::scrubbed_command("git")
        .args([
            "-C",
            project,
            "diff",
            "--unified=0",
            "--no-color",
            &format!("{}...{}", range.base, range.head),
            "--",
        ])
        .output()
        .map_err(|error| ClassifiedError::Validation(format!("could not run git diff: {error}")))?;
    if !output.status.success() {
        return Err(ClassifiedError::Validation(
            "git could not diff the requested revision range".to_owned(),
        ));
    }
    if output.stdout.len() > MAX_DIFF_BYTES {
        return Err(ClassifiedError::Validation(
            "the revision range produced a diff above the reviewable size limit".to_owned(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| {
        ClassifiedError::Validation("git produced a diff that is not valid UTF-8".to_owned())
    })
}

/// Accept only conservative revision names. Anything that could be read as an
/// option, a range, or a second argument is refused before reaching git.
fn validate_revision(revision: &str) -> Result<(), ClassifiedError> {
    let refuse = |reason: &str| {
        Err(ClassifiedError::Validation(format!(
            "unsafe git revision argument: {reason}"
        )))
    };
    if revision.is_empty() || revision.len() > MAX_REVISION_LEN {
        return refuse("a revision must be non-empty and bounded");
    }
    if revision.starts_with('-') {
        return refuse("a revision must not start with a dash");
    }
    if revision.contains("..") {
        return refuse("a revision must name one commit, not a range");
    }
    if !revision
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
    {
        return refuse("a revision may contain only letters, digits, '.', '_', '/', and '-'");
    }
    Ok(())
}

/// Stable code for a refusal, for operator-facing messages.
fn refusal_code(refusal: Option<ComparabilityRefusal>) -> String {
    refusal
        .and_then(|value| serde_json::to_value(value).ok())
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Render the comparison as an issue body that a reader can reconstruct.
fn comparison_issue_body(comparison: &RevisionComparisonView, signatures: &[&str]) -> String {
    use std::fmt::Write as _;
    let mut body = String::new();
    let _ = writeln!(
        body,
        "oxfuzz compared two retained fuzzing runs across a source change.\n"
    );
    let _ = writeln!(body, "- base run: `{}`", comparison.base_run_id);
    let _ = writeln!(body, "- head run: `{}`", comparison.head_run_id);
    let _ = writeln!(
        body,
        "- coverage: {}",
        match comparison.coverage {
            CoverageComparison::Regressed { delta_pct } => format!("regressed by {delta_pct:.2}%"),
            CoverageComparison::Stable { delta_pct } => format!("stable ({delta_pct:.2}%)"),
            CoverageComparison::Unavailable => "unavailable".to_owned(),
        }
    );
    let _ = writeln!(body, "\n## Findings introduced by this change\n");
    for signature in signatures {
        let _ = writeln!(body, "- `{signature}`");
    }
    let _ = writeln!(
        body,
        "\nFindings are identified by retained stack signature. Findings the base\nrun already reproduced are excluded."
    );
    body
}
