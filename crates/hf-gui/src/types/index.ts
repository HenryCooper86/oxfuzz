// Shared types for oxfuzz GUI.

export type ViewType =
  | "dashboard"
  | "workflow"
  | "discover"
  | "harness"
  | "run"
  | "triage"
  | "corpus"
  | "settings"
  | "chat"
  | "projects"
  | "artifacts"
  | "reports"
  | "runs"
  | "changes"
  | "audit"
  | "agents"
  | "skills"
  | "knowledge"
  | "automation"
  | "automotive"
  | "defectdojo"
  | "help";

export interface CoverageSample {
  t: number;
  edges: number;
  execs: number;
}

export interface RunHistoryItem {
  id: string;
  project_root: string;
  target: string | null;
  /** Service-owned key for runs with comparable coverage conditions. */
  comparison_key: string | null;
  engine: string;
  status: string;
  started_at: string;
  ended_at: string | null;
  duration_secs: number | null;
  crashes: number;
  edges: number | null;
  execs: number | null;
  harness_rev: string | null;
  binary_rev: string | null;
  evidence_dir: string | null;
}

export interface TargetCandidate {
  id: string;
  project_root: string;
  language: string;
  symbol: string;
  kind: string;
  location: { file: string; line: number; col: number };
  signature: string | null;
  input_surface: string;
  complexity: number;
  fit_score: number;
  sanitizers: string[];
  rationale: string;
  reachable_functions?: string[];
  accumulated_complexity?: number;
}

export interface TargetInventory {
  project_root: string;
  candidates: TargetCandidate[];
  /** Project-only call adjacency (caller -> direct project callees). */
  call_graph?: Record<string, string[]>;
}

export type SemgrepOperationState =
  | "staging"
  | "scanning"
  | "validating"
  | "persisting"
  | "done"
  | "failed"
  | "cancelled";

export type SemgrepOverlayState =
  | "none"
  | "current"
  | "stale_source"
  | "stale_base"
  | "incomplete_journal";

export type SemgrepCancelOutcome = "accepted" | "inactive" | "not_found";

export interface SemgrepOperationView {
  operation_id: string;
  project_root: string;
  language: "c" | "cpp";
  state: SemgrepOperationState;
  active: boolean;
  started_at: string;
  ended_at: string | null;
  failure_code: string | null;
  failure_message: string | null;
  result: SemgrepInventory | null;
}

export interface SemgrepTargetCandidate extends TargetCandidate {
  base_score: number;
  semgrep_boost: number;
  effective_score: number;
  semgrep_matched_rule_count: number;
}

export interface SemgrepFinding {
  fingerprint: string;
  rule_id: string;
  severity: "error" | "warning" | "info";
  message: string;
  relative_file: string;
  start_line: number;
  start_col: number;
  end_line: number;
  end_col: number;
  matched_target_id: string | null;
  nominal_weight: number;
}

export interface SemgrepInventory {
  project_root: string;
  language: "c" | "cpp";
  scan_id: string | null;
  source_sha256: string | null;
  overlay_state: SemgrepOverlayState;
  candidates: SemgrepTargetCandidate[];
  findings: SemgrepFinding[];
  call_graph: Record<string, string[]>;
}

export interface CorpusEntry {
  path: string;
  sha256: string;
  size: number;
  source: string;
  coverage_hash: string | null;
}

export type CrashSeverity = "Exploitable" | "ProbablyExploitable" | "NotExploitable" | "Undefined";

/** CASR crash-analysis report attached to a triaged crash. */
export interface CasrReport {
  severity: CrashSeverity;
  severity_short: string;
  crashline: string;
  stack: string[];
  cluster: number | null;
}

export interface Crash {
  id: string;
  run_id: string;
  target_id: string;
  input_path: string;
  stack_signature: string;
  kind: string;
  summary: string;
  minimized: boolean;
  bug_report: { title: string; summary: string; repro_steps: string; stack: string; severity_guess: string } | null;
  casr: CasrReport | null;
}

/** On-demand LLM verdict for a triaged crash (matches hf-service CrashVerdict). */
export interface CrashVerdict {
  reproduces_deterministically: boolean;
  likely_target_bug: boolean;
  confidence: "low" | "medium" | "high";
  reasons: string[];
}

export interface FuzzProgress {
  type: string;
  data: unknown;
}

export interface SystemStatus {
  docker: boolean;
  sandbox_image: boolean;
  libfuzzer: boolean;
  aflplusplus: boolean;
  honggfuzz: boolean;
  syzkaller: boolean;
  /** The configured DefectDojo is answering (false also when unconfigured). */
  defectdojo: boolean;
}

/** Lifecycle state of the DefectDojo instance the app is pointed at. */
export type DefectDojoState =
  | "not_configured"
  | "remote"
  | "docker_down"
  | "not_installed"
  | "stopped"
  | "starting"
  | "ready";

export interface DefectDojoStatus {
  state: DefectDojoState;
  url: string | null;
  /** Human-readable explanation of `state`, safe to render as-is. */
  message: string;
  /** True when oxfuzz can start/stop this instance itself. */
  managed: boolean;
}

/** Engine identifiers used across the Run view and status bar. */
export type EngineId = "libfuzzer" | "afl++" | "honggfuzz" | "syzkaller";

export interface WorkbenchTotals {
  projects: number;
  targets: number;
  harnesses: number;
  harnesses_needing_review: number;
  runs: number;
  active_runs: number;
  crashes: number;
  /** Crashes with no drafted bug report yet -- what "triage required" keys on. */
  crashes_needing_triage: number;
  corpus_entries: number;
}

export interface WorkbenchRun {
  id: string;
  project_root: string;
  engine: string;
  status: string;
  started_at: string;
  ended_at: string | null;
  crash_count: number;
}

export interface WorkbenchTarget {
  id: string;
  project_root: string;
  symbol: string;
  language: string;
  fit_score: number;
  rationale: string;
}

export interface HarnessReviewItem {
  harness_id: string;
  target_id: string;
  project_root: string;
  target_symbol: string;
  engine: string;
  language: string;
  status: string;
  build_output: string;
  smoke_passed: boolean;
  smoke_execs_per_sec: number;
  needs_review: boolean;
  next_action: string;
  source_preview: string;
}

export type FindingProofStatus = "supported" | "not_verified" | "unavailable";
export type FindingEvidenceKind =
  | "crash_record"
  | "run_record"
  | "casr_report"
  | "remediation_record";
export type FaultOriginDetermination = "target" | "harness" | "runtime" | "unknown";
export type ReproductionDetermination = "deterministic" | "not_verified";
export type CasrExploitabilityDetermination =
  | "exploitable"
  | "probably_exploitable"
  | "not_exploitable"
  | "undefined"
  | "unavailable";
export type ReachabilityDetermination = "demonstrated" | "not_verified";
export type FixVerificationDetermination =
  | "verified"
  | "rejected"
  | "inconclusive"
  | "not_verified";

export interface FindingEvidenceReference {
  kind: FindingEvidenceKind;
  record_id: string;
}

export interface FindingProofClaim<T extends string> {
  determination: T;
  status: FindingProofStatus;
  detail_code: string;
  detail: string;
  evidence: FindingEvidenceReference[];
}

export interface FindingProofCard {
  schema_version: number;
  fault_origin: FindingProofClaim<FaultOriginDetermination>;
  deterministic_reproduction: FindingProofClaim<ReproductionDetermination>;
  casr_exploitability: FindingProofClaim<CasrExploitabilityDetermination>;
  external_reachability: FindingProofClaim<ReachabilityDetermination>;
  fix_verification: FindingProofClaim<FixVerificationDetermination>;
}

/// Durable Patch-to-Proof workflow state, owned by hf-service. The presentation
/// layer renders these values; it never derives them from stage results.
export type RemediationOperationStatus =
  | "draft"
  | "approved"
  | "running"
  | "verified"
  | "rejected"
  | "inconclusive";

export type RemediationOperationStage =
  | "review"
  | "original_replay"
  | "patch_build"
  | "patched_replay"
  | "regression"
  | "follow_up"
  | "complete";

export type VerificationStageStatus = "passed" | "failed" | "inconclusive" | "skipped";

export interface VerificationStageEvidence {
  status: VerificationStageStatus;
  detail_code: string;
  cases: number;
  failures: number;
  findings: number;
}

export interface SandboxVerificationEvidence {
  verification_id: string;
  source_revision_sha256: string;
  patch_sha256: string;
  reproducer_sha256: string;
  harness_sha256: string;
  original_binary_sha256: string;
  patched_binary_sha256: string | null;
  sandbox_image_sha256: string;
  regression_corpus_sha256: string;
  verification_spec_sha256: string;
  original_replay: VerificationStageEvidence;
  patch_build: VerificationStageEvidence;
  patched_replay: VerificationStageEvidence;
  regression: VerificationStageEvidence;
  follow_up_fuzz: VerificationStageEvidence;
}

export interface RemediationVerificationSpec {
  schema_version: number;
  engine: string;
  replay_timeout_secs: number;
  max_regression_cases: number;
  follow_up_fuzz_seconds: number;
  max_mem_mb: number;
  max_cpus: number;
  seed: number;
}

/// The exact scope an operator approves before any sandbox execution.
export interface RemediationBinding {
  finding_id: string;
  run_id: string;
  source_revision_sha256: string;
  patch_sha256: string;
  patch: string;
  reproducer_sha256: string;
  harness_sha256: string;
  original_binary_sha256: string;
  sandbox_image_sha256: string;
  evidence_manifest_sha256: string;
  regression_corpus_sha256: string;
  verification_spec_sha256: string;
  verification_spec: RemediationVerificationSpec;
}

export interface RemediationOperationView {
  operation_id: string;
  run_id: string;
  finding_id: string;
  status: RemediationOperationStatus;
  current_stage: RemediationOperationStage;
  binding: RemediationBinding;
  verification: SandboxVerificationEvidence | null;
  failure_code: string | null;
  failure_message: string | null;
}

export interface RemediationDraftView {
  operation_id: string;
  status: RemediationOperationStatus;
}

/// Change-Aware Pull-Request Fuzzing, owned by hf-service. The presentation
/// layer renders these determinations; it never recomputes one.
///
/// There is deliberately no "unaffected" impact: the retained reachable set is
/// bounded and syntactic, so absence from it is missing analysis, not proof.
export type TargetImpact = "changed" | "reaches_change" | "unknown";

export type FindingChange = "introduced" | "carried_over" | "resolved" | "unknown";

export type ComparabilityRefusal =
  | "base_not_terminal"
  | "head_not_terminal"
  | "missing_revision"
  | "sandbox_not_exact"
  | "different_target"
  | "different_engine"
  | "different_corpus"
  | "different_sandbox"
  | "same_source_revision";

export interface LineRange {
  start: number;
  end: number;
}

export interface ChangedFile {
  old_path: string | null;
  new_path: string | null;
  ranges: LineRange[];
  binary: boolean;
}

export interface AffectedTarget {
  target_id: string;
  symbol: string;
  impact: TargetImpact;
  reason_code: string;
  approximate: boolean;
}

export interface ChangeAwarePlanEntry {
  target_id: string;
  symbol: string;
  impact: TargetImpact;
  reason_code: string;
  baseline_run_id: string | null;
}

export interface ChangeImpactView {
  schema_version: number;
  files: ChangedFile[];
  affected: AffectedTarget[];
  plan: ChangeAwarePlanEntry[];
}

export interface ClassifiedFinding {
  stack_signature: string;
  change: FindingChange;
}

export type CoverageComparison =
  | { status: "unavailable" }
  | { status: "stable"; delta_pct: number }
  | { status: "regressed"; delta_pct: number };

export interface RevisionComparisonView {
  schema_version: number;
  base_run_id: string;
  head_run_id: string;
  comparable: boolean;
  refusal: ComparabilityRefusal | null;
  findings: ClassifiedFinding[];
  coverage: CoverageComparison;
}

export interface PublishedComparison {
  destination: string;
  introduced: number;
  coverage_regressed: boolean;
  url: string | null;
}

/// Build Doctor diagnosis, owned by hf-service. The presentation layer renders
/// these determinations; it never decides that a build system is supported.
export type BuildSystem =
  | "cmake"
  | "meson"
  | "autotools"
  | "make"
  | "bazel"
  | "cargo"
  | "unknown";

export type BuildSystemStatus =
  | "ready"
  | "supported"
  | "unsupported_in_image"
  | "not_needed"
  | "unknown";

export interface BuildPlanStep {
  argv: string[];
  working_dir: string;
  purpose: string;
}

export interface BuildPlan {
  steps: BuildPlanStep[];
  expected_artifact: string;
}

export interface BuildSystemDiagnosis {
  build_system: BuildSystem;
  status: BuildSystemStatus;
  markers: string[];
  missing_tool: string | null;
  plan: BuildPlan | null;
}

export type BuildPlanRunStatus = "succeeded" | "step_failed" | "artifact_missing";

export interface FailedBuildStep {
  index: number;
  exit_code: number;
  output: string;
}

export interface BuildPlanRunOutcome {
  status: BuildPlanRunStatus;
  build_system: BuildSystem;
  steps_run: number;
  failed_step: FailedBuildStep | null;
  build_context: unknown | null;
}

/// Harness Tournament, owned by hf-service. The presentation layer renders the
/// service ranking; it never recomputes one, and a tournament never promotes.
export type CandidateOrigin = "heuristic" | "llm";

export type VerdictLevel = "Pass" | "Suspect" | "Fail";

export interface SmokeEvidence {
  verdict: VerdictLevel;
  execs_per_sec: number;
  crashes: number;
}

export interface HarnessCandidateEvidence {
  index: number;
  origin: CandidateOrigin;
  source_sha256: string;
  compiled: boolean;
  repairs_used: number;
  compile_error: string | null;
  smoke: SmokeEvidence | null;
}

export interface HarnessTournamentResult {
  schema_version: number;
  candidates: HarnessCandidateEvidence[];
  /** Candidate indices, best first. */
  ranking: number[];
  winner_index: number | null;
  /** Always false: promotion stays an explicit human step. */
  promoted: boolean;
}

/// Coverage Blocker Explorer, owned by hf-service. The presentation layer
/// renders the service ranking and proposal; it derives neither, and it starts
/// nothing.
export type MeasurementStatus =
  | { status: "available"; signature: string }
  | { status: "unavailable"; reason_code: string };

export type NextExperimentKind = "grow_corpus" | "refine_harness" | "no_experiment_available";

export interface CoverageBlocker {
  function: string;
  location: string | null;
  /** Still-uncovered functions transitively reachable from here. */
  unlocked_uncovered: number;
  /** null means no observed route at all, not "nearby". */
  frontier_distance: number | null;
  nearest_covered: string | null;
  path: string[];
}

export interface NextExperiment {
  kind: NextExperimentKind;
  target_function: string | null;
  reason_code: string;
}

export interface CoverageBlockerView {
  schema_version: number;
  measurement: MeasurementStatus;
  /** Empty whenever no measurement backs the view. */
  blockers: CoverageBlocker[];
  experiment: NextExperiment;
}

export interface CrashReviewItem {
  crash_id: string;
  run_id: string;
  target_id: string;
  target_symbol: string;
  kind: string;
  summary: string;
  severity: string;
  minimized: boolean;
  has_bug_report: boolean;
  proof: FindingProofCard;
}

/** A localizable readiness/next-action note: a stable code plus a count. */
export interface ReadinessNote {
  code: string;
  count: number;
}

export interface WorkbenchReadiness {
  state: string;
  score: number;
  headline: string;
  detail: string;
  blockers: string[];
  /** Localizable form of `blockers`, parallel to it (same order and length). */
  blocker_items: ReadinessNote[];
}

export interface WorkbenchDashboard {
  active_project: string | null;
  active_target: string | null;
  totals: WorkbenchTotals;
  recent_runs: WorkbenchRun[];
  top_targets: WorkbenchTarget[];
  harness_reviews: HarnessReviewItem[];
  crash_reviews: CrashReviewItem[];
  readiness: WorkbenchReadiness;
  next_actions: string[];
  /** Localizable form of `next_actions`, parallel to it (same order/length). */
  next_action_items: ReadinessNote[];
}

export interface IssueExport {
  crash_id: string;
  title: string;
  description: string;
  labels: string[];
  /** "github" | "gitlab" -- which forge the URLs/API target. */
  provider: string;
  project_web_url: string | null;
  issue_url: string | null;
  /** True when the issue can be filed directly via the API (repo + token). */
  can_file: boolean;
}

/** The issue created by filing via the provider API. */
export interface CreatedIssue {
  url: string;
  number: number | null;
}

export interface ReportDraft {
  id: string;
  title: string;
  project: string;
  target: string | null;
  status: string;
  updated_at: string;
  content: string;
}
