// Shared types for hobot_fuzz GUI.

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
  | "audit"
  | "agents"
  | "skills"
  | "knowledge"
  | "automation"
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
  clusterfuzzlite: boolean;
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
  /** True when hobot_fuzz can start/stop this instance itself. */
  managed: boolean;
}

/** Engine identifiers used across the Run view and status bar. */
export type EngineId = "libfuzzer" | "afl++" | "honggfuzz" | "clusterfuzzlite" | "syzkaller";

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
}

export interface WorkbenchReadiness {
  state: string;
  score: number;
  headline: string;
  detail: string;
  blockers: string[];
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
