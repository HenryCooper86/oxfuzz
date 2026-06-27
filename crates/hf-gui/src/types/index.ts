// Shared types for hobot_fuzz GUI.

export type ViewType =
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
  | "agents"
  | "skills"
  | "knowledge"
  | "automation";

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
}

/** Engine identifiers used across the Run view and status bar. */
export type EngineId = "libfuzzer" | "afl++" | "honggfuzz" | "clusterfuzzlite" | "syzkaller";