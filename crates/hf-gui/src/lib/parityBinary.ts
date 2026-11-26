import { getTransport } from "./index";
import type { CreatedIssue, IssueExport } from "../types";

/** How the target takes its input (`oxfuzz binary` flags: none, --stdin, --socket, --messages). */
export type BinaryInputMode = "file" | "stdin" | "socket" | "socket_messages";

export const BINARY_INPUT_MODES: BinaryInputMode[] = ["file", "stdin", "socket", "socket_messages"];

/** The CLI default for `--timeout-ms`. */
export const DEFAULT_BINARY_TIMEOUT_MS = 1000;
/** The CLI default for `--duration` (60s). */
export const DEFAULT_BINARY_DURATION_SECS = 60;

export interface BinaryFuzzOptions {
  project: string;
  binary: string;
  input: BinaryInputMode;
  seeds?: string;
  libraries?: string;
  durationSecs: number;
  timeoutMs: number;
  /** AFL dictionary tokens in escaped form; empty for none. */
  dictionary?: string[];
  /** An earlier session of the same binary whose queue seeds this one. */
  continueFrom?: string;
  /** Split multi-byte comparisons in the emulator (AFL_COMPCOV_LEVEL=2). */
  compcov?: boolean;
}

export interface MinimizedInput {
  input: string;
  sha256: string;
  size: number;
}

export interface BinaryFinding {
  input: string;
  sha256: string;
  size: number;
  fuzzer_signal: number | null;
  replay_signal: number | null;
  replayed: boolean;
  confirmed: boolean;
  kind: string | null;
  signature: string;
  summary: string;
  frames: string[];
  duplicate_of: string | null;
  minimized: MinimizedInput | null;
}

export interface BinaryFuzzOutcome {
  session: string;
  workspace: string;
  binary_name: string;
  binary_sha256: string;
  machine: "aarch64" | "x86_64";
  input: BinaryInputMode;
  duration_secs: number;
  execs_done: number | null;
  execs_per_sec: number | null;
  edges_found: number | null;
  corpus_count: number | null;
  saved_hangs: number | null;
  findings: BinaryFinding[];
  distinct_findings: number;
  findings_omitted: number;
  started_at?: string | null;
  finished_at?: string | null;
  continued_from?: string | null;
  dictionary_tokens?: number;
  compcov?: boolean;
  stopped?: boolean;
}

export interface BinaryProfile {
  machine: "aarch64" | "x86_64";
  size: number;
  sha256: string;
  linking: "dynamic" | "static";
  imports: string[];
  suggested_input: BinaryInputMode;
  suggestion_reasons: string[];
  strings: string[];
  dictionary: string[];
  notes: string[];
}

export interface SeedPreview {
  name: string;
  size: number;
  sha256: string;
  preview: string;
}

export interface BinarySeedDraft {
  draft: string;
  directory: string;
  seeds: SeedPreview[];
}

export type BinaryStage = "preparing" | "fuzzing" | "replaying" | "minimizing";

export const BINARY_STAGES: BinaryStage[] = ["preparing", "fuzzing", "replaying", "minimizing"];

export interface BinaryProgress {
  session: string;
  binary_name: string;
  stage: BinaryStage;
  started_at: string;
  duration_secs: number;
  elapsed_secs: number;
  execs_done: number | null;
  execs_per_sec: number | null;
  edges_found: number | null;
  corpus_count: number | null;
  saved_crashes: number | null;
  saved_hangs: number | null;
  stopping: boolean;
}

export interface BinarySessionSummary {
  session: string;
  workspace: string;
  binary_name: string;
  binary_sha256: string;
  machine: "aarch64" | "x86_64";
  input: BinaryInputMode;
  duration_secs: number;
  started_at: string | null;
  finished_at: string | null;
  execs_done: number | null;
  findings: number;
  distinct_findings: number;
  confirmed: number;
  minimized: number;
  continued_from: string | null;
  can_continue: boolean;
}

export interface BinaryExplanation {
  session: string;
  finding_sha256: string;
  text: string;
  created_at: string;
}

export function binaryFuzz(options: BinaryFuzzOptions): Promise<BinaryFuzzOutcome> {
  return getTransport().invoke<BinaryFuzzOutcome>("binary_fuzz", { options });
}

export function binaryInspect(binary: string): Promise<BinaryProfile> {
  return getTransport().invoke<BinaryProfile>("binary_inspect", { binary });
}

export function binarySeedDrafts(
  project: string, binary: string, input: BinaryInputMode, description: string | null, count: number,
): Promise<BinarySeedDraft> {
  return getTransport().invoke<BinarySeedDraft>("binary_seed_drafts", { project, binary, input, description, count });
}

export function binaryDictionaryRefine(
  project: string, binary: string, input: BinaryInputMode, tokens: string[],
): Promise<string[]> {
  return getTransport().invoke<string[]>("binary_dictionary_refine", { project, binary, input, tokens });
}

export function binaryProgress(project: string): Promise<BinaryProgress | null> {
  return getTransport().invoke<BinaryProgress | null>("binary_progress", { project });
}

export function binaryStop(project: string, session: string): Promise<boolean> {
  return getTransport().invoke<boolean>("binary_stop", { project, session });
}

export function binarySessions(project: string): Promise<BinarySessionSummary[]> {
  return getTransport().invoke<BinarySessionSummary[]>("binary_sessions", { project });
}

export function binarySession(project: string, session: string): Promise<BinaryFuzzOutcome> {
  return getTransport().invoke<BinaryFuzzOutcome>("binary_session", { project, session });
}

export function binaryFindingExplanation(
  project: string, session: string, finding: string,
): Promise<BinaryExplanation | null> {
  return getTransport().invoke<BinaryExplanation | null>("binary_finding_explanation", { project, session, finding });
}

export function binaryFindingExplain(project: string, session: string, finding: string): Promise<BinaryExplanation> {
  return getTransport().invoke<BinaryExplanation>("binary_finding_explain", { project, session, finding });
}

/** The session directory's binary, which a continued session fuzzes again. */
export function sessionBinary(workspace: string): string {
  return `${workspace.replace(/[\\/]+$/, "")}/target`;
}

export function binaryIssueExport(project: string, report: string, finding: string): Promise<IssueExport> {
  return getTransport().invoke<IssueExport>("binary_issue_export", { project, report, finding });
}

export function binaryFileIssue(project: string, report: string, finding: string): Promise<CreatedIssue> {
  return getTransport().invoke<CreatedIssue>("binary_file_issue", { project, report, finding });
}

/** A counter for display: grouped digits, or "-" when unknown. */
export function formatCount(value: number | null | undefined): string {
  return value === null || value === undefined ? "-" : value.toLocaleString();
}

/** The `report.json` of a session workspace. */
export function reportPath(workspace: string): string {
  return `${workspace.replace(/[\\/]+$/, "")}/report.json`;
}

/** A finding must be named by at least 8 hex digits of its input sha256. */
export function validFindingId(value: string): boolean {
  return /^[0-9a-fA-F]{8,64}$/.test(value.trim());
}
