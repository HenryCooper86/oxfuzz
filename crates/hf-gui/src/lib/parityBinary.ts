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
}

export function binaryFuzz(options: BinaryFuzzOptions): Promise<BinaryFuzzOutcome> {
  return getTransport().invoke<BinaryFuzzOutcome>("binary_fuzz", { options });
}

export function binaryIssueExport(project: string, report: string, finding: string): Promise<IssueExport> {
  return getTransport().invoke<IssueExport>("binary_issue_export", { project, report, finding });
}

export function binaryFileIssue(project: string, report: string, finding: string): Promise<CreatedIssue> {
  return getTransport().invoke<CreatedIssue>("binary_file_issue", { project, report, finding });
}

/** The `report.json` of a session workspace. */
export function reportPath(workspace: string): string {
  return `${workspace.replace(/[\\/]+$/, "")}/report.json`;
}

/** A finding must be named by at least 8 hex digits of its input sha256. */
export function validFindingId(value: string): boolean {
  return /^[0-9a-fA-F]{8,64}$/.test(value.trim());
}
