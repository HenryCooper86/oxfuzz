// Typed shapes for the analysis commands the desktop shares with the command
// line. Field names mirror the service's serde output.

export type BisectVerdict = "good" | "bad" | "skip";
export interface BisectStep { commit: string; verdict: BisectVerdict; note: string }
export type BisectResult =
  | { kind: "first_bad"; commit: string; subject: string }
  | { kind: "undecided"; commits: string[] };
export interface BisectOutcome { good: string; bad: string; candidates: number; result: BisectResult; steps: BisectStep[] }

export interface RegressionResult { crash_id: string; input: string; still_crashes: boolean; verified: boolean; summary: string }

export interface CoverageSummary {
  lines_covered: number; lines_total: number; line_percent: number;
  functions_covered: number; functions_total: number; function_percent: number;
  regions_covered: number; regions_total: number; region_percent: number;
}
export interface LineReportOutcome { path: string | null; lines_hit: number; lines_total: number; files: number; skipped_files: number }

export type ConcolicAvailability = { state: "available" } | { state: "unavailable"; reason: string };
export type ConcolicOutcome = {
  inputs_explored: number; inputs_skipped: number; inputs_solved: number; inputs_novel: number;
  stop_reason: string; corpus_size_before: number; corpus_size_after: number;
};
export interface ReductionOutcome { before: number; after: number; before_bytes: number; after_bytes: number }
export interface SeedRegenerationOutcome {
  removed_dead: number; replacements_requested: number; replacements_added: number;
  replacement_survives: number; replacement_dies_at_entry: number; replacement_not_measured: number;
}

export type SurfaceMeasurement = { state: "unavailable"; reason: string } | { state: "retained"; measurements: number };
export interface UnreachedCandidate { symbol: string; discovery_score: number; attempt: { state: string; attempts?: number } }
export interface UnreachedSurfaceView { measurement: SurfaceMeasurement; candidates: UnreachedCandidate[] }
export type AttributionTier = { tier: "untouched" } | { tier: "partial" | "saturated"; covered: number; total: number };
export interface AttributionCandidate { symbol: string; discovery_score: number; tier: AttributionTier; covered_share: number }
export interface CoverageAttributionView { measurement: SurfaceMeasurement; candidates: AttributionCandidate[] }

export interface TrustGate { claim: string; verdict: "supported" | "refuted" | "unsupported" | "unavailable"; detail: string }
export interface CampaignTrustReport { run_id: string; gates: TrustGate[]; determination: "untrustworthy" | "unqualified" | "qualified" | "trusted"; unlicensed_claims: string[] }

export interface RunEdgeSetCapture { run_id: string; binary_sha256: string; inputs: number; edges: number; collected_at: string; already_retained: boolean }
export interface CoverageDiffReport {
  run_a: string; run_b: string; same_binary: boolean; edges_a: number; edges_b: number;
  only_a: number; only_b: number; common: number; union: number;
  only_a_sample: number[]; only_b_sample: number[]; sample_cap: number;
}

export type AiPolicy = "auto" | "require" | "off";

export function shortCommit(commit: string): string {
  return commit.slice(0, 12);
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function percentText(value: number): string {
  return `${Number.isFinite(value) ? value.toFixed(1) : "0.0"}%`;
}

/** A concolic availability answer, tolerant of an unexpected payload. */
export function concolicUnavailableReason(value: unknown): string | null {
  if (!isObject(value) || value.state === "available") return null;
  return typeof value.reason === "string" ? value.reason : "unknown";
}
