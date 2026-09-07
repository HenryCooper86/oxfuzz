import type { RunOwner } from "../lib/transport";
import { count, parseOwner, parseSummary, rate, record, timestamp } from "./runOutputValidation";
import { EMPTY_RUN_STATS, type RunStats, type RunSummary } from "./runOutput";

export const RUN_CAP = 64;
export const OWNER_REQUEST_CAP = 8;
export const HEALTH_REQUEST_CAP = 8;
export const LOG_CAP = 600;
export const LOG_LINE_CAP = 4096;
export const HEALTH_CAP = 200;
export const V1_KEY = "hf_run_summary_v1";
export const V2_KEY = "hf_run_summary_v2";

export interface HealthItem {
  id: string;
  severity: "warning" | "error";
  condition: string;
  detail: string;
}
export interface RunData {
  owner: RunOwner | null;
  log: string[];
  stats: RunStats;
  summary: RunSummary | null;
  healthEvents: HealthItem[];
  nextCursor: string | null | undefined;
  healthLoading: boolean;
  healthError: string | null;
  lastTarget: string;
  lastEngine: string;
  status: string | null;
  observedAt: string | null;
}
export type PersistedRun = Pick<
  RunData,
  "owner" | "stats" | "summary" | "lastTarget" | "lastEngine" | "status" | "observedAt"
>;
export interface OutputState {
  runs: Record<string, RunData>;
  latest: Record<string, string>;
  legacy: Record<string, RunData>;
  foregroundId: string | null;
  requestState: "idle" | "pending" | "admitted";
  requestError: string | null;
  cancelling: boolean;
  keepLegacySource: boolean;
}
export function emptyRun(): RunData {
  return {
    owner: null,
    log: [],
    stats: { ...EMPTY_RUN_STATS },
    summary: null,
    healthEvents: [],
    nextCursor: undefined,
    healthLoading: false,
    healthError: null,
    lastTarget: "",
    lastEngine: "",
    status: null,
    observedAt: null,
  };
}
function parsePersisted(value: unknown, id?: string): RunData | null {
  if (!record(value) || !record(value.stats)) return null;
  const owner = id ? parseOwner(value.owner, id) : null;
  if (id && !owner) return null;
  const stats = value.stats;
  return {
    ...emptyRun(),
    owner,
    stats: {
      currentExecs: rate(stats.currentExecs),
      meanExecs: rate(stats.meanExecs),
      peakExecs: rate(stats.peakExecs),
      edges: count(stats.edges),
      rawCrashSignals: id ? count(stats.rawCrashSignals) : null,
    },
    summary: parseSummary(value.summary),
    lastTarget: owner
      ? (owner.target ?? "")
      : typeof value.lastTarget === "string"
        ? value.lastTarget
        : "",
    lastEngine: owner?.engine ?? (typeof value.lastEngine === "string" ? value.lastEngine : ""),
    status: owner?.status ?? null,
    observedAt: timestamp(value.observedAt) ? value.observedAt : null,
  };
}
function readJson(key: string, onFailure?: () => void): unknown {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    // Unavailable storage or malformed JSON cannot prevent independent v1 recovery.
    onFailure?.();
    return null;
  }
}
export function loadOutput(): OutputState {
  const state: OutputState = {
    runs: {},
    latest: {},
    legacy: {},
    foregroundId: null,
    requestState: "idle",
    requestError: null,
    cancelling: false,
    keepLegacySource: false,
  };
  const v2 = readJson(V2_KEY);
  if (
    record(v2) &&
    v2.schema_version === 2 &&
    record(v2.runs) &&
    record(v2.latest_run_by_project) &&
    record(v2.legacy_by_project)
  ) {
    for (const [id, value] of Object.entries(v2.runs).slice(-RUN_CAP)) {
      const run = parsePersisted(value, id);
      if (run) state.runs[id] = run;
    }
    for (const [project, id] of Object.entries(v2.latest_run_by_project)) {
      if (typeof id === "string" && state.runs[id]?.owner?.project_root === project)
        state.latest[project] = id;
    }
    for (const [project, value] of Object.entries(v2.legacy_by_project).slice(-RUN_CAP)) {
      const run = parsePersisted(value);
      if (run) state.legacy[project] = run;
    }
  }
  let legacyReadFailed = false;
  const v1 = readJson(V1_KEY, () => {
    legacyReadFailed = true;
  });
  if (record(v1))
    for (const [project, value] of Object.entries(v1).slice(-RUN_CAP)) {
      if (!record(value) || state.latest[project] || state.legacy[project]) continue;
      const stats = record(value.stats) ? value.stats : {};
      state.legacy[project] = {
        ...emptyRun(),
        stats: {
          ...EMPTY_RUN_STATS,
          peakExecs: rate(stats.execs),
          edges: count(stats.edges),
          rawCrashSignals: null,
        },
        summary: parseSummary(value.summary),
        lastTarget: typeof value.lastTarget === "string" ? value.lastTarget : "",
        lastEngine: typeof value.lastEngine === "string" ? value.lastEngine : "",
      };
    }
  state.legacy = Object.fromEntries(Object.entries(state.legacy).slice(0, RUN_CAP));
  state.keepLegacySource =
    legacyReadFailed ||
    (record(v1) &&
      Object.keys(v1).some((project) => !state.legacy[project] && !state.latest[project]));
  return state;
}
export function serializeOutput(state: OutputState): string {
  const strip = ({
    owner,
    stats,
    summary,
    lastTarget,
    lastEngine,
    status,
    observedAt,
  }: RunData): PersistedRun => ({
    owner,
    stats,
    summary,
    lastTarget,
    lastEngine,
    status,
    observedAt,
  });
  return JSON.stringify({
    schema_version: 2,
    runs: Object.fromEntries(
      Object.entries(state.runs)
        .filter(([, run]) => run.owner)
        .map(([id, run]) => [id, strip(run)]),
    ),
    latest_run_by_project: state.latest,
    legacy_by_project: Object.fromEntries(
      Object.entries(state.legacy).map(([project, run]) => [project, strip(run)]),
    ),
  });
}
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
