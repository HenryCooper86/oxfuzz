import { createContext, useContext } from "react";

export interface RunStats {
  currentExecs: number | null;
  meanExecs: number | null;
  peakExecs: number | null;
  edges: number | null;
  rawCrashSignals: number | null;
}

export interface AutoRevert {
  reverted_to_run: string;
  from_rev: string;
  to_rev: string;
  previous_edges: number;
  regressed_edges: number;
  drop_pct: number;
  reverted: boolean;
}

export interface RunSummary {
  edges: number | null;
  crashes: number;
  execs: number | null;
  stagnation?: string | null;
  autoRevert?: AutoRevert | null;
}

export interface RunOutputValue {
  selectedRun?: import("../lib/transport").RunOwner | null;
  requestState?: "idle" | "pending" | "admitted";
  requestError?: string | null;
  healthState?: { loading: boolean; error: string | null; hasOlder: boolean };
  log: string[];
  stats: RunStats;
  summary: RunSummary | null;
  running: boolean;
  cancelling: boolean;
  lastTarget: string;
  lastEngine: string;
  healthEvents?: Array<{
    id: string;
    severity: "warning" | "error";
    condition: string;
    detail: string;
  }>;
  loadOlderHealthEvents?: () => Promise<void>;
  runFuzzer: (params: {
    project: string;
    target: string;
    engine: string;
    duration: number;
  }) => Promise<number>;
  runSyzkaller: (options: Record<string, unknown>) => Promise<number>;
  cancelRun: () => Promise<void>;
  clear: () => void;
}

export const EMPTY_RUN_STATS: RunStats = {
  currentExecs: null,
  meanExecs: null,
  peakExecs: null,
  edges: null,
  rawCrashSignals: null,
};
export const RunOutputContext = createContext<RunOutputValue | null>(null);

/** Access shared run output. Safe outside a provider. */
export function useRunOutput(): RunOutputValue {
  return (
    useContext(RunOutputContext) ?? {
      log: [],
      stats: EMPTY_RUN_STATS,
      summary: null,
      running: false,
      cancelling: false,
      lastTarget: "",
      lastEngine: "",
      healthEvents: [],
      loadOlderHealthEvents: async () => {},
      runFuzzer: async () => 0,
      runSyzkaller: async () => 0,
      cancelRun: async () => {},
      clear: () => {},
    }
  );
}
