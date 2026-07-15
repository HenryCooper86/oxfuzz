import { createContext, useContext } from "react";

export interface RunStats {
  execs: number;
  edges: number;
  crashes: number;
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
  edges: number;
  crashes: number;
  execs: number;
  stagnation?: string | null;
  autoRevert?: AutoRevert | null;
}

export interface RunOutputValue {
  log: string[];
  stats: RunStats;
  summary: RunSummary | null;
  running: boolean;
  cancelling: boolean;
  lastTarget: string;
  lastEngine: string;
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

export const EMPTY_RUN_STATS: RunStats = { execs: 0, edges: 0, crashes: 0 };
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
      runFuzzer: async () => 0,
      runSyzkaller: async () => 0,
      cancelRun: async () => {},
      clear: () => {},
    }
  );
}
