import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { getTransport } from "../lib";
import { useProject } from "./ProjectContext";
import { pruneToKeys } from "../lib/projectState";

// Owns the output of a fuzz run -- the live log, rolling stats, final summary --
// and the `run:progress` listener. Persistent output is kept per fuzzing target
// (project path) so switching targets retains each one's last run; the live
// `running` flag is global since only one run happens at a time. Because this
// lives at the app root (always mounted), a run keeps streaming even when the
// user navigates away from the Run view.

interface Stats {
  execs: number;
  edges: number;
  crashes: number;
}
/** The auto-revert policy outcome, present when a run's harness revision
 *  regressed coverage past the threshold and the previous revision was
 *  automatically restored. */
export interface AutoRevert {
  reverted_to_run: string;
  from_rev: string;
  to_rev: string;
  previous_edges: number;
  regressed_edges: number;
  drop_pct: number;
}
interface Summary {
  edges: number;
  crashes: number;
  execs: number;
  /** Coverage-stagnation proposal from the backend (e.g. "new_harness"), or
   *  null when coverage kept progressing. Drives the Run view's iterate hint. */
  stagnation?: string | null;
  /** Set when the auto-revert policy fired this run; null otherwise. */
  autoRevert?: AutoRevert | null;
}
type RunResult = {
  edges: number;
  crashes: number;
  execs: number;
  exit_code: number | null;
  stagnation?: string | null;
  auto_revert?: AutoRevert | null;
};

interface RunData {
  log: string[];
  stats: Stats;
  summary: Summary | null;
  lastTarget: string;
  lastEngine: string;
}

interface RunOutputValue {
  log: string[];
  stats: Stats;
  summary: Summary | null;
  running: boolean;
  /** True between a cancel request and the run actually stopping. */
  cancelling: boolean;
  /** Target + engine of the most recent run, for the Run -> Triage handoff. */
  lastTarget: string;
  lastEngine: string;
  /** Run a libFuzzer/AFL++/honggfuzz/CFL campaign; resolves to the crash count. */
  runFuzzer: (p: {
    project: string;
    target: string;
    engine: string;
    duration: number;
    arch: string;
  }) => Promise<number>;
  /** Run a syzkaller campaign; resolves to the crash count. */
  runSyzkaller: (opts: Record<string, unknown>) => Promise<number>;
  /** Cancel the in-flight fuzz run (cooperative; the run stops shortly after). */
  cancelRun: () => Promise<void>;
  clear: () => void;
}

const RunOutputContext = createContext<RunOutputValue | null>(null);

const ZERO: Stats = { execs: 0, edges: 0, crashes: 0 };
const EMPTY: RunData = { log: [], stats: ZERO, summary: null, lastTarget: "", lastEngine: "" };
const LOG_CAP = 600;

// Per-target run summary/stats are persisted across restarts; the live log is
// not (large and ephemeral -- the crashes and corpus live on disk/DB).
const STORAGE_KEY = "hf_run_summary_v1";
type PersistedRun = Pick<RunData, "stats" | "summary" | "lastTarget" | "lastEngine">;

/** Load persisted per-target run summaries (best-effort); log starts empty. */
function loadSummaries(): Record<string, RunData> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    if (!parsed || typeof parsed !== "object") return {};
    const out: Record<string, RunData> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, PersistedRun>)) {
      out[k] = {
        log: [],
        stats: v.stats ?? ZERO,
        summary: v.summary ?? null,
        lastTarget: v.lastTarget ?? "",
        lastEngine: v.lastEngine ?? "",
      };
    }
    return out;
  } catch {
    return {};
  }
}

export function RunOutputProvider({ children }: { children: React.ReactNode }) {
  const { activeProject, recentProjects } = useProject();
  const key = activeProject || "__none__";
  // The always-mounted progress listener writes to whichever target is active.
  const keyRef = useRef(key);
  useEffect(() => {
    keyRef.current = key;
  }, [key]);
  // The project bucket a run is writing to, captured at run start. While a run
  // is in flight, progress/log/summary all target this key -- so switching the
  // active project mid-run does not split a run's output across two buckets.
  const activeRunKeyRef = useRef<string | null>(null);

  const [byProject, setByProject] = useState<Record<string, RunData>>(loadSummaries);
  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const cur = byProject[key] ?? EMPTY;

  // Persist the summary/stats subset (never the log), pruned to projects still
  // in the recents list so a removed project's run output does not linger.
  const lastWriteRef = useRef("");
  useEffect(() => {
    try {
      const persisted: Record<string, PersistedRun> = {};
      for (const [k, d] of Object.entries(pruneToKeys(byProject, recentProjects))) {
        persisted[k] = {
          stats: d.stats,
          summary: d.summary,
          lastTarget: d.lastTarget,
          lastEngine: d.lastEngine,
        };
      }
      const serialized = JSON.stringify(persisted);
      if (serialized !== lastWriteRef.current) {
        lastWriteRef.current = serialized;
        localStorage.setItem(STORAGE_KEY, serialized);
      }
    } catch {
      // Best-effort: localStorage may be unavailable or full.
    }
  }, [byProject, recentProjects]);

  const patch = useCallback((k: string, fn: (d: RunData) => RunData) => {
    setByProject((prev) => ({ ...prev, [k]: fn(prev[k] ?? EMPTY) }));
  }, []);

  const appendLog = useCallback(
    (line: string) => {
      patch(activeRunKeyRef.current ?? keyRef.current, (d) => ({
        ...d,
        log: d.log.length >= LOG_CAP ? [...d.log.slice(-(LOG_CAP - 1)), line] : [...d.log, line],
      }));
    },
    [patch],
  );

  // Always-on progress listener: stats update in place, raw fuzzer lines fill
  // the active target's log. Mounted once for the app's lifetime.
  useEffect(() => {
    let alive = true;
    let unlisten: (() => void) | undefined;
    getTransport()
      .listen<{ type: string; data: unknown }>("run:progress", (ev) => {
        const p = ev.payload;
        const k = activeRunKeyRef.current ?? keyRef.current;
        if (p?.type === "ExecsPerSec") {
          const v = Number(p.data) || 0;
          patch(k, (d) => ({ ...d, stats: { ...d.stats, execs: Math.max(d.stats.execs, v) } }));
        } else if (p?.type === "EdgesCovered") {
          const v = Number(p.data) || 0;
          patch(k, (d) => ({ ...d, stats: { ...d.stats, edges: Math.max(d.stats.edges, v) } }));
        } else if (p?.type === "CrashesFound") {
          patch(k, (d) => ({ ...d, stats: { ...d.stats, crashes: d.stats.crashes + 1 } }));
          appendLog("  [!] CRASH DETECTED");
        } else if (p?.type === "LogLine") {
          appendLog(`  ${p.data}`);
        }
      })
      .then((u) => {
        if (alive) unlisten = u;
        else u();
      });
    return () => {
      alive = false;
      if (unlisten) unlisten();
    };
  }, [appendLog, patch]);

  const clear = useCallback(() => {
    patch(keyRef.current, () => EMPTY);
  }, [patch]);

  const now = () => new Date().toLocaleTimeString();

  const runFuzzer = useCallback<RunOutputValue["runFuzzer"]>(
    async (p) => {
      const k = p.project || "__none__";
      activeRunKeyRef.current = k;
      patch(k, () => ({
        ...EMPTY,
        lastTarget: p.target,
        lastEngine: p.engine,
        log: [`[${now()}] Starting ${p.engine} on ${p.target} for ${p.duration}s`],
      }));
      setRunning(true);
      try {
        const result = await getTransport().invoke<RunResult>("run_fuzzer", {
          project: p.project,
          target: p.target,
          engine: p.engine,
          duration: p.duration,
          arch: p.arch,
        });
        // Web mode has no run_fuzzer endpoint and resolves to undefined.
        if (!result) {
          appendLog(`[${now()}] Fuzzing is not available in web mode.`);
          return 0;
        }
        patch(k, (d) => ({
          ...d,
          summary: {
            edges: result.edges,
            crashes: result.crashes,
            execs: Math.round(result.execs),
            stagnation: result.stagnation ?? null,
            autoRevert: result.auto_revert ?? null,
          },
        }));
        if (result.auto_revert) {
          const ar = result.auto_revert;
          appendLog(
            `[${now()}] Auto-revert: coverage dropped ${ar.drop_pct.toFixed(1)}% (${ar.regressed_edges} < ${ar.previous_edges} edges) after harness ${ar.from_rev.slice(0, 8)} -- restored ${ar.to_rev.slice(0, 8)} and recompiled.`,
          );
        }
        appendLog(`[${now()}] Run complete (exit ${result.exit_code ?? "?"})`);
        return result.crashes;
      } catch (e) {
        appendLog(`error: ${e}`);
        throw e;
      } finally {
        setRunning(false);
        setCancelling(false);
        activeRunKeyRef.current = null;
      }
    },
    [appendLog, patch],
  );

  // Cooperatively cancel the active fuzz run. The backend kills the sandboxed
  // fuzzer and `run_fuzzer` resolves shortly after with its partial results,
  // which clears `running`/`cancelling` via its finally block.
  const cancelRun = useCallback<RunOutputValue["cancelRun"]>(async () => {
    setCancelling(true);
    appendLog(`[${now()}] Stopping run...`);
    try {
      await getTransport().invoke<number>("cancel_run", {});
    } catch (e) {
      appendLog(`error: ${e}`);
      setCancelling(false);
    }
  }, [appendLog]);

  const runSyzkaller = useCallback<RunOutputValue["runSyzkaller"]>(
    async (opts) => {
      // Key on the run's project (not just the active one) so a mid-run project
      // switch doesn't split output; label the target "kernel" so downstream
      // (Triage) knows this was a kernel campaign, not an empty per-target run.
      const k = (typeof opts.project === "string" && opts.project) || keyRef.current || "__none__";
      activeRunKeyRef.current = k;
      patch(k, () => ({ ...EMPTY, lastTarget: "kernel", lastEngine: "syzkaller", log: [`[${now()}] Starting syzkaller campaign`] }));
      setRunning(true);
      try {
        const result = await getTransport().invoke<RunResult>("run_syzkaller", { opts });
        // Web mode has no run_syzkaller endpoint and resolves to undefined.
        if (!result) {
          appendLog(`[${now()}] Syzkaller is not available in web mode.`);
          return 0;
        }
        patch(k, (d) => ({
          ...d,
          summary: { edges: result.edges, crashes: result.crashes, execs: Math.round(result.execs) },
        }));
        appendLog(`[${now()}] Campaign step complete (exit ${result.exit_code ?? "?"})`);
        return result.crashes;
      } catch (e) {
        appendLog(`error: ${e}`);
        throw e;
      } finally {
        setRunning(false);
        setCancelling(false);
        activeRunKeyRef.current = null;
      }
    },
    [appendLog, patch],
  );

  const value = useMemo(
    () => ({
      log: cur.log,
      stats: cur.stats,
      summary: cur.summary,
      running,
      cancelling,
      lastTarget: cur.lastTarget,
      lastEngine: cur.lastEngine,
      runFuzzer,
      runSyzkaller,
      cancelRun,
      clear,
    }),
    [cur, running, cancelling, runFuzzer, runSyzkaller, cancelRun, clear],
  );

  return <RunOutputContext.Provider value={value}>{children}</RunOutputContext.Provider>;
}

/** Access shared run output. Safe outside a provider (returns inert defaults). */
export function useRunOutput(): RunOutputValue {
  const ctx = useContext(RunOutputContext);
  if (!ctx) {
    return {
      log: [],
      stats: ZERO,
      summary: null,
      running: false,
      cancelling: false,
      lastTarget: "",
      lastEngine: "",
      runFuzzer: async () => 0,
      runSyzkaller: async () => 0,
      cancelRun: async () => {},
      clear: () => {},
    };
  }
  return ctx;
}
