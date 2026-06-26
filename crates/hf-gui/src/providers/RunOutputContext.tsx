import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { getTransport } from "../lib";
import { useProject } from "./ProjectContext";

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
interface Summary {
  edges: number;
  crashes: number;
  execs: number;
}
type RunResult = { edges: number; crashes: number; execs: number; exit_code: number | null };

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
  clear: () => void;
}

const RunOutputContext = createContext<RunOutputValue | null>(null);

const ZERO: Stats = { execs: 0, edges: 0, crashes: 0 };
const EMPTY: RunData = { log: [], stats: ZERO, summary: null, lastTarget: "", lastEngine: "" };
const LOG_CAP = 600;

export function RunOutputProvider({ children }: { children: React.ReactNode }) {
  const { activeProject } = useProject();
  const key = activeProject || "__none__";
  // The always-mounted progress listener writes to whichever target is active.
  const keyRef = useRef(key);
  useEffect(() => {
    keyRef.current = key;
  }, [key]);

  const [byProject, setByProject] = useState<Record<string, RunData>>({});
  const [running, setRunning] = useState(false);
  const cur = byProject[key] ?? EMPTY;

  const patch = useCallback((k: string, fn: (d: RunData) => RunData) => {
    setByProject((prev) => ({ ...prev, [k]: fn(prev[k] ?? EMPTY) }));
  }, []);

  const appendLog = useCallback(
    (line: string) => {
      patch(keyRef.current, (d) => ({
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
        const k = keyRef.current;
        if (p?.type === "ExecsPerSec") {
          const v = Number(p.data) || 0;
          patch(k, (d) => ({ ...d, stats: { ...d.stats, execs: Math.max(d.stats.execs, v) } }));
        } else if (p?.type === "EdgesCovered") {
          const v = Number(p.data) || 0;
          patch(k, (d) => ({ ...d, stats: { ...d.stats, edges: Math.max(d.stats.edges, v) } }));
        } else if (p?.type === "CrashesFound") {
          patch(k, (d) => ({ ...d, stats: { ...d.stats, crashes: d.stats.crashes + 1 } }));
          appendLog("  ⚠ CRASH DETECTED");
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
          summary: { edges: result.edges, crashes: result.crashes, execs: Math.round(result.execs) },
        }));
        appendLog(`[${now()}] Run complete (exit ${result.exit_code ?? "?"})`);
        return result.crashes;
      } catch (e) {
        appendLog(`error: ${e}`);
        throw e;
      } finally {
        setRunning(false);
      }
    },
    [appendLog, patch],
  );

  const runSyzkaller = useCallback<RunOutputValue["runSyzkaller"]>(
    async (opts) => {
      const k = keyRef.current;
      patch(k, () => ({ ...EMPTY, lastEngine: "syzkaller", log: [`[${now()}] Starting syzkaller campaign`] }));
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
      lastTarget: cur.lastTarget,
      lastEngine: cur.lastEngine,
      runFuzzer,
      runSyzkaller,
      clear,
    }),
    [cur, running, runFuzzer, runSyzkaller, clear],
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
      lastTarget: "",
      lastEngine: "",
      runFuzzer: async () => 0,
      runSyzkaller: async () => 0,
      clear: () => {},
    };
  }
  return ctx;
}
