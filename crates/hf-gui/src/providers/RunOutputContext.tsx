import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { getTransport } from "../lib";

// Owns the output of a fuzz run -- the live log, rolling stats, final summary,
// and running flag -- and the `run:progress` listener. Because this lives at
// the app root (always mounted), a run keeps streaming into it even when the
// user navigates away from the Run view, so no progress is lost when jumping
// between stages.

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
const LOG_CAP = 600;

export function RunOutputProvider({ children }: { children: React.ReactNode }) {
  const [log, setLog] = useState<string[]>([]);
  const [stats, setStats] = useState<Stats>(ZERO);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [running, setRunning] = useState(false);
  const [lastTarget, setLastTarget] = useState("");
  const [lastEngine, setLastEngine] = useState("");

  const appendLog = useCallback((line: string) => {
    setLog((l) => (l.length >= LOG_CAP ? [...l.slice(-(LOG_CAP - 1)), line] : [...l, line]));
  }, []);

  // Always-on progress listener: stats update in place, raw fuzzer lines fill
  // the log. Mounted once for the app's lifetime.
  useEffect(() => {
    let alive = true;
    let unlisten: (() => void) | undefined;
    getTransport()
      .listen<{ type: string; data: unknown }>("run:progress", (ev) => {
        const p = ev.payload;
        if (p?.type === "ExecsPerSec") {
          const v = Number(p.data) || 0;
          setStats((s) => ({ ...s, execs: Math.max(s.execs, v) }));
        } else if (p?.type === "EdgesCovered") {
          const v = Number(p.data) || 0;
          setStats((s) => ({ ...s, edges: Math.max(s.edges, v) }));
        } else if (p?.type === "CrashesFound") {
          setStats((s) => ({ ...s, crashes: s.crashes + 1 }));
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
  }, [appendLog]);

  const clear = useCallback(() => {
    setLog([]);
    setStats(ZERO);
    setSummary(null);
  }, []);

  const now = () => new Date().toLocaleTimeString();

  const runFuzzer = useCallback<RunOutputValue["runFuzzer"]>(
    async (p) => {
      clear();
      setRunning(true);
      setLastTarget(p.target);
      setLastEngine(p.engine);
      setLog([`[${now()}] Starting ${p.engine} on ${p.target} for ${p.duration}s`]);
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
        setSummary({ edges: result.edges, crashes: result.crashes, execs: Math.round(result.execs) });
        appendLog(`[${now()}] Run complete (exit ${result.exit_code ?? "?"})`);
        return result.crashes;
      } catch (e) {
        appendLog(`error: ${e}`);
        throw e;
      } finally {
        setRunning(false);
      }
    },
    [appendLog, clear],
  );

  const runSyzkaller = useCallback<RunOutputValue["runSyzkaller"]>(
    async (opts) => {
      clear();
      setRunning(true);
      setLastTarget("");
      setLastEngine("syzkaller");
      setLog([`[${now()}] Starting syzkaller campaign`]);
      try {
        const result = await getTransport().invoke<RunResult>("run_syzkaller", { opts });
        // Web mode has no run_syzkaller endpoint and resolves to undefined.
        if (!result) {
          appendLog(`[${now()}] Syzkaller is not available in web mode.`);
          return 0;
        }
        setSummary({ edges: result.edges, crashes: result.crashes, execs: Math.round(result.execs) });
        appendLog(`[${now()}] Campaign step complete (exit ${result.exit_code ?? "?"})`);
        return result.crashes;
      } catch (e) {
        appendLog(`error: ${e}`);
        throw e;
      } finally {
        setRunning(false);
      }
    },
    [appendLog, clear],
  );

  const value = useMemo(
    () => ({ log, stats, summary, running, lastTarget, lastEngine, runFuzzer, runSyzkaller, clear }),
    [log, stats, summary, running, lastTarget, lastEngine, runFuzzer, runSyzkaller, clear],
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
