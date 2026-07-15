import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import { useProject } from "./project";
import { useRunStatus } from "./runStatus";
import { pruneToKeys } from "../lib/projectState";
import {
  EMPTY_RUN_STATS,
  RunOutputContext,
  type AutoRevert,
  type RunOutputValue,
  type RunStats,
  type RunSummary,
} from "./runOutput";

// Owns the output of a fuzz run -- the live log, rolling stats, final summary --
// and the `run:progress` listener. Persistent output is kept per fuzzing target
// (project path) so switching targets retains each one's last run; the live
// `running` flag is global since only one run happens at a time. Because this
// lives at the app root (always mounted), a run keeps streaming even when the
// user navigates away from the Run view.

type RunResult = {
  run_id: string | null;
  edges: number;
  crashes: number;
  execs: number;
  exit_code: number | null;
  termination: "completed" | "timed_out" | "cancelled";
  stagnation?: string | null;
  auto_revert?: AutoRevert | null;
};

interface RunData {
  log: string[];
  stats: RunStats;
  summary: RunSummary | null;
  lastTarget: string;
  lastEngine: string;
}

const EMPTY: RunData = {
  log: [],
  stats: EMPTY_RUN_STATS,
  summary: null,
  lastTarget: "",
  lastEngine: "",
};
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
        stats: v.stats ?? EMPTY_RUN_STATS,
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
  const { t } = useI18n();
  const { activeProject, recentProjects } = useProject();
  // The status bar's "active engine" indicator is owned here (where every run
  // path lives) rather than in a single view, so runs launched from the agent,
  // automation, or syzkaller flows light it up too -- not just the Run button.
  const { setActiveEngine } = useRunStatus();
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
      setActiveEngine(p.engine);
      try {
        const result = await getTransport().invoke<RunResult>("run_fuzzer", {
          project: p.project,
          target: p.target,
          engine: p.engine,
          duration: p.duration,
        });
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
          const tail = ar.reverted
            ? `restored ${ar.to_rev.slice(0, 8)} and recompiled.`
            : `notify-only: last-good ${ar.to_rev.slice(0, 8)} was NOT restored.`;
          appendLog(
            `[${now()}] Auto-revert: coverage dropped ${ar.drop_pct.toFixed(1)}% (${ar.regressed_edges} < ${ar.previous_edges} edges) after harness ${ar.from_rev.slice(0, 8)} -- ${tail}`,
          );
        }
        if (result.termination === "cancelled") {
          appendLog(`[${now()}] Run cancelled; partial evidence retained for ${result.run_id ?? "the run"}.`);
        } else if (result.termination === "timed_out") {
          appendLog(`[${now()}] Run timed out; partial evidence retained for ${result.run_id ?? "the run"}.`);
        } else {
          appendLog(`[${now()}] Run complete (exit ${result.exit_code ?? "?"})`);
        }
        return result.crashes;
      } catch (e) {
        appendLog(`error: ${e}`);
        throw e;
      } finally {
        setRunning(false);
        setCancelling(false);
        setActiveEngine(null);
        activeRunKeyRef.current = null;
      }
    },
    [appendLog, patch, setActiveEngine],
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
      setActiveEngine("syzkaller");
      try {
        const result = await getTransport().invoke<RunResult>("run_syzkaller", { opts });
        // Web mode has no run_syzkaller endpoint and resolves to undefined.
        if (!result) {
          appendLog(`[${now()}] ${t("run.webModeSyzUnavailable")}`);
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
        setActiveEngine(null);
        activeRunKeyRef.current = null;
      }
    },
    [appendLog, patch, setActiveEngine, t],
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
