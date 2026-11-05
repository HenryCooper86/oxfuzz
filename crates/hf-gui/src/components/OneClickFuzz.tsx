import { useCallback, useEffect, useRef, useState } from "react";
import { Check, LoaderCircle, Rocket, X } from "lucide-react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import { useProject } from "../providers/project";
import { useTarget } from "../providers/target";
import { usePipeline } from "../providers/pipeline";
import { useRunOutput } from "../providers/runOutput";
import { useFuzzingSettings } from "../hooks/useFuzzingSettings";
import { formatDuration } from "../lib/duration";
import { canonicalHarnessEngine } from "../lib/harnessScope";
import { Button } from "./ui";

/** The harness scope an approval or a run applies to. */
export interface HarnessScope {
  project: string;
  target: string;
  engine: string;
}

/** Lets the Workflow tell this component that a harness was approved. */
export interface OneClickApi {
  approved: (scope: HarnessScope) => void;
}

interface FuzzPrepared {
  target: string;
  lang: string;
  engine: string;
  harness_reused: boolean;
}

/** One `fuzz:stage` event: a stage boundary, or a step inside the harness stage. */
interface StageEvent {
  stage: string;
  target: string | null;
  reused: boolean;
  step?:
    | { kind: "drafting" }
    | { kind: "compiling"; attempt: number }
    | { kind: "compile_failed"; attempt: number }
    | { kind: "repairing"; repair: number; max: number };
}

type StepStatus = "running" | "done" | "failed";

/** One row of the preparation progress list. */
interface StepRow {
  key: string;
  label: string;
  params: Record<string, string | number>;
  startedAt: number;
  endedAt?: number;
  status: StepStatus;
}

/** Build output lines kept on screen; older lines scroll away. */
const MAX_LOG_LINES = 400;

/** End the running row, if any, with `status`. */
function closeRunning(rows: StepRow[], status: StepStatus, at: number): StepRow[] {
  return rows.map(row => row.status === "running" ? { ...row, status, endedAt: at } : row);
}

/** Apply one stage event to the progress rows. */
function applyStage(rows: StepRow[], event: StageEvent, at: number): StepRow[] {
  const target = event.target ?? "";
  const start = (key: string, label: string, params: Record<string, string | number> = {}) =>
    [...closeRunning(rows, "done", at), { key, label, params, startedAt: at, status: "running" as const }];
  const step = event.step;
  if (step?.kind === "drafting") return start("draft", "oneClick.step.draft", { target });
  if (step?.kind === "compiling") return start(`compile-${step.attempt}`, "oneClick.step.compile", { attempt: step.attempt });
  if (step?.kind === "compile_failed") return closeRunning(rows, "failed", at);
  if (step?.kind === "repairing") return start(`repair-${step.repair}`, "oneClick.step.repair", { repair: step.repair, max: step.max });
  if (event.stage === "discover") return start("discover", "oneClick.step.discover");
  if (event.stage === "harness" && event.reused) return start("reuse", "oneClick.step.reuse", { target });
  if (event.stage === "smoke") return start("smoke", "oneClick.step.smoke");
  return rows;
}

/** Elapsed milliseconds as "12s" or "1m 05s". */
function formatElapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`;
}

type Phase =
  | { kind: "idle" }
  | { kind: "preparing" }
  | { kind: "awaitingApproval"; scope: HarnessScope }
  | { kind: "ready"; scope: HarnessScope }
  | { kind: "started"; scope: HarnessScope }
  | { kind: "error"; message: string };

const LANGS: Record<string, string> = { c: "c", cpp: "cpp", "c++": "cpp", rust: "rust", go: "go", python: "python" };

/**
 * "Fuzz this project": prepare a target and harness in one click, then stop
 * for the person to approve the harness. The click carries only the smoke-test
 * consent; a run starts after the matching approval, or from an explicit
 * "Start run" when the target already had an approved harness.
 */
export function OneClickFuzz({ onOpen, apiRef }: {
  onOpen: (section: "harness" | "run") => void;
  apiRef?: (api: OneClickApi | null) => void;
}) {
  const { t } = useI18n();
  const { activeProject } = useProject();
  const { setTarget, setEngine, setLang } = useTarget();
  const { markDone } = usePipeline();
  const { runFuzzer } = useRunOutput();
  const { settings } = useFuzzingSettings();
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [steps, setSteps] = useState<StepRow[]>([]);
  const [log, setLog] = useState<string[]>([]);
  const [logOpen, setLogOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const logRef = useRef<HTMLPreElement>(null);
  const duration = settings?.default_duration_secs ?? 0;
  const durationText = formatDuration(duration);

  const startRun = useCallback(async (scope: HarnessScope) => {
    if (!settings) return;
    setPhase({ kind: "started", scope });
    onOpen("run");
    try {
      await runFuzzer({ ...scope, duration: settings.default_duration_secs });
    } catch (error) {
      setPhase({ kind: "error", message: String(error) });
    }
  }, [onOpen, runFuzzer, settings]);

  // Keep the latest phase reachable from the stable approval callback.
  const phaseRef = useRef(phase);
  useEffect(() => { phaseRef.current = phase; }, [phase]);
  useEffect(() => {
    apiRef?.({
      approved: (scope) => {
        const current = phaseRef.current;
        if (current.kind !== "awaitingApproval") return;
        const pending = current.scope;
        if (pending.project === scope.project && pending.target === scope.target && canonicalHarnessEngine(pending.engine) === canonicalHarnessEngine(scope.engine)) {
          void startRun(pending);
        }
      },
    });
    return () => apiRef?.(null);
  }, [apiRef, startRun]);

  // Running rows show a live elapsed time.
  const busy = phase.kind === "preparing";
  useEffect(() => {
    if (!busy) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [busy]);

  // Keep the newest build output in view.
  useEffect(() => {
    const element = logRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [log, logOpen]);

  async function prepare() {
    if (!activeProject || !settings) return;
    const project = activeProject;
    setPhase({ kind: "preparing" });
    setSteps([]);
    setLog([]);
    setLogOpen(false);
    const unlisten: (() => void)[] = [];
    try {
      unlisten.push(await getTransport().listen<StageEvent>("fuzz:stage", (event) => {
        const at = Date.now();
        setSteps(rows => applyStage(rows, event.payload, at));
        setNow(at);
      }));
      unlisten.push(await getTransport().listen<{ line: string }>("fuzz:log", (event) => {
        setLog(lines => [...lines, event.payload.line].slice(-MAX_LOG_LINES));
      }));
    } catch {
      // Without events the panel shows a generic "Preparing" line.
    }
    try {
      const prepared = await getTransport().invoke<FuzzPrepared>("fuzz_prepare", { project, engine: settings.default_engine });
      const engine = canonicalHarnessEngine(prepared.engine) || settings.default_engine;
      const scope = { project, target: prepared.target, engine };
      setTarget(prepared.target);
      setEngine(engine);
      const lang = LANGS[prepared.lang.toLowerCase()];
      if (lang) setLang(lang);
      markDone("discover", project);
      setSteps(rows => closeRunning(rows, "done", Date.now()));
      if (prepared.harness_reused) {
        setPhase({ kind: "ready", scope });
      } else {
        setPhase({ kind: "awaitingApproval", scope });
        onOpen("harness");
      }
    } catch (error) {
      setSteps(rows => closeRunning(rows, "failed", Date.now()));
      setLogOpen(true);
      setPhase({ kind: "error", message: String(error) });
    } finally {
      unlisten.forEach(stop => stop());
    }
  }

  const showSteps = (busy || phase.kind === "error") && steps.length > 0;
  return (
    <section className="surface-card flex flex-col gap-2" style={{ padding: "12px 14px", borderLeft: "3px solid var(--accent)" }}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-text-secondary m-0 flex-1 min-w-[240px]">{t("oneClick.hint", { duration: durationText })}</p>
        {phase.kind !== "awaitingApproval" && phase.kind !== "ready" && (
          <Button variant="primary" size="sm" onClick={() => void prepare()} disabled={!activeProject || !settings || busy} loading={busy}>
            {!busy && <Rocket size={13} />}{t("oneClick.title")}
          </Button>
        )}
      </div>
      {busy && steps.length === 0 && <p role="status" className="text-xs m-0">{t("oneClick.preparing")}</p>}
      {showSteps && (
        <ol role="status" aria-label={t("oneClick.progress")} className="m-0 p-0 list-none flex flex-col gap-1 text-xs">
          {steps.map(row => (
            <li key={row.key} data-step-status={row.status} className="flex items-center gap-2">
              {row.status === "running" && <LoaderCircle aria-hidden size={13} className="animate-spin shrink-0" style={{ color: "var(--accent)" }} />}
              {row.status === "done" && <Check aria-hidden size={13} className="shrink-0" style={{ color: "var(--success)" }} />}
              {row.status === "failed" && <X aria-hidden size={13} className="shrink-0" style={{ color: "var(--error)" }} />}
              <span className={row.status === "running" ? "flex-1" : "flex-1 text-text-secondary"}>{t(row.label, row.params)}</span>
              <span className="tabular-nums text-text-secondary">{formatElapsed((row.endedAt ?? now) - row.startedAt)}</span>
            </li>
          ))}
        </ol>
      )}
      {log.length > 0 && (
        <details open={logOpen} onToggle={(event) => setLogOpen(event.currentTarget.open)} className="text-xs">
          <summary className="cursor-pointer text-text-secondary">{log.length === 1 ? t("oneClick.logOne") : t("oneClick.logMany", { count: log.length })}</summary>
          <pre ref={logRef} className="m-0 mt-1 p-2 overflow-auto font-mono whitespace-pre-wrap break-all" style={{ maxHeight: 220, background: "var(--surface-code)", borderRadius: 6 }}>{log.join("\n")}</pre>
        </details>
      )}
      {phase.kind === "awaitingApproval" && <p role="status" className="text-xs m-0">{t("oneClick.awaitingApproval", { target: phase.scope.target, duration: durationText })}</p>}
      {phase.kind === "ready" && (
        <div className="flex flex-wrap items-center gap-2">
          <p role="status" className="text-xs m-0">{t("oneClick.reused", { target: phase.scope.target })}</p>
          <Button variant="primary" size="sm" onClick={() => void startRun(phase.scope)}>{t("oneClick.startRun", { duration: durationText })}</Button>
        </div>
      )}
      {phase.kind === "started" && <p role="status" className="text-xs m-0">{t("oneClick.started", { target: phase.scope.target, duration: durationText })}</p>}
      {phase.kind === "error" && <p role="alert" className="text-xs m-0" style={{ color: "var(--error)" }}>{t("oneClick.failed", { error: phase.message })}</p>}
    </section>
  );
}
