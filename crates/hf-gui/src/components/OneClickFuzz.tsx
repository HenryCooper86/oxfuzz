import { useCallback, useEffect, useRef, useState } from "react";
import { Rocket } from "lucide-react";
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

type Phase =
  | { kind: "idle" }
  | { kind: "preparing"; stage: { stage: string; target: string | null; reused: boolean } | null }
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

  async function prepare() {
    if (!activeProject || !settings) return;
    const project = activeProject;
    setPhase({ kind: "preparing", stage: null });
    let unlisten: (() => void) | undefined;
    try {
      unlisten = await getTransport().listen<{ stage: string; target: string | null; reused: boolean }>("fuzz:stage", (event) => {
        setPhase((current) => current.kind === "preparing" ? { kind: "preparing", stage: event.payload } : current);
      });
    } catch {
      // Without stage events the panel shows a generic "Preparing" line.
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
      if (prepared.harness_reused) {
        setPhase({ kind: "ready", scope });
      } else {
        setPhase({ kind: "awaitingApproval", scope });
        onOpen("harness");
      }
    } catch (error) {
      setPhase({ kind: "error", message: String(error) });
    } finally {
      unlisten?.();
    }
  }

  const stageText = (stage: { stage: string; target: string | null; reused: boolean } | null) => {
    if (!stage) return t("oneClick.preparing");
    const target = stage.target ?? "";
    if (stage.stage === "discover") return t("oneClick.stage.discover");
    if (stage.stage === "harness") return t(stage.reused ? "oneClick.stage.harnessReused" : "oneClick.stage.harness", { target });
    if (stage.stage === "smoke") return t("oneClick.stage.smoke", { target });
    return t("oneClick.preparing");
  };

  const busy = phase.kind === "preparing";
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
      {phase.kind === "preparing" && <p role="status" className="text-xs m-0">{stageText(phase.stage)}</p>}
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
