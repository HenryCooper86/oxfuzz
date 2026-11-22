import "../i18n.parityRun";
import { useEffect, useRef, useState } from "react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import {
  DEFAULT_RUN_OPTIONS,
  campaignRequest,
  runApi,
  runOptionsError,
  type CampaignOutcome,
  type CampaignProgress,
  type RunOptionsState,
} from "../lib/parityRun";
import { Button, Input } from "./ui";
import { RunOptionsFields } from "./RunOptionsFields";
import { Play } from "lucide-react";

const LOG_CAP = 500;

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function positiveInt(text: string, max: number): number | null {
  const value = Number(text);
  return text.trim() !== "" && Number.isSafeInteger(value) && value >= 1 && value <= max ? value : null;
}

/** Multi-iteration run-then-triage campaign (`oxfuzz campaign`). */
export function CampaignPanel({
  project,
  target,
  engine,
  lang,
  defaultDurationSecs,
  maxDurationSecs,
  disabled,
}: {
  project: string;
  /** Selected run target, shown as a hint only; the field starts empty so the service auto-picks. */
  target: string;
  engine: string;
  lang: string;
  defaultDurationSecs: number;
  maxDurationSecs: number;
  disabled: boolean;
}) {
  const { t } = useI18n();
  const [campaignTarget, setCampaignTarget] = useState("");
  const [iterations, setIterations] = useState("3");
  const [duration, setDuration] = useState(String(defaultDurationSecs));
  const [opts, setOpts] = useState<RunOptionsState>(DEFAULT_RUN_OPTIONS);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [outcome, setOutcome] = useState<CampaignOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      unlistenRef.current?.();
      unlistenRef.current = null;
    };
  }, []);

  const iterationCount = positiveInt(iterations, 1000);
  const durationSecs = positiveInt(duration, maxDurationSecs);
  const optsInvalid = runOptionsError(opts, { maxCpus: null, showCpus: false }) !== null;
  const canStart = !disabled && !running && project !== "" && iterationCount !== null && durationSecs !== null && !optsInvalid;

  async function start() {
    if (!canStart || iterationCount === null || durationSecs === null) return;
    setRunning(true);
    setError(null);
    setOutcome(null);
    setLog([]);
    try {
      try {
        unlistenRef.current = await getTransport().listen<CampaignProgress>("campaign:progress", (event) => {
          const { type, data } = event.payload;
          if (!mounted.current) return;
          const line = type === "LogLine" ? String(data) : null;
          if (line !== null) setLog((previous) => [...previous, line].slice(-LOG_CAP));
        });
      } catch {
        // Progress is advisory; the campaign result is authoritative.
        unlistenRef.current = null;
      }
      const result = await runApi.campaign(
        campaignRequest(
          { project, target: campaignTarget, engine, lang, durationSecs, iterations: iterationCount },
          opts,
        ),
      );
      if (mounted.current) setOutcome(result);
    } catch (e) {
      if (mounted.current) setError(messageOf(e));
    } finally {
      unlistenRef.current?.();
      unlistenRef.current = null;
      if (mounted.current) setRunning(false);
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }} aria-label={t("campaign.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-semibold">{t("campaign.title")}</span>
        <span className="text-xs text-text-muted">{t("campaign.hint")}</span>
      </div>
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" }}>
        <div className="flex flex-col gap-1">
          <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>{t("campaign.target")}</span>
          <Input
            mono
            aria-label={t("campaign.target")}
            placeholder={target || t("campaign.targetAuto")}
            value={campaignTarget}
            disabled={running}
            onChange={(e) => setCampaignTarget(e.target.value)}
          />
          <span className="text-xs text-text-muted">{t("campaign.targetHelp")}</span>
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>{t("campaign.iterations")}</span>
          <Input
            type="number"
            min={1}
            aria-label={t("campaign.iterations")}
            value={iterations}
            disabled={running}
            onChange={(e) => setIterations(e.target.value)}
          />
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>{t("campaign.duration")}</span>
          <Input
            type="number"
            min={1}
            max={maxDurationSecs}
            aria-label={t("campaign.duration")}
            value={duration}
            disabled={running}
            onChange={(e) => setDuration(e.target.value)}
          />
        </div>
      </div>
      <RunOptionsFields value={opts} onChange={setOpts} engine={engine} maxCpus={null} showCpus={false} disabled={running} />
      <div>
        <Button variant="primary" size="sm" onClick={() => void start()} disabled={!canStart} loading={running}>
          {!running && <Play size={14} />}
          {running ? t("campaign.running") : t("campaign.start")}
        </Button>
      </div>
      {error && <p role="alert" className="text-xs text-error">{error}</p>}
      {log.length > 0 && (
        <div className="max-h-48 overflow-auto" role="log" aria-label={t("campaign.log")} style={{ fontFamily: "var(--font-mono)" }}>
          {log.map((line, i) => <div key={i} className="text-xs text-text-secondary">{line}</div>)}
        </div>
      )}
      {outcome && <CampaignSummary outcome={outcome} />}
    </section>
  );
}

function CampaignSummary({ outcome }: { outcome: CampaignOutcome }) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-1 text-sm" role="status">
      <p className="font-semibold">{t("campaign.finished", { target: outcome.target })}</p>
      <p className="text-xs">
        {t("campaign.crashes", { count: outcome.crashes })} · {t("campaign.edges", { count: outcome.edges })} · {t("campaign.iterationsDone", { count: outcome.iterations })} · {t("campaign.autoReverts", { count: outcome.auto_reverts })}
        {typeof outcome.hangs === "number" && <> · {t("campaign.hangs", { count: outcome.hangs })}</>}
      </p>
      <p className="text-xs text-text-muted">{t("campaign.harnessStatus", { status: outcome.harness_status })} · {t("campaign.termination", { reason: outcome.termination })}</p>
      {outcome.refine && (
        <div className="text-xs" style={{ borderLeft: "3px solid var(--accent)", paddingLeft: "var(--space-sm)" }}>
          <p>{outcome.refine.note}</p>
          {outcome.refine.harness_id && (
            <p>
              {t("campaign.refineId")} <code>{outcome.refine.harness_id}</code>. {t("campaign.refineAdopt")}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
