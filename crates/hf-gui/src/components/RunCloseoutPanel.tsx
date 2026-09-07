import { useEffect, useMemo, useRef, useState } from "react";
import { getTransport } from "../lib";
import { formatInvokeError } from "../lib/invokeError";
import type { CloseoutStep, RunCloseoutReport } from "../types";
import { Button } from "./ui";
import { useI18n } from "../i18nContext";

const STEPS: CloseoutStep[] = [
  "triage",
  "minimize",
  "corpus_absorb",
  "coverage",
  "blockers",
  "disposition",
  "trust_report",
];

function detail(report: RunCloseoutReport, step: CloseoutStep, t: (key: string, params?: Record<string, string | number>) => string): string {
  const outcome = report.steps.find((item) => item.step === step)?.outcome;
  if (!outcome) return t("runCloseout.pending");
  if (outcome.outcome === "completed") return outcome.detail;
  if (outcome.outcome === "skipped") return outcome.reason;
  if (outcome.outcome === "blocked") {
    return t("runCloseout.blockedBy", { step: t(`runCloseout.step.${outcome.dependency}`) });
  }
  return outcome.error;
}

function outcomeLabel(outcome: string, t: (key: string) => string) {
  return t(`runCloseout.${outcome}`);
}

interface RunCloseoutPanelProps {
  runId: string;
  runKind: string;
  runStatus: string;
}

export function RunCloseoutPanel(props: RunCloseoutPanelProps) {
  return <RunCloseoutPanelSession key={props.runId} {...props} />;
}

function RunCloseoutPanelSession({
  runId,
  runKind,
  runStatus,
}: RunCloseoutPanelProps) {
  const { t } = useI18n();
  const [report, setReport] = useState<RunCloseoutReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const lifetime = useRef(0);
  useEffect(() => {
    lifetime.current += 1;
    return () => { lifetime.current += 1; };
  }, []);
  const eligible = runKind.toLowerCase() === "campaign"
    && ["done", "failed", "cancelled"].includes(runStatus.toLowerCase());

  useEffect(() => {
    let current = true;
    getTransport().invoke<RunCloseoutReport>("run_closeout_report", { runId })
      .then((value) => { if (current) setReport(value); })
      .catch((cause) => { if (current) setError(formatInvokeError(cause)); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [runId]);

  const available = report?.availability.status === "available";
  const reason = useMemo(() => {
    if (!eligible) return t("runCloseout.terminalOnly");
    if (report?.availability.status === "unavailable") return report.availability.reason;
    return error;
  }, [eligible, error, report, t]);

  async function analyze() {
    const generation = lifetime.current;
    setRunning(true);
    setError(null);
    try {
      const value = await getTransport().invoke<RunCloseoutReport>("run_closeout", { runId });
      if (lifetime.current === generation) setReport(value);
    } catch (cause) {
      if (lifetime.current === generation) setError(formatInvokeError(cause));
    } finally {
      if (lifetime.current === generation) setRunning(false);
    }
  }

  return (
    <section data-run-closeout className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <div>
          <h4 className="text-sm font-semibold">{t("runCloseout.title")}</h4>
          <p className="text-xs text-text-muted">{t("runCloseout.description")}</p>
          <p className="text-xs text-text-muted">{t("runCloseout.effects")}</p>
        </div>
        <Button size="sm" onClick={() => void analyze()} disabled={!eligible || !available || running}>
          {running ? t("runCloseout.analyzing") : t("runCloseout.analyze")}
        </Button>
      </div>
      {reason && <p role="status" className="text-xs text-text-muted">{reason}</p>}
      {loading && <p role="status" className="text-xs text-text-muted">{t("runCloseout.loading")}</p>}
      {report && (
        <ol className="grid gap-1">
          {STEPS.map((step) => {
            const record = report.steps.find((item) => item.step === step);
            return (
              <li key={step} className="flex gap-2 text-xs">
                <strong className="w-28">{t(`runCloseout.step.${step}`)}</strong>
                <span data-closeout-outcome={record?.outcome.outcome ?? "pending"}>
                  <strong>{outcomeLabel(record?.outcome.outcome ?? "pending", t)}</strong>: {detail(report, step, t)}
                </span>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
