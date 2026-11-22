import "../i18n.parityRun";
import { useState } from "react";
import { useI18n } from "../i18nContext";
import { runApi, type AiPolicy, type CiGateOutcome } from "../lib/parityRun";
import { Button, Input, Select } from "./ui";
import { ShieldCheck } from "lucide-react";

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Short fuzz run plus triage that decides a pass/fail gate (`oxfuzz ci`). */
export function CiGatePanel({
  project,
  target,
  engine,
  maxDurationSecs,
  disabled,
}: {
  project: string;
  target: string;
  engine: string;
  maxDurationSecs: number;
  disabled: boolean;
}) {
  const { t } = useI18n();
  const [duration, setDuration] = useState("120");
  const [ai, setAi] = useState<AiPolicy>("auto");
  const [running, setRunning] = useState(false);
  const [outcome, setOutcome] = useState<CiGateOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);

  const seconds = Number(duration);
  const validDuration = duration.trim() !== "" && Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= maxDurationSecs;
  const canRun = !disabled && !running && project !== "" && target !== "" && validDuration;

  async function run() {
    if (!canRun) return;
    setRunning(true);
    setError(null);
    setOutcome(null);
    setSavedPath(null);
    try {
      setOutcome(await runApi.ciGate({ project, target, engine, durationSecs: seconds, ...(ai === "auto" ? {} : { ai }) }));
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setRunning(false);
    }
  }

  async function saveSarif() {
    if (!outcome) return;
    try {
      setSavedPath(await runApi.saveText({ fileName: "oxfuzz.sarif", extensions: ["sarif", "json"], contents: outcome.sarif }));
    } catch (e) {
      setError(messageOf(e));
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }} aria-label={t("ci.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-semibold">{t("ci.title")}</span>
        <span className="text-xs text-text-muted">{t("ci.hint")}</span>
      </div>
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" }}>
        <div className="flex flex-col gap-1">
          <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>{t("ci.duration")}</span>
          <Input
            type="number"
            min={1}
            max={maxDurationSecs}
            aria-label={t("ci.duration")}
            value={duration}
            disabled={running}
            onChange={(e) => setDuration(e.target.value)}
          />
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>{t("runOpts.ai")}</span>
          <Select
            ariaLabel={t("ci.ai")}
            value={ai}
            disabled={running}
            onChange={(next) => setAi(next as AiPolicy)}
            options={[
              { value: "auto", label: t("runOpts.aiAuto") },
              { value: "require", label: t("runOpts.aiRequire") },
              { value: "off", label: t("runOpts.aiOff") },
            ]}
          />
          <span className="text-xs text-text-muted">{t("ci.aiHelp")}</span>
        </div>
      </div>
      {target === "" && <p className="text-xs text-text-muted">{t("ci.noTarget")}</p>}
      <div>
        <Button variant="primary" size="sm" onClick={() => void run()} disabled={!canRun} loading={running}>
          {!running && <ShieldCheck size={14} />}
          {running ? t("ci.running") : t("ci.run")}
        </Button>
      </div>
      {error && <p role="alert" className="text-xs text-error">{error}</p>}
      {outcome && (
        <div className="flex flex-col gap-2" role="status">
          <p className="text-sm font-semibold" style={{ color: outcome.passed ? "var(--success)" : "var(--error)" }}>
            {outcome.passed ? t("ci.pass") : t("ci.fail")}
          </p>
          {outcome.seed_warning && <p className="text-xs text-text-muted">{outcome.seed_warning}</p>}
          {outcome.findings.length > 0 && (
            <ul className="flex flex-col gap-1 text-xs">
              {outcome.findings.map((finding, i) => (
                <li key={i}><strong>{finding.kind}</strong>: {finding.summary}</li>
              ))}
            </ul>
          )}
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void saveSarif()}>{t("ci.saveSarif")}</Button>
            {savedPath && <span className="text-xs text-text-muted break-all">{t("ci.savedTo", { path: savedPath })}</span>}
          </div>
        </div>
      )}
    </section>
  );
}
