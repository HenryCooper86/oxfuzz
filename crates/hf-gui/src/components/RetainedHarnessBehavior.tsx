import { useCallback, useEffect, useRef, useState } from "react";
import { getTransport } from "../lib";
import { formatInvokeError } from "../lib/invokeError";
import type { RunOwner } from "../lib/transport";
import { useI18n } from "../i18nContext";
import { behaviorChecks } from "../lib/harnessBehavior";
import { HarnessBehaviorEvidence, type HarnessBehaviorReport } from "./HarnessBehaviorEvidence";
import { Button } from "./ui";

type Props = { runId: string | null; project: string; target: string; sourceSha?: string | null; binarySha?: string | null };
function matchesReport(value: unknown, props: Props): value is HarnessBehaviorReport {
  if (!value || typeof value !== "object") return false;
  const report = value as Record<string, unknown>;
  if (report.version !== 1 || !behaviorChecks.every(key => {
    const check = report[key] as Record<string, unknown> | null;
    return check && ["pass", "suspect", "unavailable"].includes(String(check.status)) && typeof check.detail === "string" && check.detail.length <= 16384;
  })) return false;
  if (report.run_id === null) return behaviorChecks.every(key => (report[key] as Record<string, unknown>).status === "unavailable");
  return report.run_id === props.runId && (!props.sourceSha || report.source_sha256 === props.sourceSha)
    && (!props.binarySha || report.binary_sha256 === props.binarySha);
}
export function RetainedHarnessBehavior(props: Props) {
  return <Evidence key={JSON.stringify(props)} {...props} />;
}
function Evidence(props: Props) {
  const { t } = useI18n();
  const { runId, project, target, sourceSha, binarySha } = props;
  const [report, setReport] = useState<HarnessBehaviorReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(Boolean(runId));
  const generation = useRef(0);
  const load = useCallback(async () => {
    if (!runId) return;
    const current = ++generation.current;
    setBusy(true); setError(null); setReport(null);
    try {
      const owner = await getTransport().invoke<RunOwner>("run_owner", { runId });
      if (current !== generation.current) return;
      if (owner.run_id !== runId || owner.project_root !== project || owner.target !== target || owner.kind !== "smoke") throw new Error(t("harness.behavior.ownerMismatch"));
      const value = await getTransport().invoke<unknown>("run_harness_behavior", { runId });
      if (current !== generation.current) return;
      if (!matchesReport(value, { runId, project, target, sourceSha, binarySha })) throw new Error(t("harness.behavior.invalid"));
      setReport(value);
    } catch (failure) { if (current === generation.current) setError(formatInvokeError(failure)); }
    finally { if (current === generation.current) setBusy(false); }
  }, [runId, project, target, sourceSha, binarySha, t]);
  const invalidate = useCallback(() => { generation.current++; }, []);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) void load(); });
    return () => { active = false; invalidate(); };
  }, [load, invalidate]);
  return <section className="mt-3 space-y-2" aria-label={t("harness.behavior.title")}>
    {runId ? <><p className="font-mono text-xs break-all">{runId}</p><Button size="sm" variant="outline" disabled={busy} onClick={() => void load()}>{t("harness.behavior.refresh")}</Button></> : <p>{t("harness.behavior.noRun")}</p>}
    {busy && <p role="status">{t("harness.behavior.loading")}</p>}
    {error && <p role="alert" className="text-error">{error}</p>}
    {report && <HarnessBehaviorEvidence report={report} />}
  </section>;
}
