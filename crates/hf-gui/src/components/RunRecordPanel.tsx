import "../i18n.parityDiscovery";
import { useState } from "react";
import { useI18n } from "../i18nContext";
import { formatInvokeError } from "../lib/invokeError";
import { discoveryApi } from "../lib/parityDiscovery";
import { Button } from "./ui";

/** One run's full stored record with live telemetry (`oxfuzz runs --id`). */
export function RunRecordPanel({ runId }: { runId: string }) {
  const { t } = useI18n();
  const [record, setRecord] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      setRecord(await discoveryApi.runDetail(runId));
    } catch (cause) {
      setError(formatInvokeError(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-2 mt-2">
      <div><Button variant="outline" size="sm" onClick={() => void load()} loading={busy} disabled={busy}>{t("parityDiscovery.runs.record")}</Button></div>
      {record && <pre className="text-xs overflow-auto max-h-64">{JSON.stringify(record, null, 2)}</pre>}
      {error && <p role="alert" className="text-xs" style={{ color: "var(--error)" }}>{t("parityDiscovery.runs.recordFailed", { error })}</p>}
    </div>
  );
}
