import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, X } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../lib";
import { formatInvokeError } from "../lib/invokeError";
import { Button } from "./ui";
import { useI18n } from "../i18nContext";

interface InterruptedRun {
  run_id: string;
  project: string;
  target: string;
  engine: string;
  started_at: number;
}

const shortPath = (p: string) => p.split("/").filter(Boolean).pop() || p;

export function RecoveryBanner({ onReview }: { onReview?: (run: InterruptedRun) => void }) {
  return isTauriEnvironment() ? <DesktopRecoveryBanner onReview={onReview} /> : null;
}

function DesktopRecoveryBanner({ onReview }: { onReview?: (run: InterruptedRun) => void }) {
  const { t } = useI18n();
  const [runs, setRuns] = useState<InterruptedRun[]>([]);

  const [error, setError] = useState<{ action: "load" | "dismiss"; message: string } | null>(null);
  const [busy, setBusy] = useState(true);
  const [revision, setRevision] = useState(0);
  const generation = useRef(0);
  const pending = useRef(true);
  const invalidate = useCallback(() => { generation.current++; }, []);

  useEffect(() => {
    const request = ++generation.current;
    getTransport().invoke<InterruptedRun[]>("interrupted_runs")
      .then(value => { if (request === generation.current) { setRuns(value); setError(null); } })
      .catch(error => { if (request === generation.current) setError({ action: "load", message: formatInvokeError(error) }); })
      .finally(() => { if (request === generation.current) { pending.current = false; setBusy(false); } });
    return invalidate;
  }, [revision, invalidate]);

  async function dismiss(id: string) {
    if (pending.current) return;
    pending.current = true; setBusy(true); setError(null);
    const request = ++generation.current;
    try {
      const remaining = await getTransport().invoke<InterruptedRun[]>("dismiss_interrupted_run", { runId: id });
      if (request === generation.current) setRuns(remaining);
    } catch (error) {
      if (request === generation.current) setError({ action: "dismiss", message: formatInvokeError(error) });
    } finally {
      if (request === generation.current) { pending.current = false; setBusy(false); }
    }
  }

  if (runs.length === 0 && !error) return null;

  return (
    <div
      className="rounded-md"
      style={{ background: "rgba(217,119,6,0.10)", border: "1px solid rgba(217,119,6,0.4)", padding: "var(--space-sm) var(--space-md)", margin: "var(--space-md) var(--space-lg) 0" }}
    >
      {error && <div role="alert" className="text-xs mb-2">{t(`recovery.${error.action}Failed`, { error: error.message })} <Button disabled={busy} onClick={() => { pending.current = true; setBusy(true); setRevision(value => value + 1); }}>{t("common.retry")}</Button></div>}
      {runs.length > 0 && <div className="flex flex-wrap items-center gap-2 mb-1">
        <AlertTriangle size={14} style={{ color: "#d97706" }} />
        <span className="text-xs font-semibold" style={{ color: "#d97706" }}>
          {runs.length === 1 ? t("recovery.recoveredOne") : t("recovery.recoveredMany", { n: runs.length })}
        </span>
        <span className="text-xs text-text-muted">{t("recovery.detail")}</span>
      </div>}
      <div className="flex flex-col gap-1 mt-1">
        {runs.map((r) => (
          <div key={r.run_id} className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono text-text-primary truncate">
              {shortPath(r.project)} / {r.target}
            </span>
            <span className="text-text-muted font-mono">{r.engine}</span>
            <span className="text-text-muted">· {t("recovery.started")} {new Date(r.started_at * 1000).toLocaleString()}</span>
            {onReview && <Button size="sm" onClick={() => onReview(r)}>{t("recovery.review")}</Button>}
            <button
              disabled={busy}
              onClick={() => void dismiss(r.run_id)}
              className="ml-auto inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-text-muted hover:text-text-primary hover:bg-surface-hover"
              title={t("recovery.dismiss")}
            >
              <X size={12} />
              {t("recovery.dismiss")}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
