// Surfaces fuzz runs that were interrupted by a prior crash/quit (detected on
// startup from the persistent run journal). The campaign's crashes/corpus on
// disk are intact; the user can re-run from the Run view, or dismiss here.

import { useEffect, useState } from "react";
import { AlertTriangle, X } from "lucide-react";
import { getTransport } from "../lib";
import { useI18n } from "../i18n";

interface InterruptedRun {
  run_id: string;
  project: string;
  target: string;
  engine: string;
  started_at: number;
}

const shortPath = (p: string) => p.split("/").filter(Boolean).pop() || p;

export function RecoveryBanner() {
  const { t } = useI18n();
  const [runs, setRuns] = useState<InterruptedRun[]>([]);

  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<InterruptedRun[]>("interrupted_runs")
      .then((r) => !cancelled && setRuns(r))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  async function dismiss(id: string) {
    try {
      setRuns(await getTransport().invoke<InterruptedRun[]>("dismiss_interrupted_run", { runId: id }));
    } catch {
      /* best-effort */
    }
  }

  if (runs.length === 0) return null;

  return (
    <div
      className="rounded-md"
      style={{ background: "rgba(217,119,6,0.10)", border: "1px solid rgba(217,119,6,0.4)", padding: "var(--space-sm) var(--space-md)", margin: "var(--space-md) var(--space-lg) 0" }}
    >
      <div className="flex items-center gap-2 mb-1">
        <AlertTriangle size={14} style={{ color: "#d97706" }} />
        <span className="text-xs font-semibold" style={{ color: "#d97706" }}>
          {runs.length === 1 ? t("recovery.recoveredOne") : t("recovery.recoveredMany", { n: runs.length })}
        </span>
        <span className="text-xs text-text-muted">{t("recovery.detail")}</span>
      </div>
      <div className="flex flex-col gap-1 mt-1">
        {runs.map((r) => (
          <div key={r.run_id} className="flex items-center gap-2 text-xs">
            <span className="font-mono text-text-primary truncate">
              {shortPath(r.project)} / {r.target}
            </span>
            <span className="text-text-muted font-mono">{r.engine}</span>
            <span className="text-text-muted">· {t("recovery.started")} {new Date(r.started_at * 1000).toLocaleString()}</span>
            <button
              onClick={() => dismiss(r.run_id)}
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
