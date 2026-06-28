// Observability panel -- live provider health plus fuzz-run progress.
//
// Provider health (freeze state, in-flight + total requests, errors) comes from
// the provider pool via the `provider_statuses` command. Active runs are driven
// from the shared RunOutput context (the same live stats the Run view streams).

import { useEffect, useState } from "react";
import { Gauge, Container, Cpu } from "lucide-react";
import { Badge } from "../ui/Badge";
import { getTransport } from "../../lib";
import { useRunOutput } from "../../providers/RunOutputContext";

interface ProviderStatus {
  id: string;
  frozen: boolean;
  freeze_reason: string | null;
  active_requests: number;
  total_requests: number;
  total_errors: number;
}

export function ObservabilityPanel() {
  const { running, stats, summary, lastTarget, lastEngine } = useRunOutput();
  const [providers, setProviders] = useState<ProviderStatus[]>([]);

  // Poll provider health so freeze/error state stays current as the agent works.
  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      getTransport()
        .invoke<ProviderStatus[]>("provider_statuses")
        .then((d) => !cancelled && setProviders(d ?? []))
        .catch(() => !cancelled && setProviders([]));
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  // Show a card while a run streams, and keep the last completed run visible.
  const hasRun = running || summary !== null;
  const liveStats = running ? stats : summary ?? stats;

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center gap-2 p-2 border-b border-border">
        <Gauge size={14} style={{ color: "var(--accent)" }} />
        <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Observability</span>
      </div>

      <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
        {/* Provider health -- live from the provider pool */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Providers</div>
          {providers.length === 0 ? (
            <div className="surface-card p-2 text-xs text-text-muted">
              No LLM provider configured.
            </div>
          ) : (
            providers.map((p) => (
              <div key={p.id} className="surface-card p-2 mb-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono text-text-primary">{p.id}</span>
                  <Badge variant={p.frozen ? "error" : "success"}>{p.frozen ? "frozen" : "ready"}</Badge>
                </div>
                <div className="flex justify-between text-xs text-text-muted">
                  <span>in-flight: {p.active_requests}</span>
                  <span>reqs: {p.total_requests}</span>
                  <span style={{ color: p.total_errors > 0 ? "var(--error)" : "var(--text-muted)" }}>
                    errs: {p.total_errors}
                  </span>
                </div>
                {p.frozen && p.freeze_reason && (
                  <div className="text-xs mt-1" style={{ color: "var(--error)" }}>{p.freeze_reason}</div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Active Fuzz Runs */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <Cpu size={11} /> Active Runs
          </div>
          {hasRun ? (
            <div className="surface-card p-2 mb-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-text-primary">{lastTarget || "—"}</span>
                <Badge variant={running ? "success" : "default"}>{lastEngine || "fuzzer"}</Badge>
              </div>
              <div className="flex items-center gap-1 mb-1">
                <Container size={9} className="text-text-muted" />
                <div className="flex-1 rounded-sm overflow-hidden" style={{ height: "4px", background: "var(--surface-active)" }}>
                  <div style={{ width: "100%", height: "100%", background: running ? "var(--success)" : "var(--text-muted)" }} />
                </div>
                <span className="text-xs text-text-muted">{running ? "running" : "done"}</span>
              </div>
              <div className="flex justify-between text-xs text-text-muted">
                <span>execs/s: {liveStats.execs}</span>
                <span>edges: {liveStats.edges}</span>
                <span style={{ color: liveStats.crashes > 0 ? "var(--error)" : "var(--text-muted)" }}>crashes: {liveStats.crashes}</span>
              </div>
            </div>
          ) : (
            <div className="surface-card p-2 text-xs text-text-muted">
              No active runs. Start a campaign in the Run view.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
