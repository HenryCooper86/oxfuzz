// Observability panel -- shows live fuzz-run progress plus provider stats.
//
// Active runs are driven from the shared RunOutput context (the same live
// stats the Run view streams). Provider-level metrics (token/cost/concurrency)
// have no backend feed yet, so that section shows an honest empty state rather
// than fabricated numbers.

import { Gauge, Container, Cpu } from "lucide-react";
import { Badge } from "../ui/Badge";
import { useRunOutput } from "../../providers/RunOutputContext";

export function ObservabilityPanel() {
  const { running, stats, summary, lastTarget, lastEngine } = useRunOutput();

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
        {/* Provider Stats -- no live feed yet */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Providers</div>
          <div className="surface-card p-2 text-xs text-text-muted">
            Provider metrics are not instrumented yet.
          </div>
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
