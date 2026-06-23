// Observability panel -- shows provider stats + active fuzz runs.

import { Gauge, Container, Cpu } from "lucide-react";
import { Badge } from "../ui/Badge";

export function ObservabilityPanel() {
  const providers = [
    { id: "openai", model: "gpt-4o", concurrency: 1, max: 3, requests: 5, errors: 0, tokens: 1850, cost: 0.034 },
  ];

  const activeRuns = [
    { target: "parse_value", engine: "libFuzzer", execs: 5000, edges: 35, crashes: 0, duration: "12s" },
  ];

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center gap-2 p-2 border-b border-border">
        <Gauge size={14} style={{ color: "var(--accent)" }} />
        <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Observability</span>
      </div>

      <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
        {/* Provider Stats */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Providers</div>
          {providers.map((p) => (
            <div key={p.id} className="surface-card p-2 mb-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-text-primary">{p.id}</span>
                <Badge variant="success">active</Badge>
              </div>
              <div className="text-xs text-text-muted mb-1">{p.model}</div>
              {/* Concurrency bar */}
              <div className="flex items-center gap-1 mb-1">
                <span className="text-xs text-text-muted">concurrency</span>
                <div className="flex-1 rounded-sm overflow-hidden" style={{ height: "4px", background: "var(--surface-active)" }}>
                  <div style={{ width: `${(p.concurrency / p.max) * 100}%`, height: "100%", background: "var(--accent)" }} />
                </div>
                <span className="text-xs text-text-muted">{p.concurrency}/{p.max}</span>
              </div>
              <div className="flex justify-between text-xs text-text-muted">
                <span>req: {p.requests}</span>
                <span>tok: {p.tokens.toLocaleString()}</span>
                <span>cost: ${p.cost.toFixed(3)}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Active Fuzz Runs */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <Cpu size={11} /> Active Runs
          </div>
          {activeRuns.map((r, i) => (
            <div key={i} className="surface-card p-2 mb-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-text-primary">{r.target}</span>
                <Badge variant="accent">{r.engine}</Badge>
              </div>
              <div className="flex items-center gap-1 mb-1">
                <Container size={9} className="text-text-muted" />
                <div className="flex-1 rounded-sm overflow-hidden" style={{ height: "4px", background: "var(--surface-active)" }}>
                  <div style={{ width: "60%", height: "100%", background: "var(--success)" }} />
                </div>
                <span className="text-xs text-text-muted">{r.duration}</span>
              </div>
              <div className="flex justify-between text-xs text-text-muted">
                <span>execs/s: {r.execs}</span>
                <span>edges: {r.edges}</span>
                <span style={{ color: r.crashes > 0 ? "var(--error)" : "var(--text-muted)" }}>crashes: {r.crashes}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}