// Diagnostics panel -- live LLM cost/usage for this session, backed by
// hf-service::diagnostics (the DiagnosticsRecorder that every LLM call -- rank,
// harness drafting, triage bug reports, chat -- reports into). Totals are
// in-memory and cover the current app session.

import { useCallback, useEffect, useState } from "react";
import { Activity, Loader2, RotateCw } from "lucide-react";
import { getTransport } from "../../lib";
import { Badge } from "../ui/Badge";

interface ModelCost {
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
}
interface CostSummary {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  by_model: ModelCost[];
}

const fmtTokens = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(1)}k` : `${n}`);
const fmtCost = (n: number) => (n > 0 ? `$${n.toFixed(n < 0.01 ? 4 : 2)}` : "$0");

export function DiagnosticsPanel() {
  const [data, setData] = useState<CostSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    getTransport()
      .invoke<CostSummary>("diagnostics_cost_summary")
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, []);

  // Initial load + light polling so cost updates as the agent works.
  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      getTransport()
        .invoke<CostSummary>("diagnostics_cost_summary")
        .then((d) => !cancelled && setData(d))
        .catch(() => !cancelled && setData(null))
        .finally(() => !cancelled && setLoading(false));
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const empty = !data || data.calls === 0;

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center justify-between p-2 border-b border-border">
        <div className="flex items-center gap-2">
          <Activity size={14} style={{ color: "var(--accent)" }} />
          <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Diagnostics</span>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="default">{data?.calls ?? 0}</Badge>
          <button onClick={load} className="text-text-muted hover:text-text-primary" title="Refresh">
            {loading ? <Loader2 size={12} className="animate-spin" /> : <RotateCw size={12} />}
          </button>
        </div>
      </div>

      {empty ? (
        <div className="flex-1 overflow-y-auto p-2 flex items-center justify-center">
          <div className="flex flex-col items-center text-center gap-1" style={{ opacity: 0.7 }}>
            <Activity size={20} className="text-text-muted" style={{ opacity: 0.5 }} />
            <span className="text-xs text-text-muted">No LLM calls yet</span>
            <span className="text-xs text-text-muted" style={{ opacity: 0.7 }}>Rank, harness, triage, and chat are tracked here.</span>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
          {/* Session totals */}
          <div className="grid grid-cols-3 gap-2">
            <Stat label="Cost" value={fmtCost(data.cost_usd)} accent />
            <Stat label="Calls" value={`${data.calls}`} />
            <Stat label="Tokens" value={fmtTokens(data.input_tokens + data.output_tokens)} />
          </div>

          {/* Per-model breakdown */}
          <div>
            <div className="text-xs text-text-muted uppercase mb-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>By Model</div>
            <div className="flex flex-col">
              {data.by_model.map((m) => (
                <div key={m.model} className="flex items-center gap-2 py-1.5 border-b border-border last:border-0 text-xs">
                  <span className="font-mono flex-1 truncate" title={m.model}>{m.model}</span>
                  <span className="text-text-muted">{m.calls}×</span>
                  <span className="text-text-muted font-mono" style={{ minWidth: "52px", textAlign: "right" }}>
                    {fmtTokens(m.input_tokens + m.output_tokens)} tok
                  </span>
                  <span className="font-mono" style={{ minWidth: "56px", textAlign: "right", color: m.cost_usd > 0 ? "var(--accent)" : "var(--text-muted)" }}>
                    {fmtCost(m.cost_usd)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="rounded-md p-2" style={{ background: "var(--surface-code)" }}>
      <div className="text-xs text-text-muted">{label}</div>
      <div className="text-sm font-mono font-semibold" style={{ color: accent ? "var(--accent)" : "var(--text-primary)" }}>{value}</div>
    </div>
  );
}
