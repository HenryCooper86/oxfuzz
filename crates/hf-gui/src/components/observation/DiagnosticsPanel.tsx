// Diagnostics panel -- shows LLM call timeline for harness generation / triage.

import { useState } from "react";
import { Activity, ChevronRight, ChevronDown, Copy, Clock } from "lucide-react";
import { Badge } from "../ui/Badge";
import { Separator } from "../ui/Separator";

interface DiagEntry {
  id: string;
  timestamp: string;
  type: string;
  duration_ms: number;
  tokens_in: number;
  tokens_out: number;
  cost: number;
  status: "ok" | "error";
  summary: string;
  detail?: string;
}

const mockEntries: DiagEntry[] = [
  { id: "1", timestamp: "10:34:12", type: "llm.complete", duration_ms: 1200, tokens_in: 500, tokens_out: 120, cost: 0.003, status: "ok", summary: "Harness draft for parse_value", detail: "Generated LLVMFuzzerTestOneInput scaffold" },
  { id: "2", timestamp: "10:34:15", type: "sandbox.compile", duration_ms: 3000, tokens_in: 0, tokens_out: 0, cost: 0, status: "ok", summary: "Compiled fuzz_parse_value in Docker" },
  { id: "3", timestamp: "10:34:20", type: "engine.run", duration_ms: 15000, tokens_in: 0, tokens_out: 0, cost: 0, status: "ok", summary: "libFuzzer: 35 edges, 3 crashes in 15s" },
];

export function DiagnosticsPanel() {
  const [expanded, setExpanded] = useState<string | null>(null);
  const entries = mockEntries;

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center justify-between p-2 border-b border-border">
        <div className="flex items-center gap-2">
          <Activity size={14} style={{ color: "var(--accent)" }} />
          <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Diagnostics</span>
        </div>
        <Badge variant="accent">{entries.length}</Badge>
      </div>

      <div className="flex-1 overflow-y-auto p-1">
        {entries.map((e) => (
          <div key={e.id} className="mb-1">
            <button
              onClick={() => setExpanded(expanded === e.id ? null : e.id)}
              className="flex items-center gap-2 w-full text-left rounded-md p-2 transition-colors duration-100 hover:bg-surface-hover"
              style={{ border: "none", background: "transparent", cursor: "pointer" }}
            >
              {expanded === e.id ? <ChevronDown size={12} className="text-text-muted shrink-0" /> : <ChevronRight size={12} className="text-text-muted shrink-0" />}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-text-primary truncate">{e.type}</span>
                  {e.status === "ok" ? <Badge variant="success">ok</Badge> : <Badge variant="error">err</Badge>}
                </div>
                <span className="text-xs text-text-muted truncate block">{e.summary}</span>
              </div>
              <div className="flex flex-col items-end shrink-0">
                <span className="text-xs text-text-muted flex items-center gap-1"><Clock size={9} />{e.duration_ms}ms</span>
                {e.cost > 0 && <span className="text-xs text-text-muted">${e.cost.toFixed(4)}</span>}
              </div>
            </button>
            {expanded === e.id && e.detail && (
              <div className="ml-6 mt-1 mb-2 p-2 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-text-muted">Detail</span>
                  <button onClick={() => navigator.clipboard.writeText(e.detail ?? "")} className="text-text-muted hover:text-text-primary" style={{ background: "transparent", border: "none", cursor: "pointer" }}>
                    <Copy size={11} />
                  </button>
                </div>
                <pre className="text-xs text-text-secondary" style={{ fontFamily: "var(--font-mono)", whiteSpace: "pre-wrap" }}>{e.detail}</pre>
                <Separator />
                <div className="flex gap-3 mt-1 text-xs text-text-muted">
                  <span>in: {e.tokens_in}</span>
                  <span>out: {e.tokens_out}</span>
                  <span>cost: ${e.cost.toFixed(4)}</span>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}