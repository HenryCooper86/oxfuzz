// Diagnostics panel -- an LLM call timeline for harness generation / triage.
//
// There is no backend command feeding a real LLM/sandbox call trace yet
// (the desktop app exposes no `diagnostics` invoke, the web router has no
// endpoint), so rather than fabricate rows that look live, this renders an
// honest empty state until the trace is instrumented.

import { Activity } from "lucide-react";
import { Badge } from "../ui/Badge";

export function DiagnosticsPanel() {
  // No data source wired yet -- see module comment.
  const entries: never[] = [];

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center justify-between p-2 border-b border-border">
        <div className="flex items-center gap-2">
          <Activity size={14} style={{ color: "var(--accent)" }} />
          <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Diagnostics</span>
        </div>
        <Badge variant="default">{entries.length}</Badge>
      </div>

      <div className="flex-1 overflow-y-auto p-2 flex items-center justify-center">
        <div className="flex flex-col items-center text-center gap-1" style={{ opacity: 0.7 }}>
          <Activity size={20} className="text-text-muted" style={{ opacity: 0.5 }} />
          <span className="text-xs text-text-muted">No diagnostics yet</span>
          <span className="text-xs text-text-muted" style={{ opacity: 0.7 }}>Call tracing is not instrumented.</span>
        </div>
      </div>
    </div>
  );
}
