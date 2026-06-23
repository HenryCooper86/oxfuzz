// Info panel -- shows generated artifacts, campaign plan, and iteration loop.

import { FileCode, ListChecks, Repeat, Target as TargetIcon } from "lucide-react";
import { Badge } from "../ui/Badge";

export function InfoPanel() {
  const artifacts = [
    { name: "harness.c", type: "harness", size: "340b" },
    { name: "seed_empty_obj", type: "seed", size: "2b" },
    { name: "seed_array", type: "seed", size: "7b" },
    { name: "seed_string", type: "seed", size: "8b" },
    { name: "crash-abc123", type: "crash", size: "4b" },
  ];

  const planSteps = [
    { label: "Discover targets", done: true },
    { label: "Generate harness", done: true },
    { label: "Compile in sandbox", done: true },
    { label: "Generate seeds", done: true },
    { label: "Run fuzzer", done: false },
    { label: "Triage crashes", done: false },
  ];

  const loopStatus = { phase: "Run fuzzer", round: 1, target: "parse_value" };

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center gap-2 p-2 border-b border-border">
        <TargetIcon size={14} style={{ color: "var(--accent)" }} />
        <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Campaign Info</span>
      </div>

      <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
        {/* Generated Artifacts */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <FileCode size={11} /> Artifacts
          </div>
          {artifacts.map((a, i) => (
            <div key={i} className="flex items-center gap-2 py-1 text-xs">
              <span className="font-mono text-text-primary flex-1 truncate">{a.name}</span>
              <Badge variant={a.type === "crash" ? "error" : a.type === "harness" ? "accent" : "default"}>{a.type}</Badge>
              <span className="text-text-muted">{a.size}</span>
            </div>
          ))}
        </div>

        {/* Campaign Plan */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <ListChecks size={11} /> Campaign Plan
          </div>
          {planSteps.map((s, i) => (
            <div key={i} className="flex items-center gap-2 py-1 text-xs">
              <div
                className="flex items-center justify-center rounded-full shrink-0"
                style={{
                  width: "16px", height: "16px",
                  fontSize: "10px", fontWeight: 600,
                  background: s.done ? "rgba(111,207,151,0.15)" : "var(--surface-active)",
                  border: `1px solid ${s.done ? "var(--success)" : "var(--border)"}`,
                  color: s.done ? "var(--success)" : "var(--text-muted)",
                }}
              >
                {i + 1}
              </div>
              <span style={{ color: s.done ? "var(--text-primary)" : "var(--text-muted)", textDecoration: s.done ? "line-through" : "none" }}>
                {s.label}
              </span>
            </div>
          ))}
        </div>

        {/* Iteration Loop */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <Repeat size={11} /> Iteration Loop
          </div>
          <div className="surface-card p-2 text-xs">
            <div className="flex justify-between mb-1">
              <span className="text-text-muted">Phase:</span>
              <span className="text-accent">{loopStatus.phase}</span>
            </div>
            <div className="flex justify-between mb-1">
              <span className="text-text-muted">Round:</span>
              <span className="text-text-primary">{loopStatus.round}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Target:</span>
              <span className="text-text-primary font-mono">{loopStatus.target}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}