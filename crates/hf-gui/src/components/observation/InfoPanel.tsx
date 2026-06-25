// Info panel -- shows the campaign plan and iteration loop.
//
// The plan and loop status are driven from real in-app state: the shared
// pipeline progress (which stages are done/skipped), the selected target/
// engine, and the live RunOutput context. Generated-artifact tracking has no
// backend feed yet, so that section shows an honest empty state instead of a
// fabricated file list.

import { FileCode, ListChecks, Repeat, Target as TargetIcon } from "lucide-react";
import { PIPELINE_STAGES, usePipeline } from "../../providers/PipelineContext";
import { useTarget } from "../../providers/TargetContext";
import { useRunOutput } from "../../providers/RunOutputContext";

export function InfoPanel() {
  const { isDone, isSkipped, currentStage } = usePipeline();
  const { target, engine } = useTarget();
  const { running, lastTarget, lastEngine } = useRunOutput();

  const planSteps = PIPELINE_STAGES.map((s) => ({
    label: s.label,
    done: isDone(s.id),
    skipped: isSkipped(s.id),
  }));

  const currentLabel = currentStage
    ? PIPELINE_STAGES.find((s) => s.id === currentStage)?.label ?? "—"
    : "All stages complete";
  const activeTarget = lastTarget || target;
  const activeEngine = lastEngine || engine;

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center gap-2 p-2 border-b border-border">
        <TargetIcon size={14} style={{ color: "var(--accent)" }} />
        <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Campaign Info</span>
      </div>

      <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
        {/* Generated Artifacts -- no backend feed yet */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <FileCode size={11} /> Artifacts
          </div>
          <div className="text-xs text-text-muted py-1">Artifact tracking is not instrumented yet.</div>
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
              <span style={{ color: s.done ? "var(--text-primary)" : "var(--text-muted)", textDecoration: s.done && !s.skipped ? "line-through" : "none" }}>
                {s.label}
              </span>
              {s.skipped && <span className="text-text-muted" style={{ fontSize: "10px" }}>(skipped)</span>}
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
              <span className="text-accent">{running ? "Run fuzzer" : currentLabel}</span>
            </div>
            <div className="flex justify-between mb-1">
              <span className="text-text-muted">Engine:</span>
              <span className="text-text-primary font-mono">{activeEngine || "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Target:</span>
              <span className="text-text-primary font-mono">{activeTarget || "—"}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
