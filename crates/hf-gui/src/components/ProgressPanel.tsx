import { useState } from "react";
import { Check, ChevronDown, ChevronRight, RotateCcw } from "lucide-react";
import { usePipeline, PIPELINE_STAGES, type StageId } from "../providers/PipelineContext";

export function ProgressPanel() {
  const { isDone, currentStage, completed, reset } = usePipeline();
  const [open, setOpen] = useState(true);
  const total = PIPELINE_STAGES.length;
  const doneCount = completed.length;
  const pct = Math.round((doneCount / total) * 100);

  return (
    <div
      className="flex-shrink-0 border-l border-border flex flex-col"
      style={{ width: "280px", background: "var(--surface-secondary)", animation: "fadeIn 0.15s ease" }}
    >
      <div style={{ padding: "var(--space-md)" }}>
        <div
          className="rounded-lg flex flex-col"
          style={{ background: "var(--surface-primary)", border: "1px solid var(--border)", overflow: "hidden" }}
        >
          {/* Header */}
          <button
            onClick={() => setOpen((o) => !o)}
            className="flex items-center justify-between w-full transition-colors duration-150"
            style={{
              padding: "10px 12px",
              background: "transparent",
              border: "none",
              cursor: "pointer",
              color: "var(--text-primary)",
            }}
          >
            <span className="flex items-center gap-2">
              <span className="text-sm font-semibold">Progress</span>
              <span className="text-xs text-text-muted">
                {doneCount}/{total}
              </span>
            </span>
            {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
          </button>

          {/* Progress bar */}
          <div style={{ padding: "0 12px 10px" }}>
            <div style={{ height: "4px", borderRadius: "999px", background: "var(--surface-active)", overflow: "hidden" }}>
              <div
                style={{
                  width: `${pct}%`,
                  height: "100%",
                  background: "var(--accent)",
                  transition: "width 0.3s ease",
                }}
              />
            </div>
          </div>

          {/* Steps */}
          {open && (
            <div style={{ padding: "0 6px 8px" }}>
              {PIPELINE_STAGES.map((stage, i) => (
                <StepRow
                  key={stage.id}
                  index={i + 1}
                  label={stage.label}
                  done={isDone(stage.id as StageId)}
                  current={currentStage === stage.id}
                />
              ))}
            </div>
          )}
        </div>

        {doneCount > 0 && (
          <button
            onClick={reset}
            className="flex items-center gap-1.5 mt-3 text-xs transition-colors duration-150"
            style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: "2px" }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text-secondary)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
          >
            <RotateCcw size={12} />
            Reset progress
          </button>
        )}
      </div>
    </div>
  );
}

function StepRow({
  index,
  label,
  done,
  current,
}: {
  index: number;
  label: string;
  done: boolean;
  current: boolean;
}) {
  return (
    <div className="flex items-center gap-2.5" style={{ padding: "6px 8px" }}>
      <span
        className="flex items-center justify-center rounded-full shrink-0"
        style={{
          width: "20px",
          height: "20px",
          fontSize: "11px",
          fontWeight: 600,
          background: done ? "var(--accent)" : "transparent",
          border: done ? "none" : `1px solid ${current ? "var(--accent)" : "var(--border)"}`,
          color: done ? "var(--accent-contrast)" : current ? "var(--accent)" : "var(--text-muted)",
        }}
      >
        {done ? <Check size={12} /> : index}
      </span>
      <span
        className="text-sm"
        style={{
          color: done ? "var(--text-muted)" : current ? "var(--text-primary)" : "var(--text-muted)",
          fontWeight: current ? 500 : 400,
          textDecoration: done ? "line-through" : "none",
        }}
      >
        {label}
      </span>
    </div>
  );
}
