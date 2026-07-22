import { useEffect, useRef, useState } from "react";
import { Check, ChevronDown, ChevronRight, Minus, RotateCcw } from "lucide-react";
import { usePipeline } from "../providers/pipeline";
import { useI18n } from "../i18nContext";
import {
  getInitialProgressPanelOpen,
  getProgressPercentage,
  getProgressPanelOpenAfterCompletionChange,
  getProgressPanelWidth,
} from "../lib/progressPanel";

export function ProgressPanel() {
  const { coreStages, reset } = usePipeline();
  const { t } = useI18n();
  const total = coreStages.length;
  const doneCount = coreStages.filter((c) => c.done).length;
  const complete = total > 0 && doneCount === total;
  const [open, setOpen] = useState(() => getInitialProgressPanelOpen(doneCount, total));
  const previousComplete = useRef(complete);
  const pct = getProgressPercentage(doneCount, total);

  useEffect(() => {
    setOpen((currentOpen) =>
      getProgressPanelOpenAfterCompletionChange(currentOpen, previousComplete.current, complete),
    );
    previousComplete.current = complete;
  }, [complete]);

  return (
    <div
      className="flex-shrink-0 border-l border-border flex flex-col"
      style={{
        width: getProgressPanelWidth(open),
        background: "var(--surface-secondary)",
        transition: "width 0.2s ease, background 0.2s ease",
      }}
    >
      {open ? (
        <div style={{ padding: "var(--space-md)" }}>
        <div
          className="rounded-lg flex flex-col"
          style={{ background: "var(--surface-primary)", border: "1px solid var(--border)", overflow: "hidden" }}
        >
          {/* Header */}
          <button
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-controls="progress-panel-details"
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
              <span className="text-sm font-semibold">{t("progress.title")}</span>
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

          {/* Steps -- the 4 core stages, matching the Fuzzing Workflow. */}
          {open && (
            <div id="progress-panel-details" style={{ padding: "0 6px 8px" }}>
              {coreStages.map((stage, i) => (
                <StepRow
                  key={stage.id}
                  index={i + 1}
                  label={t(`stage.${stage.id}`)}
                  done={stage.done}
                  skipped={stage.skipped}
                  current={stage.current}
                  // Show sub-progress for a multi-step stage that's underway.
                  subProgress={
                    stage.totalSteps > 1 && !stage.done
                      ? `${stage.doneSteps}/${stage.totalSteps}`
                      : undefined
                  }
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
            {t("progress.reset")}
          </button>
        )}
        </div>
      ) : (
        <button
          onClick={() => setOpen(true)}
          aria-label={complete ? t("info.allStagesComplete") : t("header.progress")}
          aria-expanded={open}
          className="flex flex-col items-center justify-center gap-1.5 w-full h-full transition-colors duration-150"
          style={{ background: "transparent", border: "none", color: "var(--text-primary)", cursor: "pointer", padding: "var(--space-sm)" }}
        >
          <span
            className="flex items-center justify-center rounded-full"
            style={{ width: "28px", height: "28px", background: complete ? "var(--accent)" : "var(--surface-active)", color: complete ? "var(--accent-contrast)" : "var(--text-muted)" }}
          >
            {complete ? <Check size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
          </span>
          <span className="text-xs font-semibold">{doneCount}/{total}</span>
        </button>
      )}
    </div>
  );
}

function StepRow({
  index,
  label,
  done,
  skipped,
  current,
  subProgress,
}: {
  index: number;
  label: string;
  done: boolean;
  skipped: boolean;
  current: boolean;
  subProgress?: string;
}) {
  // A skipped stage counts as done but renders as a muted dash, not a check.
  const marker = skipped ? <Minus size={12} /> : done ? <Check size={12} /> : index;
  return (
    <div className="flex items-center gap-2.5" style={{ padding: "6px 8px" }}>
      <span
        className="flex items-center justify-center rounded-full shrink-0"
        style={{
          width: "20px",
          height: "20px",
          fontSize: "11px",
          fontWeight: 600,
          background: skipped ? "var(--surface-active)" : done ? "var(--accent)" : "transparent",
          border: done || skipped ? "none" : `1px solid ${current ? "var(--accent)" : "var(--border)"}`,
          color: skipped
            ? "var(--text-muted)"
            : done
              ? "var(--accent-contrast)"
              : current
                ? "var(--accent)"
                : "var(--text-muted)",
        }}
      >
        {marker}
      </span>
      <span
        className="text-sm"
        style={{
          color: done || skipped ? "var(--text-muted)" : current ? "var(--text-primary)" : "var(--text-muted)",
          fontWeight: current ? 500 : 400,
          textDecoration: done && !skipped ? "line-through" : "none",
        }}
      >
        {label}
        {skipped && <span className="text-xs text-text-muted"> (skipped)</span>}
        {subProgress && !skipped && (
          <span className="text-xs text-text-muted"> · {subProgress}</span>
        )}
      </span>
    </div>
  );
}
