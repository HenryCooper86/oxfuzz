// Info panel -- shows campaign artifacts, the plan, and the iteration loop.
//
// Everything here is driven from real in-app state: artifact counts (compiled
// harness, corpus, crash inputs) come from the `artifact_summary` command for
// the active project/target; the plan and loop status from the shared pipeline
// progress, the selected target/engine, and the live RunOutput context.

import { useEffect, useState } from "react";
import { FileCode, ListChecks, Repeat, Target as TargetIcon } from "lucide-react";
import { getTransport } from "../../lib";
import { usePipeline } from "../../providers/PipelineContext";
import { useProject } from "../../providers/ProjectContext";
import { useTarget } from "../../providers/TargetContext";
import { useRunOutput } from "../../providers/RunOutputContext";

interface ArtifactSummary {
  harness_built: boolean;
  corpus_count: number;
  crash_count: number;
}

export function InfoPanel() {
  const { coreStages } = usePipeline();
  const { activeProject } = useProject();
  const { target, engine } = useTarget();
  const { running, lastTarget, lastEngine } = useRunOutput();
  const [artifacts, setArtifacts] = useState<ArtifactSummary | null>(null);

  const planSteps = coreStages.map((s) => ({
    label: s.label,
    done: s.done,
    skipped: s.skipped,
  }));

  const currentLabel = coreStages.find((s) => s.current)?.label ?? "All stages complete";
  const activeTarget = lastTarget || target;
  const activeEngine = lastEngine || engine;

  // Artifact counts for the active project/target; refresh while a run streams
  // (corpus/crashes grow) and when the target changes.
  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      if (!activeProject || !activeTarget) {
        if (!cancelled) setArtifacts(null);
        return;
      }
      getTransport()
        .invoke<ArtifactSummary>("artifact_summary", { project: activeProject, target: activeTarget })
        .then((d) => !cancelled && setArtifacts(d))
        .catch(() => !cancelled && setArtifacts(null));
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [activeProject, activeTarget, running]);

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center gap-2 p-2 border-b border-border">
        <TargetIcon size={14} style={{ color: "var(--accent)" }} />
        <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>Campaign Info</span>
      </div>

      <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
        {/* Generated Artifacts -- live counts for the active target */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <FileCode size={11} /> Artifacts
          </div>
          {artifacts ? (
            <div className="surface-card p-2 flex flex-col gap-1">
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Harness</span>
                <span style={{ color: artifacts.harness_built ? "var(--success)" : "var(--text-muted)" }}>
                  {artifacts.harness_built ? "compiled" : "not built"}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Corpus inputs</span>
                <span className="text-text-primary">{artifacts.corpus_count}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Crash inputs</span>
                <span style={{ color: artifacts.crash_count > 0 ? "var(--error)" : "var(--text-primary)" }}>
                  {artifacts.crash_count}
                </span>
              </div>
            </div>
          ) : (
            <div className="text-xs text-text-muted py-1">
              Pick a project and target to see artifacts.
            </div>
          )}
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
