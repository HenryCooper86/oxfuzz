import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Check, Minus, Target, FileCode, Play, Bug, Database } from "lucide-react";
import { usePipeline, type StageId } from "../providers/PipelineContext";
import { DiscoverView } from "./DiscoverView";
import { HarnessView } from "./HarnessView";
import { RunView } from "./RunView";
import { TriageView } from "./TriageView";
import { CorpusView } from "./CorpusView";

// A unified, connected fuzzing flow: Discover -> Harness -> Run -> Triage ->
// Corpus presented as one stacked accordion rather than separate sidebar views.
// The stages share state through the existing contexts (project/target/run
// output/pipeline), so picking a target in Discover flows into Harness and Run
// without "jumping" between pages. The active stage auto-expands and scrolls
// into view as the pipeline advances.

type WorkflowStageId = "discover" | "harness" | "run" | "triage" | "corpus";

interface WorkflowStage {
  id: WorkflowStageId;
  n: number;
  label: string;
  hint: string;
  icon: React.ComponentType<{ size?: number }>;
  Component: React.ComponentType;
}

const STAGES: WorkflowStage[] = [
  { id: "discover", n: 1, label: "Discover Targets", hint: "Scan the project for fuzzable functions", icon: Target, Component: DiscoverView },
  { id: "harness", n: 2, label: "Generate Harness", hint: "Draft, compile, and seed a harness", icon: FileCode, Component: HarnessView },
  { id: "run", n: 3, label: "Run Fuzzer", hint: "Drive the engine and watch live progress", icon: Play, Component: RunView },
  { id: "triage", n: 4, label: "Triage Crashes", hint: "Ingest and classify any crashes", icon: Bug, Component: TriageView },
  { id: "corpus", n: 5, label: "Corpus", hint: "Seed, grow, and prune the corpus", icon: Database, Component: CorpusView },
];

/** Map the granular pipeline stage to the user-facing workflow stage. */
function viewForStage(stage: StageId | null): WorkflowStageId | null {
  switch (stage) {
    case "discover":
      return "discover";
    case "harness":
    case "compile":
    case "seeds":
      return "harness";
    case "run":
      return "run";
    case "triage":
      return "triage";
    default:
      return null; // all granular stages done
  }
}

export function WorkflowView() {
  const { isDone, isSkipped, currentStage } = usePipeline();
  const activeStage = viewForStage(currentStage) ?? "corpus";
  const [expanded, setExpanded] = useState<WorkflowStageId | null>(activeStage);
  const containerRef = useRef<HTMLDivElement>(null);
  const sectionRefs = useRef<Partial<Record<WorkflowStageId, HTMLElement | null>>>({});

  // Follow the pipeline: when the active stage advances, auto-expand it. This
  // is the React "adjust state during render" pattern (no syncing effect).
  const [prevActive, setPrevActive] = useState(activeStage);
  if (activeStage !== prevActive) {
    setPrevActive(activeStage);
    setExpanded(activeStage);
  }

  // Scroll the expanded stage into view so progress is always visible.
  useEffect(() => {
    if (expanded) {
      sectionRefs.current[expanded]?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [expanded]);

  const stageDone = (id: WorkflowStageId): boolean => {
    switch (id) {
      case "discover":
        return isDone("discover");
      case "harness":
        return isDone("seeds") || isDone("compile");
      case "run":
        return isDone("run");
      case "triage":
        return isDone("triage");
      case "corpus":
        return false; // optional, no required completion
    }
  };
  const stageSkipped = (id: WorkflowStageId): boolean => id === "triage" && isSkipped("triage");

  return (
    <div ref={containerRef} className="flex flex-col gap-3" style={{ animation: "fadeIn 0.2s ease" }}>
      <div>
        <h1 className="text-xl font-semibold">Fuzzing Workflow</h1>
        <p className="text-sm text-text-secondary mt-0.5">
          One connected flow: discover a target, generate a harness, run the fuzzer, then triage crashes and manage the corpus.
        </p>
      </div>

      {STAGES.map(({ id, n, label, hint, icon: Icon, Component }) => {
        const done = stageDone(id);
        const skipped = stageSkipped(id);
        const current = activeStage === id;
        const open = expanded === id;
        return (
          <section
            key={id}
            ref={(el) => {
              sectionRefs.current[id] = el;
            }}
            className="surface-card"
            style={{
              overflow: "hidden",
              borderLeft: `3px solid ${current ? "var(--accent)" : done ? "var(--success)" : "var(--border)"}`,
            }}
          >
            <button
              onClick={() => setExpanded(open ? null : id)}
              className="flex items-center justify-between w-full text-left"
              style={{ padding: "12px 14px", background: "transparent", border: "none", cursor: "pointer", color: "var(--text-primary)" }}
            >
              <span className="flex items-center gap-3">
                <StatusBadge n={n} done={done} skipped={skipped} current={current} />
                <span className="flex flex-col">
                  <span className="text-sm font-medium flex items-center gap-2">
                    <Icon size={14} />
                    {label}
                    {skipped && <span className="text-xs text-text-muted">(skipped)</span>}
                  </span>
                  <span className="text-xs text-text-muted">{hint}</span>
                </span>
              </span>
              {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
            </button>
            {open && (
              <div style={{ padding: "0 14px 16px", borderTop: "1px solid var(--border)" }}>
                <div style={{ paddingTop: "14px" }}>
                  <Component />
                </div>
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}

function StatusBadge({ n, done, skipped, current }: { n: number; done: boolean; skipped: boolean; current: boolean }) {
  const marker = skipped ? <Minus size={13} /> : done ? <Check size={13} /> : n;
  return (
    <span
      className="flex items-center justify-center rounded-full shrink-0"
      style={{
        width: "22px",
        height: "22px",
        fontSize: "11px",
        fontWeight: 600,
        background: skipped ? "var(--surface-active)" : done ? "var(--success)" : current ? "var(--accent)" : "transparent",
        border: done || skipped || current ? "none" : "1px solid var(--border)",
        color: done || current ? "var(--accent-contrast)" : "var(--text-muted)",
      }}
    >
      {marker}
    </span>
  );
}
