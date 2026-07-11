import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Check, Minus, Target, FileCode, Play, Bug, Database, FolderOpen } from "lucide-react";
import { pickFolder } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline, type StageId } from "../providers/PipelineContext";
import type { ViewType } from "../types";
import { DiscoverView } from "./DiscoverView";
import { HarnessView } from "./HarnessView";
import { RunView } from "./RunView";
import { TriageView } from "./TriageView";
import { CorpusView } from "./CorpusView";
import { ViewHeader } from "../components/ui";

// A unified, connected fuzzing flow: choose a project, then Discover -> Harness
// -> Run -> Triage as one stacked accordion (no jumping between sidebar pages).
// Corpus is a continuous resource (seeded during Harness, grown across runs), so
// it sits below the linear flow as an ongoing tool rather than a final "step".
// Stages share the existing contexts, so a target picked in Discover flows into
// Harness and Run, and a run's crashes flow into Triage.

type CoreStageId = "discover" | "harness" | "run" | "triage";

interface CoreStage {
  id: CoreStageId;
  n: number;
  label: string;
  hint: string;
  icon: React.ComponentType<{ size?: number }>;
  // Embedded stage views accept an optional navigate callback; in the workflow
  // it expands the target section (e.g. Run's "regenerate harness" -> Harness).
  // `stepPrefix` lets a stage that has its own internal steps (Harness) render
  // them as sub-steps of this stage's number instead of a competing 1..N.
  Component: React.ComponentType<{
    embedded?: boolean;
    onNavigate?: (view: ViewType) => void;
    stepPrefix?: string;
  }>;
}

const CORE_STAGES: CoreStage[] = [
  { id: "discover", n: 1, label: "Discover Targets", hint: "Scan the project for fuzzable functions", icon: Target, Component: DiscoverView },
  { id: "harness", n: 2, label: "Generate Harness", hint: "Draft, compile, and seed a harness", icon: FileCode, Component: HarnessView },
  { id: "run", n: 3, label: "Run Fuzzer", hint: "Drive the engine and watch live progress", icon: Play, Component: RunView },
  { id: "triage", n: 4, label: "Triage Crashes", hint: "Reproduce, classify, and dedup crashes", icon: Bug, Component: TriageView },
];

/** Map the granular pipeline stage to the user-facing core stage. */
function viewForStage(stage: StageId | null): CoreStageId | null {
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
      return null;
  }
}

type SectionId = CoreStageId | "corpus";

export function WorkflowView() {
  const { activeProject, recentProjects, setActiveProject } = useProject();
  const { isDone, isSkipped, currentStage } = usePipeline();
  const activeStage: CoreStageId = viewForStage(currentStage) ?? "triage";
  const [expanded, setExpanded] = useState<SectionId | null>(activeStage);
  const sectionRefs = useRef<Partial<Record<SectionId, HTMLElement | null>>>({});
  const gated = !activeProject;

  // Auto-expand the active stage as the pipeline advances (adjust-during-render).
  const [prevActive, setPrevActive] = useState(activeStage);
  if (!gated && activeStage !== prevActive) {
    setPrevActive(activeStage);
    setExpanded(activeStage);
  }

  useEffect(() => {
    if (expanded) {
      sectionRefs.current[expanded]?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [expanded]);

  async function chooseProject() {
    const path = await pickFolder();
    if (path) setActiveProject(path);
  }

  const stageDone = (id: CoreStageId): boolean => {
    switch (id) {
      case "discover":
        return isDone("discover");
      case "harness":
        return isDone("seeds") || isDone("compile");
      case "run":
        return isDone("run");
      case "triage":
        return isDone("triage");
    }
  };

  const projectName = activeProject ? activeProject.split("/").filter(Boolean).pop() : null;

  return (
    <div className="flex flex-col gap-3" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader
        title="Fuzzing Workflow"
        description="One connected flow: choose a project, discover a target, generate a harness, run the fuzzer, then triage crashes."
      />

      {/* Project gate -- everything below runs in the chosen project's workspace. */}
      <section className="surface-card" style={{ padding: "12px 14px", borderLeft: `3px solid ${activeProject ? "var(--success)" : "var(--accent)"}` }}>
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <FolderOpen size={16} style={{ color: activeProject ? "var(--success)" : "var(--accent)" }} />
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-medium">{projectName ?? "No project selected"}</span>
              <span className="text-xs text-text-muted truncate" style={{ fontFamily: activeProject ? "var(--font-mono)" : undefined }}>
                {activeProject || "Choose a project folder to begin — every stage runs in its workspace."}
              </span>
            </div>
          </div>
          <button
            onClick={chooseProject}
            className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md"
            style={{ background: activeProject ? "var(--surface-primary)" : "var(--accent)", color: activeProject ? "var(--text-secondary)" : "var(--accent-contrast)", border: activeProject ? "1px solid var(--border)" : "none" }}
          >
            <FolderOpen size={13} />
            {activeProject ? "Change" : "Choose Folder…"}
          </button>
        </div>
        {gated && recentProjects.length > 0 && (
          <div className="mt-3 flex flex-col gap-1">
            <span className="text-xs text-text-muted">Recent projects</span>
            {recentProjects.slice(0, 5).map((p) => (
              <button
                key={p}
                onClick={() => setActiveProject(p)}
                className="text-left text-xs px-2 py-1.5 rounded-md text-text-secondary hover:bg-surface-hover hover:text-text-primary truncate"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {p}
              </button>
            ))}
          </div>
        )}
      </section>

      {/* Core linear stages */}
      {CORE_STAGES.map(({ id, n, label, hint, icon: Icon, Component }) => {
        const done = stageDone(id);
        const skipped = id === "triage" && isSkipped("triage");
        const current = !gated && activeStage === id;
        const open = !gated && expanded === id;
        return (
          <section
            key={id}
            ref={(el) => {
              sectionRefs.current[id] = el;
            }}
            className="surface-card"
            style={{
              overflow: "hidden",
              opacity: gated ? 0.5 : 1,
              borderLeft: `3px solid ${current ? "var(--accent)" : done ? "var(--success)" : "var(--border)"}`,
            }}
          >
            <button
              onClick={() => !gated && setExpanded(open ? null : id)}
              disabled={gated}
              className="flex items-center justify-between w-full text-left"
              style={{ padding: "12px 14px", background: "transparent", border: "none", cursor: gated ? "not-allowed" : "pointer", color: "var(--text-primary)" }}
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
                  <Component
                    embedded
                    stepPrefix={String(n)}
                    onNavigate={(view) => {
                      // Stay in the workflow: expand the requested stage's
                      // section (its ViewType id matches the section id).
                      if (!gated) setExpanded(view as SectionId);
                    }}
                  />
                </div>
              </div>
            )}
          </section>
        );
      })}

      {/* Corpus -- an ongoing resource, not a numbered step. */}
      <div className="mt-1 mb-1 text-xs text-text-muted uppercase" style={{ letterSpacing: "0.08em" }}>
        Ongoing
      </div>
      <section
        ref={(el) => {
          sectionRefs.current.corpus = el;
        }}
        className="surface-card"
        style={{ overflow: "hidden", opacity: gated ? 0.5 : 1, borderLeft: "3px solid var(--border)" }}
      >
        <button
          onClick={() => !gated && setExpanded(expanded === "corpus" ? null : "corpus")}
          disabled={gated}
          className="flex items-center justify-between w-full text-left"
          style={{ padding: "12px 14px", background: "transparent", border: "none", cursor: gated ? "not-allowed" : "pointer", color: "var(--text-primary)" }}
        >
          <span className="flex items-center gap-3">
            <span className="flex items-center justify-center rounded-full shrink-0" style={{ width: "22px", height: "22px", border: "1px solid var(--border)", color: "var(--text-muted)" }}>
              <Database size={12} />
            </span>
            <span className="flex flex-col">
              <span className="text-sm font-medium">Corpus</span>
              <span className="text-xs text-text-muted">Seed, grow, and prune — used throughout the loop, not a final step</span>
            </span>
          </span>
          {expanded === "corpus" ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
        </button>
        {!gated && expanded === "corpus" && (
          <div style={{ padding: "0 14px 16px", borderTop: "1px solid var(--border)" }}>
            <div style={{ paddingTop: "14px" }}>
              <CorpusView embedded />
            </div>
          </div>
        )}
      </section>
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
