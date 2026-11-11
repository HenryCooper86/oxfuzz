import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Check, Minus, Crosshair, FileCode, Play, Bug, Database } from "lucide-react";
import { useProject } from "../providers/project";
import { usePipeline } from "../providers/pipeline";
import type { ViewType } from "../types";
import { DiscoverView } from "./DiscoverView";
import { HarnessView } from "./HarnessView";
import { RunView } from "./RunView";
import { TriageView } from "./TriageView";
const CorpusView = lazy(() => import("./CorpusView").then(module => ({ default: module.CorpusView })));
import { ViewHeader, Button } from "../components/ui";
import { ActiveProjectBar } from "../components/ActiveProjectBar";
import { OneClickFuzz, type HarnessScope, type OneClickApi } from "../components/OneClickFuzz";
import { useI18n } from "../i18nContext";

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
  icon: React.ComponentType<{ size?: number }>;
  // Embedded stage views accept an optional navigate callback; in the workflow
  // it expands the target section (e.g. Run's "regenerate harness" -> Harness).
  // `stepPrefix` lets a stage that has its own internal steps (Harness) render
  // them as sub-steps of this stage's number instead of a competing 1..N.
  Component: React.ComponentType<{
    embedded?: boolean;
    onNavigate?: (view: ViewType) => void;
    stepPrefix?: string;
    // Reported by the Harness stage when a person approves a harness.
    onApproved?: (scope: HarnessScope) => void;
  }>;
}

// Labels and hints are looked up by id via t(`workflow.${id}Label`/`Hint`) at
// render time; keeping them out of this module-scope array avoids calling the
// i18n hook outside a component.
const CORE_STAGES: CoreStage[] = [
  { id: "discover", n: 1, icon: Crosshair, Component: DiscoverView },
  { id: "harness", n: 2, icon: FileCode, Component: HarnessView },
  { id: "run", n: 3, icon: Play, Component: RunView },
  { id: "triage", n: 4, icon: Bug, Component: TriageView },
];

type SectionId = CoreStageId | "corpus";
const SECTION_IDS: readonly SectionId[] = ["discover", "harness", "run", "triage", "corpus"];
const isSection = (view: ViewType): view is SectionId => (SECTION_IDS as readonly string[]).includes(view);

export function WorkflowView({ onNavigate }: { onNavigate?: (view: ViewType) => void } = {}) {
  const { t } = useI18n();
  const { activeProject } = useProject();
  // Single source of truth for stage state: the pipeline's rolled-up core
  // stages, so the Workflow and the Progress panel always agree.
  const { coreStages } = usePipeline();
  const coreById = useMemo(
    () => Object.fromEntries(coreStages.map((c) => [c.id, c])),
    [coreStages],
  );
  const allComplete = coreStages.every((c) => c.done);
  // The active stage is the first not-done core stage; when everything is done
  // nothing is highlighted (a finished campaign shouldn't mark Triage "current").
  const activeStage: CoreStageId = (coreStages.find((c) => c.current)?.id ?? "triage") as CoreStageId;
  const [expanded, setExpanded] = useState<SectionId | null>(activeStage);
  // The open stage belongs to one project. Opening another project starts at
  // that project's own current stage, not wherever the last one was left.
  const [expandedFor, setExpandedFor] = useState(activeProject);
  if (expandedFor !== activeProject) {
    setExpandedFor(activeProject);
    setExpanded(activeStage);
  }
  const sectionRefs = useRef<Partial<Record<SectionId, HTMLElement | null>>>({});
  const gated = !activeProject;

  useEffect(() => {
    if (expanded) {
      sectionRefs.current[expanded]?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [expanded]);

  // Navigation requested by an embedded stage. A stage this workflow contains is
  // expanded in place, "workflow" re-opens the current stage, and any other view
  // (Run History, Settings, ...) leaves the workflow through the app navigation.
  function navigateFromStage(view: ViewType) {
    if (view !== "workflow" && !isSection(view)) {
      onNavigate?.(view);
      return;
    }
    if (gated) return;
    const section = view === "workflow" ? activeStage : view;
    setExpanded(section);
    sectionRefs.current[section]?.querySelector("button")?.focus();
  }

  // One-click fuzzing opens stages as it advances and hears about approvals.
  const oneClickApi = useRef<OneClickApi | null>(null);
  const setOneClickApi = useCallback((api: OneClickApi | null) => { oneClickApi.current = api; }, []);
  const openSection = useCallback((section: SectionId) => {
    setExpanded(section);
    sectionRefs.current[section]?.querySelector("button")?.focus();
  }, []);

  const stageDone = (id: CoreStageId): boolean => coreById[id]?.done ?? false;

  return (
    <div className="flex flex-col gap-3" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader
        title={t("workflow.title")}
        description={t("workflow.description")}
      />

      {/* Project gate -- everything below runs in the chosen project's workspace. */}
      <ActiveProjectBar />
      {!gated && <OneClickFuzz onOpen={openSection} apiRef={setOneClickApi} />}

      {/* Core linear stages */}
      {!gated && <Button variant="primary" className="self-start" onClick={() => {
        setExpanded(activeStage);
        sectionRefs.current[activeStage]?.scrollIntoView({ behavior: "smooth", block: "start" });
        sectionRefs.current[activeStage]?.querySelector("button")?.focus();
      }}>{allComplete ? t("workflow.reviewFindings") : t("workflow.next", { stage: t(`workflow.${activeStage}Label`) })}</Button>}
      {CORE_STAGES.map(({ id, n, icon: Icon, Component }) => {
        const label = t(`workflow.${id}Label`);
        const hint = t(`workflow.${id}Hint`);
        const done = stageDone(id);
        const skipped = coreById[id]?.skipped ?? false;
        const current = !gated && !allComplete && (coreById[id]?.current ?? false);
        const open = !gated && expanded === id;
        return (
          <section
            key={id}
            ref={(el) => {
              sectionRefs.current[id] = el;
            }}
            className="workflow-stage"
            style={{
              overflow: "hidden",
              borderLeft: `3px solid ${current ? "var(--accent)" : done ? "var(--success)" : "var(--border)"}`,
            }}
          >
            <button
              onClick={() => !gated && setExpanded(open ? null : id)}
              disabled={gated}
              aria-expanded={open}
              aria-controls={`workflow-stage-${id}`}
              className="flex items-center justify-between w-full text-left"
              style={{ padding: "12px 14px", background: "transparent", border: "none", cursor: gated ? "not-allowed" : "pointer", color: "var(--text-primary)" }}
            >
              <span className="flex items-center gap-3">
                <StatusBadge n={n} done={done} skipped={skipped} current={current} />
                <span className="flex flex-col">
                  <span className="text-sm font-medium flex items-center gap-2">
                    <Icon size={14} />
                    {label}
                    {skipped && <span className="text-xs text-text-muted">{t("workflow.skipped")}</span>}
                  </span>
                  <span className="text-xs text-text-muted">{hint}</span>
                </span>
              </span>
              {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
            </button>
            {open && (
              <div id={`workflow-stage-${id}`} style={{ padding: "0 14px 16px", borderTop: "1px solid var(--border)" }}>
                <div style={{ paddingTop: "14px" }}>
                  <Component
                    embedded
                    stepPrefix={String(n)}
                    onNavigate={navigateFromStage}
                    onApproved={(scope) => oneClickApi.current?.approved(scope)}
                  />
                </div>
              </div>
            )}
          </section>
        );
      })}

      {/* Corpus -- an ongoing resource, not a numbered step. */}
      <div className="mt-1 mb-1 text-xs text-text-muted uppercase" style={{ letterSpacing: "0.08em" }}>
        {t("workflow.ongoing")}
      </div>
      <section
        ref={(el) => {
          sectionRefs.current.corpus = el;
        }}
        className="workflow-stage"
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
              <span className="text-sm font-medium">{t("workflow.corpus")}</span>
              <span className="text-xs text-text-muted">{t("workflow.corpusHint")}</span>
            </span>
          </span>
          {expanded === "corpus" ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
        </button>
        {!gated && expanded === "corpus" && (
          <div style={{ padding: "0 14px 16px", borderTop: "1px solid var(--border)" }}>
            <div style={{ paddingTop: "14px" }}>
              <Suspense fallback={<div role="status">{t("common.loading")}</div>}><CorpusView embedded onNavigate={navigateFromStage} /></Suspense>
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
