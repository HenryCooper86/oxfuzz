import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useProject } from "./ProjectContext";
import { pruneToKeys } from "../lib/projectState";

// The canonical fuzzing flow, expressed once. Granular `steps` are the source
// of truth for markDone/isDone; they roll up into the 4 CORE_STAGES that the
// Fuzzing Workflow and the Progress panel both render, so the two never disagree
// on count, numbering, or "done" (previously the panel showed x/6 while the
// workflow showed step x of 4, and neither tracked the approval gate).
export const CORE_STAGES = [
  { id: "discover", label: "Discover targets", steps: ["discover"] },
  {
    id: "harness",
    label: "Generate harness",
    // Draft -> compile -> smoke-test -> review & approve -> seed corpus.
    steps: ["harness", "compile", "smoke", "approve", "seeds"],
  },
  { id: "run", label: "Run fuzzer", steps: ["run"] },
  { id: "triage", label: "Triage crashes", steps: ["triage"] },
] as const;

export type CoreStageId = (typeof CORE_STAGES)[number]["id"];

/** The flattened granular stage list, in order. */
export const PIPELINE_STAGES = CORE_STAGES.flatMap((c) =>
  c.steps.map((id) => ({ id, group: c.id })),
);

export type StageId = (typeof PIPELINE_STAGES)[number]["id"];

/** One core stage's rolled-up progress, for the Workflow + Progress panels. */
export interface CoreStageProgress {
  id: CoreStageId;
  label: string;
  /** All of the stage's granular steps are complete. */
  done: boolean;
  /** Every completed step was skipped (nothing was actually done). */
  skipped: boolean;
  /** The first not-yet-complete core stage. */
  current: boolean;
  /** Completed granular steps / total, for a "(3/5)" sub-progress hint. */
  doneSteps: number;
  totalSteps: number;
}

interface PipelineContextValue {
  completed: StageId[];
  isDone: (id: StageId) => boolean;
  /** The first stage not yet completed -- the "current" step. Null when all done. */
  currentStage: StageId | null;
  /** The 4 core stages with rolled-up done/current/sub-progress. */
  coreStages: CoreStageProgress[];
  isSkipped: (id: StageId) => boolean;
  markDone: (id: StageId) => void;
  /** Mark a stage as not needed (e.g. Triage when a run found no crashes). It
   * counts toward completion but renders as "Skipped". */
  markSkipped: (id: StageId) => void;
  reset: () => void;
}

interface Progress {
  completed: StageId[];
  skipped: StageId[];
}
const EMPTY: Progress = { completed: [], skipped: [] };

const STORAGE_KEY = "hf_pipeline_progress_v1";

/** Load per-target progress from localStorage (best-effort). */
function loadProgress(): Record<string, Progress> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, Progress>) : {};
  } catch {
    return {};
  }
}

const PipelineContext = createContext<PipelineContextValue | null>(null);

export function PipelineProvider({ children }: { children: React.ReactNode }) {
  // Progress is kept per fuzzing target (project path), so switching between
  // targets retains each one's pipeline state instead of resetting it, and it
  // is persisted to localStorage so it survives an app restart.
  const { activeProject, recentProjects } = useProject();
  const key = activeProject || "__none__";
  const [byProject, setByProject] = useState<Record<string, Progress>>(loadProgress);
  const cur = byProject[key] ?? EMPTY;

  // Persist progress, but only for projects still in the recents list -- a
  // removed project's completed pipeline must not linger on disk. The active
  // project is cleared on removal, so the live view already drops it.
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(pruneToKeys(byProject, recentProjects)));
    } catch {
      // Best-effort: localStorage may be unavailable or full.
    }
  }, [byProject, recentProjects]);

  const update = useCallback(
    (fn: (p: Progress) => Progress) => {
      setByProject((prev) => ({ ...prev, [key]: fn(prev[key] ?? EMPTY) }));
    },
    [key],
  );

  const markDone = useCallback(
    (id: StageId) =>
      update((p) => ({
        completed: p.completed.includes(id) ? p.completed : [...p.completed, id],
        skipped: p.skipped.filter((s) => s !== id),
      })),
    [update],
  );

  const markSkipped = useCallback(
    (id: StageId) =>
      update((p) => ({
        completed: p.completed.includes(id) ? p.completed : [...p.completed, id],
        skipped: p.skipped.includes(id) ? p.skipped : [...p.skipped, id],
      })),
    [update],
  );

  const reset = useCallback(() => update(() => EMPTY), [update]);

  const isDone = useCallback((id: StageId) => cur.completed.includes(id), [cur]);
  const isSkipped = useCallback((id: StageId) => cur.skipped.includes(id), [cur]);

  const currentStage = useMemo<StageId | null>(() => {
    const next = PIPELINE_STAGES.find((s) => !cur.completed.includes(s.id));
    return next ? next.id : null;
  }, [cur]);

  // Roll the granular steps up into the 4 core stages. A core stage is `done`
  // when all its steps are complete; `current` is the first not-done core stage.
  const coreStages = useMemo<CoreStageProgress[]>(() => {
    const rows = CORE_STAGES.map((c) => {
      const doneSteps = c.steps.filter((s) => cur.completed.includes(s)).length;
      const done = doneSteps === c.steps.length;
      const skipped = done && c.steps.every((s) => cur.skipped.includes(s));
      return { id: c.id, label: c.label, done, skipped, doneSteps, totalSteps: c.steps.length };
    });
    // The current stage is the first not-done one (none when all complete).
    const currentIdx = rows.findIndex((r) => !r.done);
    return rows.map((r, i) => ({ ...r, current: i === currentIdx }));
  }, [cur]);

  const value = useMemo(
    () => ({
      completed: cur.completed,
      isDone,
      isSkipped,
      currentStage,
      coreStages,
      markDone,
      markSkipped,
      reset,
    }),
    [cur.completed, isDone, isSkipped, currentStage, coreStages, markDone, markSkipped, reset],
  );

  return <PipelineContext.Provider value={value}>{children}</PipelineContext.Provider>;
}

/** Access pipeline progress. Safe outside a provider (returns inert defaults). */
export function usePipeline(): PipelineContextValue {
  const ctx = useContext(PipelineContext);
  if (!ctx) {
    return {
      completed: [],
      isDone: () => false,
      isSkipped: () => false,
      currentStage: "discover",
      coreStages: CORE_STAGES.map((c, i) => ({
        id: c.id,
        label: c.label,
        done: false,
        skipped: false,
        current: i === 0,
        doneSteps: 0,
        totalSteps: c.steps.length,
      })),
      markDone: () => {},
      markSkipped: () => {},
      reset: () => {},
    };
  }
  return ctx;
}
