import { useCallback, useEffect, useMemo, useState } from "react";
import { useProject } from "./project";
import { pruneToKeys } from "../lib/projectState";
import {
  CORE_STAGES,
  PIPELINE_STAGES,
  PipelineContext,
  type CoreStageProgress,
  type StageId,
} from "./pipeline";

// The canonical fuzzing flow, expressed once. Granular `steps` are the source
// of truth for markDone/isDone; they roll up into the 4 CORE_STAGES that the
// Fuzzing Workflow and the Progress panel both render, so the two never disagree
// on count, numbering, or "done" (previously the panel showed x/6 while the
// workflow showed step x of 4, and neither tracked the approval gate).
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
