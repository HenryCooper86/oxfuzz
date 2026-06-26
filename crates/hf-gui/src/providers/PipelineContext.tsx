import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useProject } from "./ProjectContext";

export const PIPELINE_STAGES = [
  { id: "discover", label: "Discover targets" },
  { id: "harness", label: "Generate harness" },
  { id: "compile", label: "Compile in sandbox" },
  { id: "seeds", label: "Generate seed corpus" },
  { id: "run", label: "Run fuzzer" },
  { id: "triage", label: "Triage crashes" },
] as const;

export type StageId = (typeof PIPELINE_STAGES)[number]["id"];

interface PipelineContextValue {
  completed: StageId[];
  isDone: (id: StageId) => boolean;
  /** The first stage not yet completed -- the "current" step. Null when all done. */
  currentStage: StageId | null;
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
  const { activeProject } = useProject();
  const key = activeProject || "__none__";
  const [byProject, setByProject] = useState<Record<string, Progress>>(loadProgress);
  const cur = byProject[key] ?? EMPTY;

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(byProject));
    } catch {
      // Best-effort: localStorage may be unavailable or full.
    }
  }, [byProject]);

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

  const value = useMemo(
    () => ({
      completed: cur.completed,
      isDone,
      isSkipped,
      currentStage,
      markDone,
      markSkipped,
      reset,
    }),
    [cur.completed, isDone, isSkipped, currentStage, markDone, markSkipped, reset],
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
      markDone: () => {},
      markSkipped: () => {},
      reset: () => {},
    };
  }
  return ctx;
}
