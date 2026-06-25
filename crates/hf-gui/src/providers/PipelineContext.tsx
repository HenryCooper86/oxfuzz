import { createContext, useCallback, useContext, useMemo, useState } from "react";

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
  markDone: (id: StageId) => void;
  reset: () => void;
}

const PipelineContext = createContext<PipelineContextValue | null>(null);

export function PipelineProvider({ children }: { children: React.ReactNode }) {
  const [completed, setCompleted] = useState<StageId[]>([]);

  const markDone = useCallback((id: StageId) => {
    setCompleted((prev) => (prev.includes(id) ? prev : [...prev, id]));
  }, []);

  const reset = useCallback(() => setCompleted([]), []);

  const isDone = useCallback((id: StageId) => completed.includes(id), [completed]);

  const currentStage = useMemo<StageId | null>(() => {
    const next = PIPELINE_STAGES.find((s) => !completed.includes(s.id));
    return next ? next.id : null;
  }, [completed]);

  const value = useMemo(
    () => ({ completed, isDone, currentStage, markDone, reset }),
    [completed, isDone, currentStage, markDone, reset],
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
      currentStage: "discover",
      markDone: () => {},
      reset: () => {},
    };
  }
  return ctx;
}
