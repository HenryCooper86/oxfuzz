import { createContext, useContext } from "react";

export const CORE_STAGES = [
  { id: "discover", label: "Discover targets", steps: ["discover"] },
  {
    id: "harness",
    label: "Generate harness",
    steps: ["harness", "compile", "smoke", "approve", "seeds"],
  },
  { id: "run", label: "Run fuzzer", steps: ["run"] },
  { id: "triage", label: "Triage crashes", steps: ["triage"] },
] as const;

export type CoreStageId = (typeof CORE_STAGES)[number]["id"];

export const PIPELINE_STAGES = CORE_STAGES.flatMap((stage) =>
  stage.steps.map((id) => ({ id, group: stage.id })),
);

export type StageId = (typeof PIPELINE_STAGES)[number]["id"];

export interface CoreStageProgress {
  id: CoreStageId;
  label: string;
  done: boolean;
  skipped: boolean;
  current: boolean;
  doneSteps: number;
  totalSteps: number;
}

export interface PipelineContextValue {
  completed: StageId[];
  isDone: (id: StageId) => boolean;
  currentStage: StageId | null;
  coreStages: CoreStageProgress[];
  isSkipped: (id: StageId) => boolean;
  markDone: (id: StageId) => void;
  markSkipped: (id: StageId) => void;
  reset: () => void;
}

export const PipelineContext = createContext<PipelineContextValue | null>(null);

/** Access pipeline progress. Safe outside a provider. */
export function usePipeline(): PipelineContextValue {
  return (
    useContext(PipelineContext) ?? {
      completed: [],
      isDone: () => false,
      isSkipped: () => false,
      currentStage: "discover",
      coreStages: CORE_STAGES.map((stage, index) => ({
        id: stage.id,
        label: stage.label,
        done: false,
        skipped: false,
        current: index === 0,
        doneSteps: 0,
        totalSteps: stage.steps.length,
      })),
      markDone: () => {},
      markSkipped: () => {},
      reset: () => {},
    }
  );
}
