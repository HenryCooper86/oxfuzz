import { createContext, useContext } from "react";

export interface RunStatusValue {
  activeEngine: string | null;
  setActiveEngine: (engine: string | null) => void;
}

export const RunStatusContext = createContext<RunStatusValue | null>(null);

export function useRunStatus(): RunStatusValue {
  return useContext(RunStatusContext) ?? { activeEngine: null, setActiveEngine: () => {} };
}
