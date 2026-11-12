import { createContext, useContext } from "react";

export interface FindingSelection {
  findingId: string;
  runId: string;
}

export interface FindingSelectionValue {
  selection: FindingSelection | null;
  selectFinding: (findingId: string, runId: string) => void;
  /** Forget the active project's remembered finding (it no longer exists). */
  clearFinding: () => void;
}

export const FindingSelectionContext = createContext<FindingSelectionValue | null>(null);

export function useFindingSelection(): FindingSelectionValue {
  return useContext(FindingSelectionContext) ?? {
    selection: null,
    selectFinding: () => undefined,
    clearFinding: () => undefined,
  };
}
