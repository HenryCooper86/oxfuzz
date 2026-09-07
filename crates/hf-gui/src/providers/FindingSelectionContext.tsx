import { useCallback, useEffect, useMemo, useState } from "react";
import { pruneToKeys } from "../lib/projectState";
import { useProject } from "./project";
import {
  FindingSelectionContext,
  type FindingSelection,
} from "./findingSelection";

export const FINDING_SELECTION_STORAGE_KEY = "hf_finding_selection_v1";

function loadSelections(): Record<string, FindingSelection> {
  try {
    const raw = localStorage.getItem(FINDING_SELECTION_STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : {};
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return Object.fromEntries(
      Object.entries(parsed).filter((entry): entry is [string, FindingSelection] => {
        const value = entry[1];
        return Boolean(
          value
          && typeof value === "object"
          && "findingId" in value
          && typeof value.findingId === "string"
          && "runId" in value
          && typeof value.runId === "string",
        );
      }),
    );
  } catch {
    return {};
  }
}

export function FindingSelectionProvider({ children }: { children: React.ReactNode }) {
  const { activeProject, recentProjects } = useProject();
  const [selections, setSelections] = useState<Record<string, FindingSelection>>(loadSelections);

  const retainedSelections = useMemo(
    () => pruneToKeys(selections, recentProjects),
    [recentProjects, selections],
  );

  useEffect(() => {
    try {
      localStorage.setItem(FINDING_SELECTION_STORAGE_KEY, JSON.stringify(retainedSelections));
    } catch {
      // Browser storage may be unavailable; the in-memory selection still works.
    }
  }, [retainedSelections]);

  const selectFinding = useCallback((findingId: string, runId: string) => {
    if (!activeProject) return;
    setSelections((current) => ({ ...current, [activeProject]: { findingId, runId } }));
  }, [activeProject]);

  const clearFinding = useCallback(() => {
    if (!activeProject) return;
    setSelections((current) => {
      const next = { ...current };
      delete next[activeProject];
      return next;
    });
  }, [activeProject]);

  const value = useMemo(() => ({
    selection: activeProject ? retainedSelections[activeProject] ?? null : null,
    selectFinding,
    clearFinding,
  }), [activeProject, retainedSelections, selectFinding, clearFinding]);

  return <FindingSelectionContext.Provider value={value}>{children}</FindingSelectionContext.Provider>;
}
