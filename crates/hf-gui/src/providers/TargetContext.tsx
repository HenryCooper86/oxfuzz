import { useCallback, useEffect, useMemo, useState } from "react";
import { useProject } from "./project";
import {
  DEFAULT_TARGET_STATE,
  TargetContext,
  type TargetState,
} from "./target";
import {
  isActiveEngineId,
  parsePersistedTargetSelections,
  repairTargetSelectionEngine,
  serializableTargetSelections,
  type PersistedTargetSelections,
} from "./targetSelection";

// Carries the selected target + engine + language across views so the
// Harness -> Run handoff works. Kept per fuzzing target (project path) so
// switching between targets retains each one's selection.

const STORAGE_KEY = "hf_target_selection_v1";

function loadSelection(): PersistedTargetSelections {
  try {
    return parsePersistedTargetSelections(localStorage.getItem(STORAGE_KEY));
  } catch {
    return { entries: {}, globalRepair: null };
  }
}

export function TargetProvider({ children }: { children: React.ReactNode }) {
  const { activeProject, recentProjects } = useProject();
  const key = activeProject || "__none__";
  const [selections, setSelections] = useState<PersistedTargetSelections>(loadSelection);
  const current = selections.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
  const selectionRepair = selections.globalRepair ?? current.repair;

  useEffect(() => {
    try {
      const serializable = serializableTargetSelections(selections, recentProjects);
      if (serializable !== null) {
        // Prune selections for removed projects (mirrors Pipeline/RunOutput
        // contexts) so a deleted project's target/engine/lang does not linger in
        // localStorage and reappear if the folder is re-added later.
        localStorage.setItem(STORAGE_KEY, JSON.stringify(serializable));
      }
    } catch {
      // Best-effort: localStorage may be unavailable or full.
    }
  }, [selections, recentProjects]);

  const patch = useCallback(
    (p: Partial<TargetState>) => {
      setSelections((previous) => {
        const entry = previous.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
        return {
          ...previous,
          entries: {
            ...previous.entries,
            [key]: { ...entry, state: { ...entry.state, ...p } },
          },
        };
      });
    },
    [key],
  );

  const setTarget = useCallback((target: string) => patch({ target }), [patch]);
  const setEngine = useCallback((engine: string) => {
    if (!isActiveEngineId(engine)) return;
    setSelections((previous) => {
      const entry = previous.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
      return {
        entries: {
          ...previous.entries,
          [key]: repairTargetSelectionEngine(entry, engine),
        },
        globalRepair: null,
      };
    });
  }, [key]);
  const setLang = useCallback((lang: string) => patch({ lang }), [patch]);
  const setCompiled = useCallback((compiled: boolean) => patch({ compiled }), [patch]);
  const reset = useCallback(() => {
    setSelections((previous) => {
      const entry = previous.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
      if (previous.globalRepair?.kind === "retired_engine" || entry.repair?.kind === "retired_engine") {
        return previous;
      }
      return {
        entries: {
          ...previous.entries,
          [key]: { state: { ...DEFAULT_TARGET_STATE }, repair: null },
        },
        globalRepair: null,
      };
    });
  }, [key]);

  const value = useMemo(
    () => ({ ...current.state, selectionRepair, setTarget, setEngine, setLang, setCompiled, reset }),
    [current.state, selectionRepair, setTarget, setEngine, setLang, setCompiled, reset],
  );

  return <TargetContext.Provider value={value}>{children}</TargetContext.Provider>;
}
