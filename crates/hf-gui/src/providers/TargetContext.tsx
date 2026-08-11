import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useProject } from "./project";
import {
  DEFAULT_TARGET_STATE,
  TargetContext,
  type TargetSelectionRepair,
  type TargetStorageError,
  type TargetState,
} from "./target";
import {
  isActiveEngineId,
  parsePersistedTargetSelections,
  prunePersistedTargetSelections,
  repairTargetSelectionEngine,
  serializableTargetSelections,
  type PersistedTargetSelections,
} from "./targetSelection";

// Carries the selected target + engine + language across views so the
// Harness -> Run handoff works. Kept per fuzzing target (project path) so
// switching between targets retains each one's selection.

const STORAGE_KEY = "hf_target_selection_v1";

interface LoadedSelection {
  selections: PersistedTargetSelections;
  storageError: TargetStorageError | null;
}

type PersistResult = "saved" | "blocked" | "failed";

function emptySelection(): PersistedTargetSelections {
  return { entries: {}, globalRepair: null };
}

function loadSelection(): LoadedSelection {
  try {
    return {
      selections: parsePersistedTargetSelections(localStorage.getItem(STORAGE_KEY)),
      storageError: null,
    };
  } catch {
    return { selections: emptySelection(), storageError: { operation: "read" } };
  }
}

function firstSelectionRepair(selections: PersistedTargetSelections): TargetSelectionRepair | null {
  return selections.globalRepair
    ?? Object.values(selections.entries).find((entry) => entry.repair !== null)?.repair
    ?? null;
}

export function TargetProvider({ children }: { children: React.ReactNode }) {
  const { activeProject, recentProjects } = useProject();
  const key = activeProject || "__none__";
  const [loaded] = useState<LoadedSelection>(loadSelection);
  const [selections, setSelections] = useState<PersistedTargetSelections>(loaded.selections);
  const [storageError, setStorageError] = useState<TargetStorageError | null>(loaded.storageError);
  const selectionsRef = useRef(selections);
  const storageErrorRef = useRef(storageError);
  const retainedSelections = prunePersistedTargetSelections(selections, recentProjects);
  const current = retainedSelections.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
  const selectionRepair = retainedSelections.globalRepair
    ?? current.repair
    ?? firstSelectionRepair(retainedSelections);

  const replaceState = useCallback((next: PersistedTargetSelections, nextStorageError: TargetStorageError | null) => {
    selectionsRef.current = next;
    storageErrorRef.current = nextStorageError;
    setSelections(next);
    setStorageError(nextStorageError);
  }, []);

  const persist = useCallback((next: PersistedTargetSelections): PersistResult => {
    const serializable = serializableTargetSelections(next, recentProjects);
    if (serializable === null) return "blocked";
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(serializable));
      return "saved";
    } catch {
      return "failed";
    }
  }, [recentProjects]);

  const commit = useCallback((next: PersistedTargetSelections, writeFailureState = selectionsRef.current): PersistResult => {
    const result = persist(next);
    if (result === "saved") replaceState(next, null);
    else if (result === "blocked") replaceState(next, null);
    else replaceState(writeFailureState, { operation: "write" });
    return result;
  }, [persist, replaceState]);

  useEffect(() => {
    const currentSelections = selectionsRef.current;
    const pruned = prunePersistedTargetSelections(currentSelections, recentProjects);
    if (pruned === currentSelections) return;
    const result = persist(pruned);
    if (result === "saved") replaceState(pruned, null);
    else if (result === "failed") replaceState(pruned, { operation: "write" });
    else replaceState(pruned, storageErrorRef.current);
  }, [persist, recentProjects, replaceState]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onStorage = (event: StorageEvent) => {
      if (event.key !== STORAGE_KEY || event.storageArea !== window.localStorage) return;
      replaceState(parsePersistedTargetSelections(event.newValue), null);
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [replaceState]);

  const patch = useCallback(
    (p: Partial<TargetState>) => {
      const previous = prunePersistedTargetSelections(selectionsRef.current, recentProjects);
      const entry = previous.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
      const next = {
        ...previous,
        entries: {
          ...previous.entries,
          [key]: { ...entry, state: { ...entry.state, ...p } },
        },
      };
      if (firstSelectionRepair(previous) || storageErrorRef.current) {
        replaceState(next, storageErrorRef.current);
        return;
      }
      commit(next);
    },
    [commit, key, recentProjects, replaceState],
  );

  const setTarget = useCallback((target: string) => patch({ target }), [patch]);
  const setEngine = useCallback((engine: string) => {
    if (!isActiveEngineId(engine)) return;
    const reloaded = storageErrorRef.current?.operation === "read" ? loadSelection() : null;
    if (reloaded?.storageError) {
      replaceState(selectionsRef.current, reloaded.storageError);
      return;
    }
    const previous = prunePersistedTargetSelections(
      reloaded?.selections ?? selectionsRef.current,
      recentProjects,
    );
    const entry = previous.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
    const next = {
      entries: {
        ...previous.entries,
        [key]: repairTargetSelectionEngine(entry, engine),
      },
      globalRepair: null,
    };
    commit(next, previous);
  }, [commit, key, recentProjects, replaceState]);
  const setLang = useCallback((lang: string) => patch({ lang }), [patch]);
  const setCompiled = useCallback((compiled: boolean) => patch({ compiled }), [patch]);
  const value = useMemo(
    () => ({ ...current.state, selectionRepair, storageError, setTarget, setEngine, setLang, setCompiled }),
    [current.state, selectionRepair, storageError, setTarget, setEngine, setLang, setCompiled],
  );

  return <TargetContext.Provider value={value}>{children}</TargetContext.Provider>;
}
