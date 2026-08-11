import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useProject } from "./project";
import { projectStorageKey } from "../lib/projectState";
import {
  DEFAULT_TARGET_STATE,
  TargetContext,
  type TargetSelectionRepair,
  type TargetSelectionIssue,
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

function ownedRepair(projectKey: string | null, issue: TargetSelectionIssue): TargetSelectionRepair {
  return { projectKey, issue };
}

function firstSelectionRepair(selections: PersistedTargetSelections): TargetSelectionRepair | null {
  if (selections.globalRepair) return ownedRepair(null, selections.globalRepair);
  for (const projectKey of Object.keys(selections.entries).sort()) {
    const issue = selections.entries[projectKey].repair;
    if (issue) return ownedRepair(projectKey, issue);
  }
  return null;
}

function canResetPersistedTargetSelections(
  selections: PersistedTargetSelections,
  storageError: TargetStorageError | null,
): boolean {
  return selections.globalRepair !== null || (firstSelectionRepair(selections) === null && storageError !== null);
}

export function TargetProvider({ children }: { children: React.ReactNode }) {
  const { activeProject, recentProjects } = useProject();
  const key = projectStorageKey(activeProject);
  const [loaded] = useState<LoadedSelection>(loadSelection);
  const [selections, setSelections] = useState<PersistedTargetSelections>(loaded.selections);
  const [storageError, setStorageError] = useState<TargetStorageError | null>(loaded.storageError);
  const selectionsRef = useRef(selections);
  const storageErrorRef = useRef(storageError);
  const retainedSelections = prunePersistedTargetSelections(selections, recentProjects);
  const current = retainedSelections.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
  const selectionRepair = firstSelectionRepair(retainedSelections);
  const canResetTargetSelections = canResetPersistedTargetSelections(retainedSelections, storageError);

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

  const commit = useCallback((
    next: PersistedTargetSelections,
    writeFailureState = selectionsRef.current,
    replacementOwner?: string | null,
  ): PersistResult => {
    if (replacementOwner !== undefined && replacementOwner !== key) return "blocked";
    const result = persist(next);
    if (result === "saved") replaceState(next, null);
    else if (result === "blocked") replaceState(next, null);
    else replaceState(writeFailureState, { operation: "write" });
    return result;
  }, [key, persist, replaceState]);

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
    if (storageErrorRef.current?.operation === "read") return;
    const previous = prunePersistedTargetSelections(selectionsRef.current, recentProjects);
    const repair = firstSelectionRepair(previous);
    if (repair && repair.projectKey !== key) return;
    const entry = previous.entries[key] ?? { state: DEFAULT_TARGET_STATE, repair: null };
    const next = {
      entries: {
        ...previous.entries,
        [key]: repairTargetSelectionEngine(entry, engine),
      },
      globalRepair: null,
    };
    commit(next, previous, repair?.projectKey);
  }, [commit, key, recentProjects]);
  const setLang = useCallback((lang: string) => patch({ lang }), [patch]);
  const setCompiled = useCallback((compiled: boolean) => patch({ compiled }), [patch]);
  const resetTargetSelections = useCallback(() => {
    const previous = prunePersistedTargetSelections(selectionsRef.current, recentProjects);
    if (!canResetPersistedTargetSelections(previous, storageErrorRef.current)) return;
    const next = emptySelection();
    const result = persist(next);
    if (result === "saved") replaceState(next, null);
    else replaceState(previous, { operation: "write" });
  }, [persist, recentProjects, replaceState]);
  const retryStorage = useCallback(() => {
    const operation = storageErrorRef.current?.operation;
    if (operation === "read") {
      const reloaded = loadSelection();
      replaceState(reloaded.selections, reloaded.storageError);
      return;
    }
    if (operation !== "write") return;
    const currentSelections = prunePersistedTargetSelections(selectionsRef.current, recentProjects);
    const result = persist(currentSelections);
    if (result === "saved") replaceState(currentSelections, null);
    else replaceState(currentSelections, { operation: "write" });
  }, [persist, recentProjects, replaceState]);
  const value = useMemo(
    () => ({
      ...current.state,
      selectionRepair,
      storageError,
      setTarget,
      setEngine,
      setLang,
      setCompiled,
      canResetTargetSelections,
      resetTargetSelections,
      retryStorage,
    }),
    [
      current.state,
      selectionRepair,
      storageError,
      setTarget,
      setEngine,
      setLang,
      setCompiled,
      canResetTargetSelections,
      resetTargetSelections,
      retryStorage,
    ],
  );

  return <TargetContext.Provider value={value}>{children}</TargetContext.Provider>;
}
