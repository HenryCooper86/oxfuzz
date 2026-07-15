import { useCallback, useEffect, useMemo, useState } from "react";
import { useProject } from "./project";
import { pruneToKeys } from "../lib/projectState";
import {
  DEFAULT_TARGET_STATE,
  TargetContext,
  type TargetState,
} from "./target";

// Carries the selected target + engine + language across views so the
// Harness -> Run handoff works. Kept per fuzzing target (project path) so
// switching between targets retains each one's selection.

const STORAGE_KEY = "hf_target_selection_v1";

/** Load per-target selection from localStorage (best-effort). */
function loadSelection(): Record<string, TargetState> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, TargetState>) : {};
  } catch {
    return {};
  }
}

export function TargetProvider({ children }: { children: React.ReactNode }) {
  const { activeProject, recentProjects } = useProject();
  const key = activeProject || "__none__";
  const [byProject, setByProject] = useState<Record<string, TargetState>>(loadSelection);
  const cur = byProject[key] ?? DEFAULT_TARGET_STATE;

  useEffect(() => {
    try {
      // Prune selections for removed projects (mirrors Pipeline/RunOutput
      // contexts) so a deleted project's target/engine/lang does not linger in
      // localStorage and reappear if the folder is re-added later.
      localStorage.setItem(STORAGE_KEY, JSON.stringify(pruneToKeys(byProject, recentProjects)));
    } catch {
      // Best-effort: localStorage may be unavailable or full.
    }
  }, [byProject, recentProjects]);

  const patch = useCallback(
    (p: Partial<TargetState>) => {
      setByProject((prev) => ({
        ...prev,
        [key]: { ...(prev[key] ?? DEFAULT_TARGET_STATE), ...p },
      }));
    },
    [key],
  );

  const setTarget = useCallback((target: string) => patch({ target }), [patch]);
  const setEngine = useCallback((engine: string) => patch({ engine }), [patch]);
  const setLang = useCallback((lang: string) => patch({ lang }), [patch]);
  const setCompiled = useCallback((compiled: boolean) => patch({ compiled }), [patch]);
  const reset = useCallback(() => patch(DEFAULT_TARGET_STATE), [patch]);

  const value = useMemo(
    () => ({ ...cur, setTarget, setEngine, setLang, setCompiled, reset }),
    [cur, setTarget, setEngine, setLang, setCompiled, reset],
  );

  return <TargetContext.Provider value={value}>{children}</TargetContext.Provider>;
}
