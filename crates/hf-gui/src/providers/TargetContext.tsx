import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { useProject } from "./ProjectContext";

// Carries the selected target + engine + language across views so the
// Harness -> Run handoff works. Kept per fuzzing target (project path) so
// switching between targets retains each one's selection.

interface TargetContextValue {
  /** The selected target symbol (e.g. "parse_value"). */
  target: string;
  /** The selected engine id (e.g. "libfuzzer"). */
  engine: string;
  /** The selected language id (e.g. "c"). */
  lang: string;
  /** Whether a harness has been compiled for the current target. */
  compiled: boolean;
  setTarget: (t: string) => void;
  setEngine: (e: string) => void;
  setLang: (l: string) => void;
  setCompiled: (c: boolean) => void;
  /** Reset the current target's fields. */
  reset: () => void;
}

const TargetContext = createContext<TargetContextValue | null>(null);

type TargetState = Pick<TargetContextValue, "target" | "engine" | "lang" | "compiled">;
const DEFAULTS: TargetState = {
  target: "",
  engine: "libfuzzer",
  lang: "c",
  compiled: false,
};

export function TargetProvider({ children }: { children: React.ReactNode }) {
  const { activeProject } = useProject();
  const key = activeProject || "__none__";
  const [byProject, setByProject] = useState<Record<string, TargetState>>({});
  const cur = byProject[key] ?? DEFAULTS;

  const patch = useCallback(
    (p: Partial<TargetState>) => {
      setByProject((prev) => ({ ...prev, [key]: { ...(prev[key] ?? DEFAULTS), ...p } }));
    },
    [key],
  );

  const setTarget = useCallback((target: string) => patch({ target }), [patch]);
  const setEngine = useCallback((engine: string) => patch({ engine }), [patch]);
  const setLang = useCallback((lang: string) => patch({ lang }), [patch]);
  const setCompiled = useCallback((compiled: boolean) => patch({ compiled }), [patch]);
  const reset = useCallback(() => patch(DEFAULTS), [patch]);

  const value = useMemo(
    () => ({ ...cur, setTarget, setEngine, setLang, setCompiled, reset }),
    [cur, setTarget, setEngine, setLang, setCompiled, reset],
  );

  return <TargetContext.Provider value={value}>{children}</TargetContext.Provider>;
}

/** Access the shared target/engine/lang state. Safe outside a provider. */
export function useTarget(): TargetContextValue {
  const ctx = useContext(TargetContext);
  if (!ctx) {
    return {
      ...DEFAULTS,
      setTarget: () => {},
      setEngine: () => {},
      setLang: () => {},
      setCompiled: () => {},
      reset: () => {},
    };
  }
  return ctx;
}
