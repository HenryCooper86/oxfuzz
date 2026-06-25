import { createContext, useCallback, useContext, useMemo, useState } from "react";

// Carries the selected target + engine + language across views so the
// Harness -> Run handoff works: the user picks a target in Harness, compiles
// it, and switches to Run with the target/engine/language pre-populated.

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
  /** Reset all fields (used by "New task"). */
  reset: () => void;
}

const TargetContext = createContext<TargetContextValue | null>(null);

const DEFAULTS: Pick<TargetContextValue, "target" | "engine" | "lang" | "compiled"> = {
  target: "",
  engine: "libfuzzer",
  lang: "c",
  compiled: false,
};

export function TargetProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState(DEFAULTS);

  const setTarget = useCallback(
    (target: string) => setState((s) => ({ ...s, target })),
    [],
  );
  const setEngine = useCallback(
    (engine: string) => setState((s) => ({ ...s, engine })),
    [],
  );
  const setLang = useCallback(
    (lang: string) => setState((s) => ({ ...s, lang })),
    [],
  );
  const setCompiled = useCallback(
    (compiled: boolean) => setState((s) => ({ ...s, compiled })),
    [],
  );
  const reset = useCallback(() => setState(DEFAULTS), []);

  const value = useMemo(
    () => ({ ...state, setTarget, setEngine, setLang, setCompiled, reset }),
    [state, setTarget, setEngine, setLang, setCompiled, reset],
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