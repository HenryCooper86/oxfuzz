import { createContext, useCallback, useContext, useMemo, useState } from "react";

// Tracks which fuzzing engine (if any) is currently running, so the status bar
// can highlight the active engine while a campaign is in flight.
interface RunStatusValue {
  /** The engine id currently running (e.g. "syzkaller"), or null when idle. */
  activeEngine: string | null;
  setActiveEngine: (engine: string | null) => void;
}

const RunStatusContext = createContext<RunStatusValue | null>(null);

export function RunStatusProvider({ children }: { children: React.ReactNode }) {
  const [activeEngine, setActiveEngineState] = useState<string | null>(null);
  const setActiveEngine = useCallback((engine: string | null) => setActiveEngineState(engine), []);
  const value = useMemo(() => ({ activeEngine, setActiveEngine }), [activeEngine, setActiveEngine]);
  return <RunStatusContext.Provider value={value}>{children}</RunStatusContext.Provider>;
}

export function useRunStatus(): RunStatusValue {
  const ctx = useContext(RunStatusContext);
  if (!ctx) return { activeEngine: null, setActiveEngine: () => {} };
  return ctx;
}
