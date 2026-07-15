import { useCallback, useMemo, useState } from "react";
import { RunStatusContext } from "./runStatus";

// Tracks which fuzzing engine (if any) is currently running, so the status bar
// can highlight the active engine while a campaign is in flight.
export function RunStatusProvider({ children }: { children: React.ReactNode }) {
  const [activeEngine, setActiveEngineState] = useState<string | null>(null);
  const setActiveEngine = useCallback((engine: string | null) => setActiveEngineState(engine), []);
  const value = useMemo(() => ({ activeEngine, setActiveEngine }), [activeEngine, setActiveEngine]);
  return <RunStatusContext.Provider value={value}>{children}</RunStatusContext.Provider>;
}
