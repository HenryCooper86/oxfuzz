import { useCallback, useEffect, useMemo, useState } from "react";
import { createLatestRefresh } from "../lib/scheduleRecovery";

/** Poll one context, discarding superseded responses and previous-context data. */
export function usePolledResource<T>(load: () => Promise<T>, enabled = true) {
  const [state, setState] = useState<{ source: typeof load; data: T | null; error: string | null; loading: boolean }>({ source: load, data: null, error: null, loading: true });
  const refresh = useMemo(() => createLatestRefresh({
    load,
    onStart: () => setState(previous => ({ source: load, data: previous.source === load ? previous.data : null, error: null, loading: true })),
    commit: data => setState({ source: load, data, error: null, loading: false }),
  }), [load]);
  const reload = useCallback(() => refresh.refresh().catch((cause: unknown) => {
    setState({ source: load, data: null, error: String(cause), loading: false });
  }), [load, refresh]);
  useEffect(() => {
    if (!enabled) return;
    refresh.activate(); void reload();
    const timer = setInterval(() => void reload(), 5000);
    return () => { refresh.deactivate(); clearInterval(timer); };
  }, [enabled, refresh, reload]);
  const current = enabled && state.source === load ? state : { data: null, error: null, loading: enabled };
  return { ...current, reload };
}
