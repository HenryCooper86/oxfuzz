import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getTransport } from "../lib";
import { createLatestRefresh } from "../lib/scheduleRecovery";

/** Keep registry reads and mutations from replacing a newer editor session. */
export function useRegistryEditor<Entry, Draft>(command: string) {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const active = useRef(false);
  const editorVersion = useRef(0);
  const mutating = useRef(false);
  const refresh = useMemo(() => createLatestRefresh({
    load: () => getTransport().invoke<Entry[]>(command),
    commit: value => { setEntries(value); setLoaded(true); setLoadError(null); },
  }), [command]);
  const reload = useCallback(() => refresh.refresh().catch((cause: unknown) => {
    setEntries([]); setLoaded(true); setLoadError(String(cause));
  }), [refresh]);
  useEffect(() => {
    active.current = true; refresh.activate();
    void Promise.resolve().then(reload);
    return () => { active.current = false; editorVersion.current += 1; refresh.deactivate(); };
  }, [refresh, reload]);

  function open(factory: () => Draft | Promise<Draft>) {
    const version = ++editorVersion.current;
    setError(null);
    void Promise.resolve().then(factory).then(value => {
      if (active.current && version === editorVersion.current) setDraft(value);
    }).catch((cause: unknown) => {
      if (active.current && version === editorVersion.current) setError(String(cause));
    });
  }
  function close() {
    editorVersion.current += 1; setDraft(null); setError(null);
  }
  async function mutate(operation: () => Promise<unknown>, closeOnSuccess = true) {
    if (!active.current || mutating.current) return;
    const version = editorVersion.current;
    mutating.current = true; setBusy(true); setError(null);
    try {
      await operation();
      if (!active.current) return;
      if (closeOnSuccess && version === editorVersion.current) close();
      await reload();
    } catch (cause) {
      if (active.current && version === editorVersion.current) setError(String(cause));
    } finally {
      mutating.current = false;
      if (active.current) setBusy(false);
    }
  }
  return { entries, loaded, loadError, draft, setDraft, error, setError, busy, reload, open, close, mutate };
}
