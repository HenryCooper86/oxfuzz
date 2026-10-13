import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { DiscoveryContext, type DiscoverySnapshot } from "./discovery";
import { onProjectDeleted } from "./projectDeletion";

export function DiscoveryProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<Record<string, DiscoverySnapshot>>({});
  const [revisions, setRevisions] = useState<Record<string, number>>({});
  const revisionsRef = useRef(revisions);
  useEffect(() => onProjectDeleted(project => {
    const next = { ...revisionsRef.current, [project]: (revisionsRef.current[project] ?? 0) + 1 };
    revisionsRef.current = next;
    setRevisions(next);
    setEntries(previous => Object.fromEntries(Object.entries(previous).filter(([key]) => {
      const [owner] = JSON.parse(key) as [string, string];
      return owner !== project;
    })));
  }), []);
  const save = useCallback((project: string, lang: string, snapshot: DiscoverySnapshot, revision: number) => {
    if (revision !== (revisionsRef.current[project] ?? 0)) return;
    const key = JSON.stringify([project, lang]);
    setEntries(previous => ({ ...previous, [key]: snapshot }));
  }, []);
  const value = useMemo(() => ({ entries, revisions, save }), [entries, revisions, save]);
  return <DiscoveryContext.Provider value={value}>{children}</DiscoveryContext.Provider>;
}
