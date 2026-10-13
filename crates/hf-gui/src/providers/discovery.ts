import { createContext, useCallback, useContext, useState } from "react";
import type { RankedDiscoveryResult, TargetInventory } from "../types";
import type { BoundSemgrepInventory } from "../lib/semgrep";
export interface DiscoverySnapshot {
  inventory: TargetInventory;
  semgrep: BoundSemgrepInventory | null;
  ranked?: RankedDiscoveryResult | null;
  rankedOperationId?: string | null;
}
export interface DiscoveryStore {
  entries: Record<string, DiscoverySnapshot>;
  revisions: Record<string, number>;
  save: (project: string, lang: string, snapshot: DiscoverySnapshot, revision: number) => void;
}
export const DiscoveryContext = createContext<DiscoveryStore | null>(null);
export function useDiscoveryInventory(project: string, lang: string) {
  const shared = useContext(DiscoveryContext);
  const [local, setLocal] = useState<Record<string, DiscoverySnapshot>>({});
  const key = JSON.stringify([project, lang]);
  const snapshot = (shared?.entries ?? local)[key];
  const sharedSave = shared?.save;
  const revision = shared?.revisions[project] ?? 0;
  const save = useCallback((value: DiscoverySnapshot) => {
    if (sharedSave) sharedSave(project, lang, value, revision);
    else setLocal(previous => ({ ...previous, [key]: value }));
  }, [key, lang, project, revision, sharedSave]);
  return { snapshot, save };
}
