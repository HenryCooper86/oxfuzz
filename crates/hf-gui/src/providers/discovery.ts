import { createContext, useCallback, useContext, useState } from "react";
import type { TargetInventory } from "../types";
import type { BoundSemgrepInventory } from "../lib/semgrep";
export interface DiscoverySnapshot { inventory: TargetInventory; semgrep: BoundSemgrepInventory | null }
export interface DiscoveryStore { entries: Record<string, DiscoverySnapshot>; save: (key: string, snapshot: DiscoverySnapshot) => void }
export const DiscoveryContext = createContext<DiscoveryStore | null>(null);
export function useDiscoveryInventory(project: string, lang: string) {
  const shared = useContext(DiscoveryContext);
  const [local, setLocal] = useState<Record<string, DiscoverySnapshot>>({});
  const key = JSON.stringify([project, lang]);
  const snapshot = (shared?.entries ?? local)[key];
  const sharedSave = shared?.save;
  const save = useCallback((value: DiscoverySnapshot) => {
    if (sharedSave) sharedSave(key, value);
    else setLocal(previous => ({ ...previous, [key]: value }));
  }, [key, sharedSave]);
  return { snapshot, save };
}
