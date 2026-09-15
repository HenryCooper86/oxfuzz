import { useCallback, useMemo, useState, type ReactNode } from "react";
import { DiscoveryContext, type DiscoverySnapshot } from "./discovery";
export function DiscoveryProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<Record<string, DiscoverySnapshot>>({});
  const save = useCallback((key: string, snapshot: DiscoverySnapshot) => setEntries(previous => ({ ...previous, [key]: snapshot })), []);
  const value = useMemo(() => ({ entries, save }), [entries, save]);
  return <DiscoveryContext.Provider value={value}>{children}</DiscoveryContext.Provider>;
}
