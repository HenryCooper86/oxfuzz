/**
 * Per-project UI state (pipeline progress, run output) is stored in maps keyed
 * by project path. When projects are removed, those maps must forget the gone
 * projects so removed work no longer shows up.
 *
 * `pruneToKeys` keeps only entries whose key is an allowed project path, plus
 * the transient "__none__" bucket used when no project is active. It returns the
 * same reference when nothing changed, so it is safe to call inside a React
 * setState updater without causing redundant writes.
 */
export const NO_PROJECT_KEY = "__none__";

/** Map an empty active project to the internal bucket used by project-keyed state. */
export function projectStorageKey(activeProject: string): string {
  return activeProject || NO_PROJECT_KEY;
}

/** The internal no-project bucket is never a switchable project identity. */
export function isNoProjectKey(key: string): boolean {
  return key === NO_PROJECT_KEY;
}

export function pruneToKeys<T>(
  map: Record<string, T>,
  allowed: readonly string[],
): Record<string, T> {
  const keep = new Set<string>([...allowed, NO_PROJECT_KEY]);
  const entries = Object.entries(map).filter(([k]) => keep.has(k));
  if (entries.length === Object.keys(map).length) return map;
  return Object.fromEntries(entries) as Record<string, T>;
}
