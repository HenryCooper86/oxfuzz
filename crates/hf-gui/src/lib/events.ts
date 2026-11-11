// Lightweight app-wide "data changed" signal.
//
// Some mutations (clearing knowledge, clearing the workspace, deleting a
// project) invalidate data shown in *other* views that were loaded earlier.
// Rather than thread a query-invalidation context through every view, the
// mutating view emits this event and interested views re-fetch. Read-only
// consumers only (a re-fetch is always safe); do not use it to discard
// unsaved local edits.

const DATA_CHANGED = "hf:data-changed";

/** Notify all views that persisted data changed and should be re-fetched. */
export function emitDataChanged(): void {
  window.dispatchEvent(new Event(DATA_CHANGED));
}

/** Subscribe to {@link emitDataChanged}; returns an unsubscribe function. */
export function onDataChanged(handler: () => void): () => void {
  window.addEventListener(DATA_CHANGED, handler);
  return () => window.removeEventListener(DATA_CHANGED, handler);
}

// A harness for one target was replaced outside the Harness view (the
// one-click flow drafts, compiles and smoke-tests its own revision). Unlike
// DATA_CHANGED, this names the scope, so the Harness view can drop a stale
// local draft for exactly that target and show the revision awaiting review.

const HARNESS_REPLACED = "hf:harness-replaced";

export interface HarnessScope {
  project: string;
  target: string;
  engine: string;
}

/** Announce that `scope` now has a different retained harness revision. */
export function emitHarnessReplaced(scope: HarnessScope): void {
  window.dispatchEvent(new CustomEvent<HarnessScope>(HARNESS_REPLACED, { detail: scope }));
}

/** Subscribe to {@link emitHarnessReplaced}; returns an unsubscribe function. */
export function onHarnessReplaced(handler: (scope: HarnessScope) => void): () => void {
  const listener = (event: Event) => handler((event as CustomEvent<HarnessScope>).detail);
  window.addEventListener(HARNESS_REPLACED, listener);
  return () => window.removeEventListener(HARNESS_REPLACED, listener);
}
