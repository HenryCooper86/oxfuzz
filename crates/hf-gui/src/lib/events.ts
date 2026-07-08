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
