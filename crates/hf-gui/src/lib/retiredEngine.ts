const ACTIVE_ENGINE_IDS = new Set(["libfuzzer", "afl++", "honggfuzz", "syzkaller"]);
const DIAGNOSTIC_LIMIT = 96;
const TRUNCATION_MARKER = "… [truncated]";

function normalizedRetiredEngineId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  // The backend's central retirement recognizer owns the retired identifiers.
  // Locally, preserve every non-active persisted engine for fail-closed repair
  // without embedding a second copy of that identifier set in the frontend.
  return trimmed && !ACTIVE_ENGINE_IDS.has(trimmed) ? trimmed : null;
}

/** Return the original trimmed spelling only for a retired engine identifier. */
export function retiredEngineValue(value: unknown): string | null {
  return normalizedRetiredEngineId(value);
}

/** Recognize retired values without changing the persisted spelling. */
export function isRetiredEngineValue(value: unknown): value is string {
  return normalizedRetiredEngineId(value) !== null;
}

/** Bound UI diagnostics while retaining the original persisted spelling. */
export function retiredEngineDiagnostic(value: string): string {
  if (value.length <= DIAGNOSTIC_LIMIT) return value;
  return `${value.slice(0, DIAGNOSTIC_LIMIT - TRUNCATION_MARKER.length)}${TRUNCATION_MARKER}`;
}

/** Format the exact cross-boundary error without remapping the input. */
export function formatRetiredEngineError(value: string): string {
  return `fuzzing engine '${value}' has been retired; choose one of: afl++, honggfuzz, libfuzzer, syzkaller`;
}
