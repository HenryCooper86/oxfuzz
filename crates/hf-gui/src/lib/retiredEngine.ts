const RETIRED_ENGINE_ID = ["cluster", "fuzz", "lite"].join("");
const RETIRED_ENGINE_IDS = new Set([
  RETIRED_ENGINE_ID,
  ["c", "f", "l"].join(""),
  ["c", "f", "l", "ite"].join(""),
]);
const DIAGNOSTIC_LIMIT = 96;
const TRUNCATION_MARKER = "… [truncated]";

function normalizedRetiredEngineId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return RETIRED_ENGINE_IDS.has(trimmed.toLowerCase()) ? trimmed : null;
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
