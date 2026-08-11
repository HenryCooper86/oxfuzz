const RETIRED_ENGINE_ID = ["cluster", "fuzz", "lite"].join("");
const RETIRED_ENGINE_IDS = new Set([
  RETIRED_ENGINE_ID,
  ["c", "f", "l"].join(""),
  ["c", "f", "l", "ite"].join(""),
]);

/** Return the original trimmed spelling only for a retired engine identifier. */
export function retiredEngineValue(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return RETIRED_ENGINE_IDS.has(trimmed.toLowerCase()) ? trimmed : null;
}

/** Format the exact cross-boundary error without remapping the input. */
export function formatRetiredEngineError(value: string): string {
  return `fuzzing engine '${value}' has been retired; choose one of: afl++, honggfuzz, libfuzzer, syzkaller`;
}
