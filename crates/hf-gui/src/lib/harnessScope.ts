import type { HarnessReviewItem, TargetCandidate } from "../types";

export function canonicalHarnessLanguage(value: unknown): string {
  if (typeof value !== "string") return "";
  switch (value.toLowerCase()) {
    case "c++":
    case "cpp":
      return "cpp";
    case "c":
    case "rust":
    case "go":
    case "python":
      return value.toLowerCase();
    default:
      return "";
  }
}

export function canonicalHarnessEngine(value: unknown): string {
  if (typeof value !== "string") return "";
  switch (value.toLowerCase()) {
    case "libfuzzer":
    case "lib_fuzzer":
      return "libfuzzer";
    case "afl++":
    case "aflplusplus":
    case "afl_plus_plus":
      return "afl++";
    case "honggfuzz":
    case "syzkaller":
      return value.toLowerCase();
    default:
      return "";
  }
}

export function harnessReviewMatchesScope(
  item: HarnessReviewItem,
  target: string,
  language: string,
  engine: string,
): boolean {
  return matchesTargetSelection(item.target_symbol, item.target_selector, target)
    && canonicalHarnessLanguage(item.language) === canonicalHarnessLanguage(language)
    && canonicalHarnessEngine(item.engine) === canonicalHarnessEngine(engine);
}

/** Preserve the complete source and symbol spelling; symbols themselves may contain ::. */
export function qualifiedTargetSelector(relativeSource: string, symbol: string): string {
  return `${relativeSource}::${symbol}`;
}

export function matchesTargetSelection(symbol: string | null, selector: string | null, selected: string): boolean {
  return symbol === selected || selector === selected;
}

export function candidateTargetSelector(candidate: TargetCandidate): string {
  const file = candidate.location.file;
  const root = candidate.project_root.replace(/[\\/]+$/, "");
  const prefix = [`${root}/`, `${root}\\`].find(value => file.startsWith(value));
  return qualifiedTargetSelector(prefix ? file.slice(prefix.length) : file, candidate.symbol);
}
