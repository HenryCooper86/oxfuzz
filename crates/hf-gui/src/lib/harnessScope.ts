import type { HarnessReviewItem } from "../types";

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
  return item.target_symbol === target
    && canonicalHarnessLanguage(item.language) === canonicalHarnessLanguage(language)
    && canonicalHarnessEngine(item.engine) === canonicalHarnessEngine(engine);
}
