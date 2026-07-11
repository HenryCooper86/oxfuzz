import type { RunHistoryItem } from "../types";

export interface RunComparisons {
  /** Index of the newest earlier comparable run, or -1. */
  baselineAt: number[];
  /** The harness revision changed versus that comparable baseline. */
  changeAt: boolean[];
  /** Coverage fell after a revision change versus that comparable baseline. */
  regressAt: boolean[];
}

/**
 * Derive revision changes and coverage regressions without comparing unrelated
 * targets, engines, budgets, sanitizers, corpora, or execution environments.
 * Runs must be ordered oldest to newest. The service owns the opaque comparison
 * key so this UI helper cannot drift from the rollback policy.
 */
export function buildRunComparisons(runs: RunHistoryItem[]): RunComparisons {
  const baselineAt = runs.map((run, index) => {
    if (!run.comparison_key) return -1;
    for (let candidate = index - 1; candidate >= 0; candidate -= 1) {
      if (runs[candidate].comparison_key === run.comparison_key) return candidate;
    }
    return -1;
  });
  const changeAt = runs.map((run, index) => {
    const baseline = baselineAt[index];
    return (
      baseline >= 0 &&
      run.harness_rev != null &&
      runs[baseline].harness_rev != null &&
      run.harness_rev !== runs[baseline].harness_rev
    );
  });
  const regressAt = runs.map((run, index) => {
    const baseline = baselineAt[index];
    return (
      changeAt[index] &&
      baseline >= 0 &&
      run.edges != null &&
      runs[baseline].edges != null &&
      run.edges < runs[baseline].edges!
    );
  });
  return { baselineAt, changeAt, regressAt };
}
