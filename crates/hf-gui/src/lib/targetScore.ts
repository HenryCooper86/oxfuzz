import type { TargetCandidate } from "../types";
import { candidateTargetSelector } from "./harnessScope";

/** Which evidence produced a target's headline score. */
export type TargetScoreSource = "ai" | "semgrep" | "scan";

/**
 * The one 0-100 score shown for a target. The AI assessment is the most
 * informed, then the Semgrep-adjusted scan, then the plain code scan. The
 * other numbers stay available as supporting detail.
 */
export function targetScore(
  fitScore: number,
  assessment?: { advisory_score: number },
  semgrepEffective?: number,
): { value: number; source: TargetScoreSource } {
  const [raw, source]: [number, TargetScoreSource] = assessment
    ? [assessment.advisory_score, "ai"]
    : semgrepEffective !== undefined
      ? [semgrepEffective, "semgrep"]
      : [fitScore, "scan"];
  return { value: Math.min(100, Math.max(0, Math.round(raw * 100))), source };
}

/**
 * Harness target options, ordered and labelled by the same headline score the
 * Discover card shows. Duplicate symbols use the file-qualified selector.
 */
export function harnessTargetOptions(
  candidates: readonly TargetCandidate[],
  selectedTarget: string,
  assessments: readonly { target_id: string; advisory_score: number }[],
  semgrepEffective: ReadonlyMap<string, number>,
): { value: string; label: string }[] {
  const assessmentById = new Map(assessments.map((assessment) => [assessment.target_id, assessment]));
  return candidates
    .map((candidate) => ({
      candidate,
      score: targetScore(candidate.fit_score, assessmentById.get(candidate.id), semgrepEffective.get(candidate.id)).value,
    }))
    .sort((left, right) => right.score - left.score)
    .map(({ candidate, score }) => {
      const qualified = candidateTargetSelector(candidate);
      const duplicate = candidates.filter((other) => other.symbol === candidate.symbol).length > 1;
      const value = selectedTarget === qualified || duplicate ? qualified : candidate.symbol;
      return { value, label: `${value} · ${score}/100` };
    });
}
