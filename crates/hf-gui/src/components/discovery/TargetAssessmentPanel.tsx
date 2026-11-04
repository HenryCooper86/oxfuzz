import { useI18n } from "../../i18nContext";
import type { TargetAssessment } from "../../types";
import { targetScore } from "../../lib/targetScore";

/** The one headline score for a target, labelled with the evidence behind it. */
export function TargetScore({
  fitScore,
  assessment,
  semgrepEffective,
  color,
}: {
  fitScore: number;
  assessment?: TargetAssessment;
  semgrepEffective?: number;
  color: string;
}) {
  const { t } = useI18n();
  const score = targetScore(fitScore, assessment, semgrepEffective);
  return (
    <div data-testid="target-score" className="flex flex-col items-end shrink-0" title={t("discover.scoreTitle")}>
      <span className="font-mono" style={{ color, fontWeight: 600 }}>
        <span className="text-base">{score.value}</span>
        <span className="text-xs text-text-muted">/100</span>
      </span>
      <span className="text-xs text-text-muted">{t(`discover.scoreSource.${score.source}`)}</span>
    </div>
  );
}

/** Recommendation and the AI's plain-language reason, shown on every card. */
export function TargetAssessmentPanel({
  assessment,
  recommended,
}: {
  assessment?: TargetAssessment;
  recommended: boolean;
}) {
  const { t } = useI18n();
  if (!assessment) {
    return <div className="px-3 pb-2 text-xs text-text-muted">{t("discover.scanOnly")}</div>;
  }
  return (
    <div className="px-3 pb-2 flex flex-col gap-1">
      {recommended && <strong className="text-sm text-accent">{t("discover.recommendedFirst")}</strong>}
      <p className="text-xs text-text-secondary m-0">{assessment.rationale}</p>
    </div>
  );
}

/** The AI's factor ratings, shown under "Why this score". */
export function AssessmentFactors({ assessment }: { assessment: TargetAssessment }) {
  const { t } = useI18n();
  const factors = [
    ["discover.bugPotential", assessment.bug_potential],
    ["discover.reachableCode", assessment.reachable_code],
    ["discover.harnessFeasibility", assessment.harness_feasibility],
  ] as const;
  return (
    <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(118px, 1fr))" }}>
      {factors.map(([label, rating]) => (
        <div key={label} className="rounded-md px-2 py-1.5" style={{ background: "var(--surface-active)" }}>
          <div className="text-xs text-text-secondary">{t(label)}</div>
          <div className="font-mono text-sm text-text-primary">
            {rating === null ? t("discover.unknown") : `${rating}/4`}
          </div>
        </div>
      ))}
    </div>
  );
}
