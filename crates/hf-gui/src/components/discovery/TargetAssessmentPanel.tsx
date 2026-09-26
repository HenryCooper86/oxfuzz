import { useI18n } from "../../i18nContext";
import type { TargetAssessment } from "../../types";

export function TargetAssessmentPanel({
  assessment,
  recommended,
}: {
  assessment?: TargetAssessment;
  recommended: boolean;
}) {
  const { t } = useI18n();
  if (!assessment) {
    return <div className="px-3 pb-3 text-xs text-text-muted">{t("discover.scanOnly")}</div>;
  }
  const factors = [
    ["discover.bugPotential", assessment.bug_potential],
    ["discover.reachableCode", assessment.reachable_code],
    ["discover.harnessFeasibility", assessment.harness_feasibility],
  ] as const;
  return (
    <div className="px-3 pb-3 flex flex-col gap-2">
      {recommended && <strong className="text-sm text-accent">{t("discover.recommendedFirst")}</strong>}
      <div className="flex items-baseline gap-2">
        <span className="text-xs text-text-secondary">{t("discover.advisoryScore")}</span>
        <strong className="font-mono text-base text-text-primary">{Math.round(assessment.advisory_score * 100)}/100</strong>
      </div>
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
      <p className="text-xs text-text-secondary m-0">{assessment.rationale}</p>
    </div>
  );
}
