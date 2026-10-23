import { useI18n } from "../i18nContext";

import { behaviorChecks } from "../lib/harnessBehavior";

export interface BehaviorCheck {
  status: "pass" | "suspect" | "unavailable";
  detail: string;
}
export interface HarnessBehaviorReport {
  input_sensitivity: BehaviorCheck;
  entry_rejection: BehaviorCheck;
  repeated_input_stability: BehaviorCheck;
  persistent_state: BehaviorCheck;
  target_coverage_growth: BehaviorCheck;
}
export function HarnessBehaviorEvidence({ report }: { report: HarnessBehaviorReport }) {
  const { t } = useI18n();
  return (
    <section className="mt-3" aria-label={t("harness.behavior.title")}>
      <h4 className="font-medium">{t("harness.behavior.title")}</h4>
      <ul className="mt-1 space-y-1">
        {behaviorChecks.map((name) => (
          <li key={name}>
            <strong>{t(`harness.behavior.${name}`)}</strong> — {t(`harness.behavior.${report[name].status}`)}: {report[name].detail}
          </li>
        ))}
      </ul>
    </section>
  );
}
