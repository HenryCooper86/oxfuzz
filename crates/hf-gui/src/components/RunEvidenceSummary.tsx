import type { RunHistoryItem } from "../types";
import { useI18n } from "../i18nContext";
import { Button } from "./ui";

export function RunOutcomeNotice({ crashes }: { crashes: number }) {
  const { t } = useI18n();
  return <div className="flex flex-col gap-2">
    <p className="text-sm">{crashes === 0 ? t("results.noCrashes") : t("results.crashes", { n: crashes })}</p>
    <p className="text-xs text-text-secondary">{t("results.limit")}</p>
  </div>;
}

export function RunEvidenceSummary({ run, onFindings, onReport }: {
  run: RunHistoryItem;
  onFindings?: () => void;
  onReport?: () => void;
}) {
  const { t } = useI18n();
  return <section className="flex flex-col gap-2 mb-4" aria-label={t("results.scope")}>
    <h3 className="text-sm font-semibold">{t("results.scope")}</h3>
    <p className="text-xs break-all">{run.project_root} · {run.target_selector ?? run.target ?? t("runs.unknownTarget")}</p>
    <p className="text-xs">{run.engine} · {run.status} · {run.requested_duration_secs === null ? t("results.budgetUnknown") : t("results.budget", { value: run.requested_duration_secs })}</p>
    <RunOutcomeNotice crashes={run.crashes} />
    <p className="text-xs text-text-secondary">{run.edges === null ? t("results.coverageUnknown") : t("results.coverage", { n: run.edges })}</p>
    <div className="flex flex-wrap gap-2">
      {onFindings && <Button onClick={onFindings}>{t("results.findings")}</Button>}
      {onReport && <Button onClick={onReport}>{t("results.reports")}</Button>}
    </div>
  </section>;
}
