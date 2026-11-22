import "../i18n.parityDiscovery";
import { useI18n } from "../i18nContext";
import { RUN_LIST_LIMITS, type RunListFilter } from "../lib/parityDiscovery";

/** Active-only and newest-N controls for the run list (`oxfuzz runs --active --limit`). */
export function RunListFilters({ value, onChange }: { value: RunListFilter; onChange: (next: RunListFilter) => void }) {
  const { t } = useI18n();
  return (
    <div className="flex items-center gap-3 flex-wrap text-xs">
      <label className="flex items-center gap-1">
        <input type="checkbox" checked={value.activeOnly} onChange={(event) => onChange({ ...value, activeOnly: event.target.checked })} />
        {t("parityDiscovery.runs.activeOnly")}
      </label>
      <label className="flex items-center gap-1">
        {t("parityDiscovery.runs.limit")}
        <select
          className="rounded border border-border bg-surface-primary p-1"
          aria-label={t("parityDiscovery.runs.limit")}
          value={value.limit === null ? "" : String(value.limit)}
          onChange={(event) => onChange({ ...value, limit: event.target.value === "" ? null : Number(event.target.value) })}
        >
          <option value="">{t("parityDiscovery.runs.limitAll")}</option>
          {RUN_LIST_LIMITS.map((n) => <option key={n} value={n}>{t("parityDiscovery.runs.limitN", { n })}</option>)}
        </select>
      </label>
    </div>
  );
}
