import { useId, useState } from "react";
import { formatMicroUsd, parseUsdLimit } from "../../lib/budgetCurrency";
import { useI18n } from "../../i18nContext";
import { Input } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";

type ConfigValue = Record<string, unknown>;
const fields = ["scope_id", "max_calls", "max_tokens", "max_cost_microusd", "max_output_tokens"] as const;

/** Edits the shared config draft; the service parses and validates all limits on save. */
export function ModelBudgetSettings({ value, onChange }: { value: ConfigValue; onChange: (value: ConfigValue) => void }) {
  const { t } = useI18n();
  const budget = (value.model_budget ?? {}) as ConfigValue;
  function update(field: string, text: string) {
    const next = { ...budget };
    if (text === "") delete next[field];
    else next[field] = text;
    onChange({ ...value, model_budget: next });
  }
  return <SettingsGroup title={t("budget.title")} description={t("budget.settingsHelp")}>
    {fields.map((field) => <SettingsItem key={field} title={t(`budget.${field}`)} description={t(`budget.${field}Help`)}>
      {field === "max_cost_microusd"
        ? <DollarLimit value={String(budget[field] ?? "")} onChange={(text) => update(field, text)} />
        : <Input aria-label={t(`budget.${field}`)} value={String(budget[field] ?? "")} inputMode={field === "scope_id" ? "text" : "numeric"} onChange={(event) => update(field, event.target.value)} />}

    </SettingsItem>)}
  </SettingsGroup>;
}

function DollarLimit({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const { t } = useI18n();
  const errorId = useId();
  const [edit, setEdit] = useState<{ stored: string; text: string } | null>(null);
  const text = edit?.stored === value ? edit.text
    : value.startsWith("invalid-usd:") ? value.slice("invalid-usd:".length)
    : value === "" ? "" : /^\d+$/.test(value) ? formatMicroUsd(value) : value;
  const invalid = !parseUsdLimit(text).valid;
  function update(next: string) {
    const parsed = parseUsdLimit(next);
    // The shared backend converter rejects this noninteger draft on Save Changes.
    const stored = parsed.valid ? parsed.microUsd ?? "" : `invalid-usd:${next}`;
    setEdit({ stored, text: next });
    onChange(stored);
  }
  return <div>
    <Input aria-label={t("budget.max_cost_microusd")} value={text} inputMode="decimal" placeholder="2.50" aria-invalid={invalid} aria-describedby={invalid ? errorId : undefined} onChange={(event) => update(event.target.value)} />
    {invalid && <p id={errorId} role="alert" className="text-status-error text-xs">{t("budget.invalidUsd")}</p>}
  </div>;
}
