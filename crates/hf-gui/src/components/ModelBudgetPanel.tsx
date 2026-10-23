import { formatMicroUsd } from "../lib/budgetCurrency";
import { useCallback, useEffect, useRef, useState } from "react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import { Button } from "./ui";

export interface ModelBudgetView {
  available: boolean;
  settings: { scope_id: string | null; max_calls: string | null; max_tokens: string | null; max_cost_microusd: string | null; max_output_tokens: string };
  usage: { scope_id: string; calls: string; tokens: string; cost_microusd: string; blocked: boolean; terminal_reason: string | null } | null;
}

export function ModelBudgetPanel() {
  const { t } = useI18n();
  const [view, setView] = useState<ModelBudgetView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    const current = ++generation.current;
    try {
      const next = await getTransport().invoke<ModelBudgetView>("model_budget_view");
      if (current === generation.current) { setView(next); setError(null); }
    } catch (cause) {
      if (current === generation.current) setError(String(cause));
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, []);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) void refresh(); });
    return () => { active = false; generation.current += 1; };
  }, [refresh]);
  return <section className="rounded-lg border border-border p-4" aria-label={t("budget.title")}>
    <div className="flex items-center justify-between gap-3"><h3 className="text-sm font-semibold">{t("budget.title")}</h3><Button size="sm" variant="outline" disabled={loading} onClick={() => { setLoading(true); void refresh(); }}>{t("common.refresh")}</Button></div>
    {error && <p role="alert" className="text-status-error">{error}</p>}
    {loading && <p role="status">{t("budget.loading")}</p>}
    {view && <>
      {!view.available ? <p>{t("budget.unavailable")}</p> : !view.settings.scope_id ? <p>{t("budget.disabled")}</p> : <>
        <p className="text-sm break-all">{t("budget.scope_id")}: {view.settings.scope_id}</p>
        {view.usage ? <>
          <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-3">
            {(["calls", "tokens", "cost_microusd"] as const).map((field) => <div key={field}><dt className="text-text-muted text-xs">{t(`budget.${field}`)}</dt><dd className="font-mono text-sm break-all">{field === "cost_microusd" ? `$${formatMicroUsd(view.usage![field])}` : view.usage![field]} / {view.settings[`max_${field}`] === null ? t("budget.unlimited") : field === "cost_microusd" ? `$${formatMicroUsd(view.settings.max_cost_microusd!)}` : view.settings[`max_${field}`]}</dd></div>)}
          </dl>
          {(view.usage.blocked || view.usage.terminal_reason) && <p role="status" className="text-status-warning">{view.usage.blocked ? t("budget.blocked") : t("budget.denied")}: {view.usage.terminal_reason ?? t("budget.blocked")}</p>}
        </> : <p>{t("budget.noUsage")}</p>}
      </>}
      <p className="text-xs text-text-muted mt-3">{t("budget.usageHelp")}</p>
    </>}
  </section>;
}
