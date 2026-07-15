import { RotateCcw } from "lucide-react";
import { useI18n } from "../i18nContext";

export interface AutoRevertPolicyView {
  enabled: boolean;
  threshold_pct: number;
  notify_only: boolean;
}

// A compact badge describing an auto-revert policy. Used in the Projects list
// (override-only, accent) and on the Workbench header for the active project's
// effective policy (with a project/global scope suffix). `overridden` colours it
// and drives the optional scope suffix.
export function AutoRevertBadge({
  policy,
  overridden,
  showScope = false,
}: {
  policy: AutoRevertPolicyView;
  overridden: boolean;
  showScope?: boolean;
}) {
  const { t } = useI18n();
  const { enabled, threshold_pct, notify_only } = policy;
  const label = !enabled
    ? t("autoRevert.off")
    : notify_only
      ? t("autoRevert.notify", { pct: threshold_pct })
      : t("autoRevert.on", { pct: threshold_pct });
  const color = overridden ? "var(--accent)" : "var(--text-muted)";
  const scope = showScope ? ` · ${overridden ? t("autoRevert.project") : t("autoRevert.global")}` : "";
  const tip = overridden
    ? t("autoRevert.tipOverride", {
        label: label.toLowerCase(),
        extra: enabled && notify_only ? t("autoRevert.detectOnly") : "",
      })
    : t("autoRevert.tipInherit", { label: label.toLowerCase() });
  return (
    <span
      className="inline-flex items-center gap-1 text-xs rounded-full whitespace-nowrap"
      style={{
        padding: "2px 8px",
        border: `1px solid ${color}`,
        color,
        background: "var(--surface-secondary)",
      }}
      title={tip}
    >
      <RotateCcw size={11} />
      {label}
      {scope}
    </span>
  );
}
