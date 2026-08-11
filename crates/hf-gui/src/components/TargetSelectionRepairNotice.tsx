import { useI18n } from "../i18nContext";
import { formatRetiredEngineError } from "../lib/retiredEngine";
import type { TargetSelectionRepair } from "../providers/target";
import { Button, Select } from "./ui";

const GUIDANCE_ID = "target-selection-repair-guidance";

interface TargetSelectionRepairNoticeProps {
  repair: TargetSelectionRepair;
  engineOptions: { value: string; label: string }[];
  onSelectEngine: (engine: string) => void;
  onReset: () => void;
}

/** Explain a fail-closed persisted selection and require explicit recovery. */
export function TargetSelectionRepairNotice({
  repair,
  engineOptions,
  onSelectEngine,
  onReset,
}: TargetSelectionRepairNoticeProps) {
  const { t } = useI18n();
  const message = repair.kind === "retired_engine"
    ? formatRetiredEngineError(repair.value)
    : t("targetSelection.invalid");

  return (
    <div
      className="surface-card flex flex-col gap-2 text-sm"
      style={{ padding: "var(--space-md)", borderLeft: "3px solid var(--warning, var(--accent))" }}
    >
      <div role="alert" aria-describedby={GUIDANCE_ID}>{message}</div>
      <p id={GUIDANCE_ID} className="text-xs text-text-secondary">
        {t("targetSelection.repairGuidance")}
      </p>
      <div className="flex items-end gap-2">
        <div className="flex flex-col gap-1 w-48">
          <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            {t("targetSelection.replacementEngine")}
          </label>
          <Select
            value=""
            options={engineOptions}
            onChange={onSelectEngine}
            placeholder={t("targetSelection.chooseEngine")}
            disabled={engineOptions.length === 0}
          />
        </div>
        {repair.kind === "invalid_selection" && (
          <Button variant="outline" size="sm" onClick={onReset}>
            {t("targetSelection.reset")}
          </Button>
        )}
      </div>
    </div>
  );
}
