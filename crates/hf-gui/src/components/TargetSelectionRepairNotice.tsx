import { useI18n } from "../i18nContext";
import { formatRetiredEngineError } from "../lib/retiredEngine";
import type { TargetSelectionRepair, TargetStorageError } from "../providers/target";
import { Select } from "./ui";

const GUIDANCE_ID = "target-selection-repair-guidance";
const REPLACEMENT_ENGINE_LABEL_ID = "target-selection-replacement-engine-label";
const REPLACEMENT_ENGINE_SELECT_ID = "target-selection-replacement-engine";

interface TargetSelectionRepairNoticeProps {
  repair: TargetSelectionRepair | null;
  storageError: TargetStorageError | null;
  engineOptions: { value: string; label: string }[];
  onSelectEngine: (engine: string) => void;
}

/** Explain a fail-closed persisted selection and require explicit recovery. */
export function TargetSelectionRepairNotice({
  repair,
  storageError,
  engineOptions,
  onSelectEngine,
}: TargetSelectionRepairNoticeProps) {
  const { t } = useI18n();
  const message = repair?.kind === "retired_engine"
    ? formatRetiredEngineError(repair.value)
    : repair
      ? t("targetSelection.invalid")
      : t(storageError?.operation === "read" ? "targetSelection.storageReadError" : "targetSelection.storageWriteError");

  return (
    <div
      className="surface-card flex flex-col gap-2 text-sm"
      style={{ padding: "var(--space-md)", borderLeft: "3px solid var(--warning, var(--accent))" }}
    >
      <div role="alert" aria-describedby={GUIDANCE_ID}>{message}</div>
      {storageError && repair && (
        <p className="text-xs text-text-secondary" role="status">
          {t(storageError.operation === "read" ? "targetSelection.storageReadError" : "targetSelection.storageWriteError")}
        </p>
      )}
      <p id={GUIDANCE_ID} className="text-xs text-text-secondary">
        {t("targetSelection.repairGuidance")}
      </p>
      <div className="flex items-end gap-2">
        <div className="flex flex-col gap-1 w-48">
          <label id={REPLACEMENT_ENGINE_LABEL_ID} className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            {t("targetSelection.replacementEngine")}
          </label>
          <Select
            value=""
            id={REPLACEMENT_ENGINE_SELECT_ID}
            ariaLabelledBy={REPLACEMENT_ENGINE_LABEL_ID}
            options={engineOptions}
            onChange={onSelectEngine}
            placeholder={t("targetSelection.chooseEngine")}
            disabled={engineOptions.length === 0}
          />
        </div>
      </div>
    </div>
  );
}
