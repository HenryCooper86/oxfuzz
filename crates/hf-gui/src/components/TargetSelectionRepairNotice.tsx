import { useI18n } from "../i18nContext";
import { formatRetiredEngineError } from "../lib/retiredEngine";
import type { TargetSelectionRepair, TargetStorageError } from "../providers/target";
import { Button, Select } from "./ui";

const GUIDANCE_ID = "target-selection-repair-guidance";
const REPLACEMENT_ENGINE_LABEL_ID = "target-selection-replacement-engine-label";
const REPLACEMENT_ENGINE_SELECT_ID = "target-selection-replacement-engine";
const PROJECT_IDENTITY_LIMIT = 120;
const PROJECT_TRUNCATION_MARKER = "… [truncated]";

interface TargetSelectionRepairNoticeProps {
  repair: TargetSelectionRepair | null;
  storageError: TargetStorageError | null;
  activeProject: string;
  engineOptions: { value: string; label: string }[];
  onSelectEngine: (engine: string) => void;
  onSwitchProject: (project: string) => void;
  onReset: () => void;
  onRetryStorage: () => void;
}

function boundedProjectIdentity(project: string): string {
  if (project.length <= PROJECT_IDENTITY_LIMIT) return project;
  return `${project.slice(0, PROJECT_IDENTITY_LIMIT - PROJECT_TRUNCATION_MARKER.length)}${PROJECT_TRUNCATION_MARKER}`;
}

/** Explain a fail-closed persisted selection and require explicit recovery. */
export function TargetSelectionRepairNotice({
  repair,
  storageError,
  activeProject,
  engineOptions,
  onSelectEngine,
  onSwitchProject,
  onReset,
  onRetryStorage,
}: TargetSelectionRepairNoticeProps) {
  const { t } = useI18n();
  const message = repair?.issue.kind === "retired_engine"
    ? formatRetiredEngineError(repair.issue.value)
    : repair
      ? t("targetSelection.invalid")
      : t(storageError?.operation === "read" ? "targetSelection.storageReadError" : "targetSelection.storageWriteError");
  const repairOwner = repair?.projectKey ?? null;
  const canReplace = repairOwner !== null && repairOwner === activeProject;
  const inactiveOwner = repairOwner !== null && repairOwner !== activeProject;
  const globalRepair = repair !== null && repairOwner === null;
  const guidance = canReplace
    ? t("targetSelection.repairGuidance")
    : inactiveOwner
      ? t("targetSelection.switchProjectGuidance")
      : t(storageError?.operation === "read" ? "targetSelection.retryStorageGuidance" : "targetSelection.resetGuidance");

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
      {inactiveOwner && (
        <p className="text-xs text-text-secondary" role="status">
          {t("targetSelection.repairProject", { project: boundedProjectIdentity(repairOwner) })}
        </p>
      )}
      <p id={GUIDANCE_ID} className="text-xs text-text-secondary">
        {guidance}
      </p>
      <div className="flex items-end gap-2">
        {canReplace && (
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
        )}
        {inactiveOwner && (
          <Button variant="outline" size="sm" onClick={() => onSwitchProject(repairOwner)}>
            {t("targetSelection.switchProject")}
          </Button>
        )}
        {globalRepair && (
          <Button variant="outline" size="sm" onClick={onReset}>
            {t("targetSelection.reset")}
          </Button>
        )}
        {storageError?.operation === "read" && (
          <Button variant="outline" size="sm" onClick={onRetryStorage}>
            {t("targetSelection.retryStorage")}
          </Button>
        )}
      </div>
    </div>
  );
}
