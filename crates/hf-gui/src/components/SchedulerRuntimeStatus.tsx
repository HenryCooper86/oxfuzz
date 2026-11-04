import { useI18n } from "../i18nContext";
import { Button } from "./ui";

export interface CampaignSchedulerStatus {
  state: "stopped" | "starting" | "running" | "failed";
  armed: boolean;
}

/**
 * Scheduler liveness plus execution authorization. A scheduler starts disarmed
 * on every process start; `onArm` lets the operator make that decision here
 * instead of only through the CLI or REST API. Nothing re-arms on its own.
 */
export function SchedulerRuntimeStatus({ status, onArm, busy = false }: {
  status: CampaignSchedulerStatus | null;
  onArm?: (armed: boolean) => void;
  busy?: boolean;
}) {
  const { t } = useI18n();
  const running = status?.state === "running";
  return <div className="surface-card p-3 text-sm flex flex-wrap items-center justify-between gap-2" role={status?.state === "failed" ? "alert" : "status"}>
    <div className="flex flex-col">
      <p className="m-0">{t(`automation.runtime.${status?.state ?? "unavailable"}`)}</p>
      {running && !status.armed ? <p className="m-0 text-text-muted">{t("automation.runtime.disarmed")}</p> : null}
      {running && status.armed ? <p className="m-0 text-text-muted">{t("automation.runtime.armed")}</p> : null}
    </div>
    {running && onArm && (
      status.armed
        ? <Button variant="outline" size="sm" disabled={busy} onClick={() => onArm(false)}>{t("automation.runtime.disarm")}</Button>
        : <Button variant="primary" size="sm" disabled={busy} onClick={() => onArm(true)}>{t("automation.runtime.arm")}</Button>
    )}
  </div>;
}
