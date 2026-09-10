import { useI18n } from "../i18nContext";

export interface CampaignSchedulerStatus {
  state: "stopped" | "starting" | "running" | "failed";
  armed: boolean;
}

export function SchedulerRuntimeStatus({ status }: { status: CampaignSchedulerStatus | null }) {
  const { t } = useI18n();
  return <div className="surface-card p-3 text-sm" role={status?.state === "failed" ? "alert" : "status"}>
    <p className="m-0">{t(`automation.runtime.${status?.state ?? "unavailable"}`)}</p>
    {status?.state === "running" && !status.armed ? <p className="m-0 text-text-muted">{t("automation.runtime.disarmed")}</p> : null}
  </div>;
}
