import { useMemo } from "react";
import { useI18n } from "../i18nContext";

export interface SchedulePreview {
  state: "scheduled" | "due" | "paused" | "budget_exhausted" | "recovery_required" | "consumed" | "waiting_for_event" | "unavailable";
  timezone: string;
  timezone_fallback: boolean;
  next_fires: string[];
  remaining_runs: number | null;
  remaining_secs: number | null;
}

export default function CampaignSchedulePreview({ preview }: { preview: SchedulePreview }) {
  const { t, locale } = useI18n();
  const display = useMemo(() => {
    const formatIn = (timeZone: string) => new Intl.DateTimeFormat(locale === "zh" ? "zh-CN" : "en-GB", {
      timeZone, dateStyle: "medium", timeStyle: "short", hour12: false,
    });
    try {
      return { formatter: formatIn(preview.timezone), timezone: preview.timezone, fallback: false };
    } catch {
      return { formatter: formatIn("UTC"), timezone: "UTC", fallback: true };
    }
  }, [locale, preview.timezone]);
  const budget = [
    preview.remaining_runs !== null ? t("automation.preview.remainingRuns", { n: preview.remaining_runs }) : null,
    preview.remaining_secs !== null ? t("automation.preview.remainingSecs", { n: preview.remaining_secs }) : null,
  ].filter(Boolean).join(" · ");
  return (
    <div className="mt-2 flex flex-col gap-1 text-xs text-text-secondary">
      <div>
        <span>{t(`automation.preview.${preview.state}`)}</span>
        {preview.state === "scheduled" && preview.next_fires[0] ? (
          <> · <time dateTime={preview.next_fires[0]}>{display.formatter.format(new Date(preview.next_fires[0]))}</time></>
        ) : null}
        {preview.next_fires.length > 0 ? <span className="text-text-muted"> · {display.timezone}</span> : null}
      </div>
      {preview.state !== "unavailable" ? <p className="m-0 text-text-muted">{budget || t("automation.preview.unbounded")}</p> : null}
      {preview.timezone_fallback || display.fallback ? <p className="m-0" style={{ color: "var(--warning, #d9a441)" }}>{t("automation.preview.timezoneFallback")}</p> : null}
      {preview.next_fires.length > 0 ? (
        <details>
          <summary className="cursor-pointer text-text-muted">{t("automation.preview.details")}</summary>
          <ol className="my-1 pl-5 list-decimal">
            {preview.next_fires.map(at => <li key={at}><time dateTime={at}>{display.formatter.format(new Date(at))}</time> · {display.timezone}</li>)}
          </ol>
          <p className="m-0 text-text-muted">{t("automation.preview.advisory")}</p>
        </details>
      ) : null}
    </div>
  );
}
