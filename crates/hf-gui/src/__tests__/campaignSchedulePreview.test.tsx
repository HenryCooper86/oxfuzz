import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import CampaignSchedulePreview, { type SchedulePreview } from "../components/CampaignSchedulePreview";
import { I18nProvider } from "../i18n";

const scheduled: SchedulePreview = {
  state: "scheduled", timezone: "Asia/Shanghai", timezone_fallback: false,
  next_fires: ["2026-09-11T01:00:00+00:00", "2026-09-12T01:00:00+00:00"],
  remaining_runs: 4, remaining_secs: 240,
};
function render(preview: SchedulePreview) {
  return renderToStaticMarkup(<I18nProvider><CampaignSchedulePreview preview={preview} /></I18nProvider>);
}

describe("CampaignSchedulePreview", () => {
  it("shows service dates in the schedule timezone with remaining allowance", () => {
    const html = render(scheduled);
    expect(html).toContain("Asia/Shanghai");
    expect(html).toContain("09:00");
    expect(html).toContain('dateTime="2026-09-11T01:00:00+00:00"');
    expect(html).toContain("4 runs remaining");
    expect(html).toContain("240s remaining");
    expect(html).toContain("<summary");
  });
  it("shows paused and exhausted states without fabricated dates", () => {
    for (const [state, label] of [["paused", "Paused"], ["budget_exhausted", "Budget spent"]] as const) {
      const html = render({ ...scheduled, state, next_fires: [], remaining_runs: 0 });
      expect(html).toContain(label);
      expect(html).not.toContain("<time");
      expect(html).toContain("0 runs remaining");
    }
  });
  it("distinguishes event timing and unbounded allowances", () => {
    const html = render({ ...scheduled, state: "waiting_for_event", next_fires: [], remaining_runs: null, remaining_secs: null });
    expect(html).toContain("Waiting for an event");
    expect(html).toContain("No budget limit");
    expect(html).not.toContain("<time");
  });
  it("uses UTC when the browser cannot format the service timezone", () => {
    const html = render({ ...scheduled, timezone: "Unsupported/BrowserZone" });
    expect(html).toContain("01:00");
    expect(html).toContain("Unknown timezone; using UTC");
  });
  it("does not describe an unavailable allowance as unlimited", () => {
    const html = render({ ...scheduled, state: "unavailable", next_fires: [], remaining_runs: null, remaining_secs: null });
    expect(html).toContain("Schedule preview unavailable");
    expect(html).not.toContain("No budget limit");
  });
  it("explains legacy timezone fallback", () => {
    expect(render({ ...scheduled, timezone: "UTC", timezone_fallback: true })).toContain("Unknown timezone; using UTC");
  });
});
