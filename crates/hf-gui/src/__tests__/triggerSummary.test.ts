import { expect, it } from "vitest";
import { formatTriggerSummary } from "../lib/duration";

it("shows an interval trigger in the units used everywhere else", () => {
  expect(formatTriggerSummary("every 3600s")).toBe("every 1 h");
  expect(formatTriggerSummary("every 90s")).toBe("every 1 min 30 s");
});

it("leaves cron and one-time summaries as the service wrote them", () => {
  expect(formatTriggerSummary("cron: 0 2 * * *")).toBe("cron: 0 2 * * *");
  expect(formatTriggerSummary("once: 2026-11-11T08:00:00Z")).toBe("once: 2026-11-11T08:00:00Z");
});
