import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ScheduleRecoveryPanel } from "../components/ScheduleRecoveryPanel";

describe("ScheduleRecoveryPanel", () => {
  it("renders durable evidence and the acknowledgement action", () => {
    const html = renderToStaticMarkup(
      <ScheduleRecoveryPanel
        recoveries={[
          {
            occurrence_id: "occ-1",
            schedule_id: "schedule-1",
            schedule_name: "nightly parser",
            execution_id: "exec-1",
            triggered_at: "2026-07-29T01:00:00Z",
            state: "running",
            recovery_detail: "terminal outcome is unknown",
            schedule_exists: true,
          },
        ]}
        title="Recovery required"
        actionLabel="Acknowledge as cancelled"
        unknownScheduleLabel="Deleted schedule"
        onAcknowledge={() => undefined}
      />,
    );

    expect(html).toContain("nightly parser");
    expect(html).toContain("running");
    expect(html).toContain("terminal outcome is unknown");
    expect(html).toContain("Acknowledge as cancelled");
  });

  it("renders nothing when no recovery is required", () => {
    const html = renderToStaticMarkup(
      <ScheduleRecoveryPanel
        recoveries={[]}
        title="Recovery required"
        actionLabel="Acknowledge as cancelled"
        unknownScheduleLabel="Deleted schedule"
        onAcknowledge={() => undefined}
      />,
    );
    expect(html).toBe("");
  });
});
