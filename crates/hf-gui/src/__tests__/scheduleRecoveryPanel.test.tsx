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
        loading={false}
        error={false}
        loadingLabel="Loading recovery state"
        errorLabel="Recovery state unavailable"
        onAcknowledge={() => undefined}
      />,
    );

    expect(html).toContain("nightly parser");
    expect(html).toContain("running");
    expect(html).toContain("terminal outcome is unknown");
    expect(html).toContain("Acknowledge as cancelled");
  });

  it("renders a distinct loading state before recovery is available", () => {
    const html = renderToStaticMarkup(
      <ScheduleRecoveryPanel
        recoveries={[]}
        title="Recovery required"
        actionLabel="Acknowledge as cancelled"
        unknownScheduleLabel="Deleted schedule"
        loading
        error={false}
        loadingLabel="Loading recovery state"
        errorLabel="Recovery state unavailable"
        onAcknowledge={() => undefined}
      />,
    );
    expect(html).toContain('role="status"');
    expect(html).toContain("Loading recovery state");
  });

  it("renders recovery unavailability next to the recovery surface", () => {
    const html = renderToStaticMarkup(
      <ScheduleRecoveryPanel
        recoveries={[]}
        title="Recovery required"
        actionLabel="Acknowledge as cancelled"
        unknownScheduleLabel="Deleted schedule"
        loading={false}
        error
        loadingLabel="Loading recovery state"
        errorLabel="Recovery state unavailable"
        onAcknowledge={() => undefined}
      />,
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain("Recovery state unavailable");
  });

  it("renders nothing after a successful empty recovery response", () => {
    const html = renderToStaticMarkup(
      <ScheduleRecoveryPanel
        recoveries={[]}
        title="Recovery required"
        actionLabel="Acknowledge as cancelled"
        unknownScheduleLabel="Deleted schedule"
        loading={false}
        error={false}
        loadingLabel="Loading recovery state"
        errorLabel="Recovery state unavailable"
        onAcknowledge={() => undefined}
      />,
    );
    expect(html).toBe("");
  });
});
