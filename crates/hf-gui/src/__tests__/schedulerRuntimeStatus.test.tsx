import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import { SchedulerRuntimeStatus } from "../components/SchedulerRuntimeStatus";

it("distinguishes a stopped loop, disarmed execution, and unavailable status", () => {
  const render = (state: "failed" | "running" | "stopped", armed: boolean) => renderToStaticMarkup(
    <I18nProvider><SchedulerRuntimeStatus status={{ state, armed }} /></I18nProvider>,
  );
  expect(render("failed", true)).toContain("Restart the service");
  expect(render("failed", true)).toContain('role="alert"');
  expect(render("running", false)).toContain("Execution is disarmed");
  expect(render("running", true)).toContain("Scheduler is running");
  expect(render("stopped", true)).toContain("Scheduler is stopped");
  expect(renderToStaticMarkup(<I18nProvider><SchedulerRuntimeStatus status={null} /></I18nProvider>)).toContain("Scheduler status is unavailable");
});
