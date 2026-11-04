// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { SchedulerRuntimeStatus } from "../components/SchedulerRuntimeStatus";

it("distinguishes a stopped loop, disarmed execution, and unavailable status", () => {
  const render = (state: "failed" | "running" | "stopped", armed: boolean) => renderToStaticMarkup(
    <I18nProvider><SchedulerRuntimeStatus status={{ state, armed }} /></I18nProvider>,
  );
  expect(render("failed", true)).toContain("Restart the service");
  expect(render("failed", true)).toContain('role="alert"');
  expect(render("running", false)).toContain("Scheduled runs are not authorized yet");
  expect(render("running", true)).toContain("Scheduler is running");
  expect(render("stopped", true)).toContain("Scheduler is stopped");
  expect(renderToStaticMarkup(<I18nProvider><SchedulerRuntimeStatus status={null} /></I18nProvider>)).toContain("Scheduler status is unavailable");
});

it("offers an explicit authorize or withdraw action only while the scheduler runs", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  const onArm = vi.fn();
  const labels = () => [...host.querySelectorAll("button")].map(button => button.textContent);
  const render = async (state: "running" | "stopped", armed: boolean) =>
    act(async () => root.render(<I18nProvider><SchedulerRuntimeStatus status={{ state, armed }} onArm={onArm} /></I18nProvider>));
  try {
    await render("running", false);
    expect(labels()).toEqual(["Authorize scheduled runs"]);
    await act(async () => host.querySelector("button")!.click());
    expect(onArm).toHaveBeenCalledWith(true);
    await render("running", true);
    expect(labels()).toEqual(["Withdraw authorization"]);
    await act(async () => host.querySelector("button")!.click());
    expect(onArm).toHaveBeenCalledWith(false);
    await render("stopped", false);
    expect(labels()).toEqual([]);
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
