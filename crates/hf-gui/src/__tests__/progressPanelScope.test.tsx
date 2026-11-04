// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { progressPanelScope } from "../lib/progressPanel";
import { ProgressPanel } from "../components/ProgressPanel";
import { I18nProvider } from "../i18n";
import { ConfirmContext } from "../providers/confirm";
import { PipelineContext, usePipeline } from "../providers/pipeline";

it("treats only the pipeline screens as the progress panel's home", () => {
  for (const view of ["workflow", "discover", "harness", "run", "triage", "corpus"] as const) {
    expect(progressPanelScope(view)).toBe("pipeline");
  }
  for (const view of ["dashboard", "help", "chat", "runs", "reports", "automation", "settings"] as const) {
    expect(progressPanelScope(view)).toBe("other");
  }
});

it("keeps a separate progress toggle for pipeline and other screens in the app shell", () => {
  const app = readFileSync(resolve(__dirname, "../App.tsx"), "utf8");
  expect(app).toContain("progressPanelScope(activeView)");
  expect(app).toMatch(/other:\s*false/);
});

it("asks before resetting progress", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const reset = vi.fn();
  let answer = false;
  const confirm = vi.fn(async () => answer);
  function Fixture() {
    const progress = usePipeline();
    return <PipelineContext.Provider value={{ ...progress, reset, coreStages: progress.coreStages.map(stage => ({ ...stage, done: stage.id === "discover", current: stage.id === "harness" })) }}>
      <ConfirmContext.Provider value={confirm}><ProgressPanel /></ConfirmContext.Provider>
    </PipelineContext.Provider>;
  }
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><Fixture /></I18nProvider>));
    const button = () => [...host.querySelectorAll("button")].find(b => b.textContent === "Reset progress")!;
    await act(async () => button().click());
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(reset).not.toHaveBeenCalled();
    answer = true;
    await act(async () => button().click());
    expect(reset).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});

it("leaves the stage plan to the Progress panel instead of repeating it in Info", () => {
  const info = readFileSync(resolve(__dirname, "../components/observation/InfoPanel.tsx"), "utf8");
  expect(info).not.toContain("info.campaignPlan");
});
