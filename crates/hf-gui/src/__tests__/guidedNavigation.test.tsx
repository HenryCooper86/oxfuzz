// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { Sidebar } from "../components/Sidebar";
import { WorkflowView } from "../views/WorkflowView";
import { I18nProvider } from "../i18n";
import { PipelineContext, usePipeline } from "../providers/pipeline";
const project = vi.hoisted(() => ({ activeProject: "/fixture", recentProjects: ["/fixture"], removeRecent: vi.fn(), setActiveProject: vi.fn() }));
vi.mock("../providers/project", () => ({ useProject: () => project }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ target: "parse" }) }));
vi.mock("../lib", () => ({ useDefectDojo: () => ({ configured: true }), pickFolder: vi.fn() }));
vi.mock("../views/DiscoverView", () => ({ DiscoverView: () => <p>Discovery content</p> }));
vi.mock("../views/HarnessView", () => ({ HarnessView: () => <p>Harness content</p> }));
vi.mock("../views/RunView", () => ({ RunView: () => <p>Run content</p> }));
vi.mock("../views/TriageView", () => ({ TriageView: () => <p>Findings content</p> }));
it("keeps specialist tools discoverable and identifies a directly opened tool", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host); const navigate = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><Sidebar activeView="workflow" onNavigate={navigate} onNewTarget={vi.fn()} onSelectTarget={vi.fn()} /></I18nProvider>));
    const details = host.querySelector("details"); expect(details).not.toBeNull(); expect(details?.open).toBe(false);
    expect([...host.querySelectorAll("button")].filter(button => !button.closest("details")).length).toBeLessThan(13);
    await act(async () => { details!.open = true; });
    const auto = [...host.querySelectorAll("button")].find(button => button.textContent === "Automotive")!;
    await act(async () => auto.click()); expect(navigate).toHaveBeenCalledWith("automotive");
    await act(async () => root.render(<I18nProvider><Sidebar activeView="automotive" onNavigate={navigate} onNewTarget={vi.fn()} onSelectTarget={vi.fn()} /></I18nProvider>));
    expect(host.querySelector("details")?.open).toBe(true);
    expect(host.querySelector('[aria-current="page"]')?.textContent).toBe("Automotive");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
it("offers navigation to the next workflow stage without starting work", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); Element.prototype.scrollIntoView = vi.fn();
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  function Fixture() {
    const progress = usePipeline();
    return <PipelineContext.Provider value={{ ...progress, coreStages: progress.coreStages.map(stage => ({ ...stage, done: stage.id === "discover", current: stage.id === "harness" })) }}><WorkflowView /></PipelineContext.Provider>;
  }
  try {
    await act(async () => root.render(<I18nProvider><Fixture /></I18nProvider>));
    const next = [...host.querySelectorAll("button")].find(button => button.textContent?.startsWith("Next:"));
    expect(next).toBeTruthy(); await act(async () => next!.click());
    expect(host.textContent).toContain("Harness content");
    expect(host.querySelector('[aria-expanded="true"]')?.textContent).toContain("Generate Harness");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
