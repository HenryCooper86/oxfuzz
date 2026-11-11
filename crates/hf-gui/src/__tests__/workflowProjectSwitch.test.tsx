// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { WorkflowView } from "../views/WorkflowView";
import { I18nProvider } from "../i18n";

const state = vi.hoisted(() => ({
  project: "/finished",
  stages: [{ id: "discover", current: false, done: true }, { id: "triage", current: true, done: false }],
}));
vi.mock("../lib", () => ({ pickFolder: vi.fn() }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: state.project, recentProjects: [], setActiveProject: vi.fn() }) }));
vi.mock("../providers/pipeline", () => ({ usePipeline: () => ({ coreStages: state.stages }) }));
vi.mock("../views/DiscoverView", () => ({ DiscoverView: () => <p>Discover content</p> }));
vi.mock("../views/HarnessView", () => ({ HarnessView: () => null }));
vi.mock("../views/RunView", () => ({ RunView: () => null }));
vi.mock("../views/TriageView", () => ({ TriageView: () => <p>Triage content</p> }));
vi.mock("../components/OneClickFuzz", () => ({ OneClickFuzz: () => null }));

function openStage(host: HTMLElement): string | null {
  return host.querySelector('[aria-expanded="true"]')?.getAttribute("aria-controls") ?? null;
}

it("opens the new project's current stage instead of the stage the last project was on", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const originalScroll = HTMLElement.prototype.scrollIntoView;
  HTMLElement.prototype.scrollIntoView = vi.fn();
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><WorkflowView /></I18nProvider>));
    expect(openStage(host)).toBe("workflow-stage-triage");

    state.project = "/fresh";
    state.stages = [{ id: "discover", current: true, done: false }, { id: "triage", current: false, done: false }];
    await act(async () => root.render(<I18nProvider><WorkflowView /></I18nProvider>));
    expect(openStage(host)).toBe("workflow-stage-discover");
    expect(host.textContent).toContain("Discover content");
  } finally { await act(async () => root.unmount()); host.remove(); HTMLElement.prototype.scrollIntoView = originalScroll; vi.unstubAllGlobals(); }
});
