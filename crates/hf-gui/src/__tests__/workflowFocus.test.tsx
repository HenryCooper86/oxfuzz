// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { WorkflowView } from "../views/WorkflowView";
import { I18nProvider } from "../i18n";
vi.mock("../lib", () => ({ pickFolder: vi.fn() }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/sample", recentProjects: [], setActiveProject: vi.fn() }) }));
vi.mock("../providers/pipeline", () => ({ usePipeline: () => ({ coreStages: [{ id: "discover", current: true, done: false }] }) }));
vi.mock("../views/DiscoverView", () => ({ DiscoverView: ({ onNavigate }: { onNavigate: (view: string) => void }) => <button onClick={() => onNavigate("harness")}>Use this target and continue</button> }));
vi.mock("../views/HarnessView", () => ({ HarnessView: () => <p>Harness content</p> }));
vi.mock("../views/RunView", () => ({ RunView: () => null }));
vi.mock("../views/TriageView", () => ({ TriageView: () => null }));
it("moves keyboard focus to the destination stage after an explicit handoff", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("HTMLElement", HTMLElement);
  const originalScroll = HTMLElement.prototype.scrollIntoView;
  HTMLElement.prototype.scrollIntoView = vi.fn();
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><WorkflowView /></I18nProvider>));
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Use this target and continue")!.click());
    expect(document.activeElement?.getAttribute("aria-controls")).toBe("workflow-stage-harness");
  } finally { await act(async () => root.unmount()); host.remove(); HTMLElement.prototype.scrollIntoView = originalScroll; vi.unstubAllGlobals(); }
});
