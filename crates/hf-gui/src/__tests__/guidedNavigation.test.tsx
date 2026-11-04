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
vi.mock("../views/DiscoverView", () => ({ DiscoverView: ({ onNavigate }: { onNavigate: (view: "settings") => void }) => <button onClick={() => onNavigate("settings")}>Open AI Settings</button> }));
vi.mock("../views/HarnessView", () => ({ HarnessView: ({ onApproved }: { onApproved?: (scope: { project: string; target: string; engine: string }) => void }) => <>
  <p>Harness content</p>
  <button onClick={() => onApproved?.({ project: "/fixture", target: "parse", engine: "libfuzzer" })}>Approve mock</button>
</> }));
const oneClick = vi.hoisted(() => ({ approved: vi.fn() }));
vi.mock("../components/OneClickFuzz", () => ({ OneClickFuzz: ({ apiRef }: { apiRef?: (api: { approved: typeof oneClick.approved }) => void }) => { apiRef?.({ approved: oneClick.approved }); return <p>One click</p>; } }));
vi.mock("../views/RunView", () => ({ RunView: ({ onNavigate }: { onNavigate: (view: string) => void }) => <>
  <p>Run content</p>
  <button onClick={() => onNavigate("runs")}>Open Run History</button>
  <button onClick={() => onNavigate("triage")}>Open Triage</button>
  <button onClick={() => onNavigate("workflow")}>Open guided workflow</button>
</> }));
vi.mock("../views/TriageView", () => ({ TriageView: () => <p>Findings content</p> }));
it("shows every tool in always-visible sections and marks the open tool", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host); const navigate = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><Sidebar activeView="workflow" onNavigate={navigate} onNewTarget={vi.fn()} onSelectTarget={vi.fn()} /></I18nProvider>));
    // Nothing is hidden behind a collapsible group.
    expect(host.querySelector("details")).toBeNull();
    expect(host.querySelector("[aria-expanded]")).toBeNull();
    const labels = [...host.querySelectorAll("button")].map(button => button.textContent);
    for (const tool of ["Discover", "Harness", "Run", "Corpus", "Artifacts", "Change Review", "Policy Audit", "Agents", "Skills", "Knowledge", "Automation", "Automotive", "DefectDojo"]) {
      expect(labels).toContain(tool);
    }
    const auto = [...host.querySelectorAll("button")].find(button => button.textContent === "Automotive")!;
    await act(async () => auto.click()); expect(navigate).toHaveBeenCalledWith("automotive");
    await act(async () => root.render(<I18nProvider><Sidebar activeView="automotive" onNavigate={navigate} onNewTarget={vi.fn()} onSelectTarget={vi.fn()} /></I18nProvider>));
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
it("opens AI Settings from Discover within the workflow", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  Element.prototype.scrollIntoView = vi.fn();
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  const navigate = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><WorkflowView onNavigate={navigate} /></I18nProvider>));
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Open AI Settings")!.click());
    expect(navigate).toHaveBeenCalledWith("settings");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
it("forwards non-stage destinations from an embedded stage and expands stage destinations", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); Element.prototype.scrollIntoView = vi.fn();
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  const navigate = vi.fn();
  function Fixture() {
    const progress = usePipeline();
    return <PipelineContext.Provider value={{ ...progress, coreStages: progress.coreStages.map(stage => ({ ...stage, done: stage.id === "discover" || stage.id === "harness", current: stage.id === "run" })) }}><WorkflowView onNavigate={navigate} /></PipelineContext.Provider>;
  }
  const click = async (label: string) => act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === label)!.click());
  try {
    await act(async () => root.render(<I18nProvider><Fixture /></I18nProvider>));
    expect(host.textContent).toContain("Run content");
    // A view the workflow does not contain leaves the workflow.
    await click("Open Run History");
    expect(navigate).toHaveBeenCalledWith("runs");
    // "Open guided workflow" from inside the workflow re-opens the current stage.
    await click("Open guided workflow");
    expect(navigate).not.toHaveBeenCalledWith("workflow");
    expect(host.querySelector('[aria-expanded="true"]')?.textContent).toContain("Run Fuzzer");
    // A stage the workflow contains is expanded in place.
    await click("Open Triage");
    expect(navigate).not.toHaveBeenCalledWith("triage");
    expect(host.textContent).toContain("Findings content");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});

it("offers one-click fuzzing and forwards harness approvals to it", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); Element.prototype.scrollIntoView = vi.fn();
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  function Fixture() {
    const progress = usePipeline();
    return <PipelineContext.Provider value={{ ...progress, coreStages: progress.coreStages.map(stage => ({ ...stage, done: stage.id === "discover", current: stage.id === "harness" })) }}><WorkflowView /></PipelineContext.Provider>;
  }
  try {
    await act(async () => root.render(<I18nProvider><Fixture /></I18nProvider>));
    expect(host.textContent).toContain("One click");
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Approve mock")!.click());
    expect(oneClick.approved).toHaveBeenCalledWith({ project: "/fixture", target: "parse", engine: "libfuzzer" });
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
