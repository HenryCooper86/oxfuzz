// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { HarnessView } from "../views/HarnessView";
import { TriageView } from "../views/TriageView";
import { I18nProvider } from "../i18n";
const invoke = vi.hoisted(() => vi.fn(async (command: string) => command === "discover" ? { candidates: [], call_graph: {} } : []));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke, listen: async () => () => {} }), pickFolder: vi.fn(), isTauriEnvironment: () => false, onDataChanged: () => () => {} }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/sample", recentProjects: ["/sample"], setActiveProject: vi.fn() }) }));
vi.mock("../components/BuildDoctorPanel", () => ({ BuildDoctorPanel: () => <p>Build diagnosis fixture</p> }));
it("groups build configuration in optional advanced tools after the beginner explanation", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><HarnessView /></I18nProvider>));
    expect(host.textContent).toContain("A harness is a small test driver");
    const details = [...host.querySelectorAll("details")].find(d => d.querySelector("summary")?.textContent === "Advanced tools (optional)");
    expect(details?.textContent).toContain("Build diagnosis fixture");
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
it("distinguishes a project with no campaigns from filtered findings and links to the workflow", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); const root = createRoot(host); const navigate = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><TriageView onNavigate={navigate} /></I18nProvider>));
    expect(host.textContent).toContain("No campaigns yet");
    expect(host.textContent).not.toContain("No retained findings match");
    await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent === "Open guided workflow")!.click());
    expect(navigate).toHaveBeenCalledWith("workflow");
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
