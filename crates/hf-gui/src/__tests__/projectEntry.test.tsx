// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { ProjectsView } from "../views/ProjectsView";
import { I18nProvider } from "../i18n";
const mocks = vi.hoisted(() => ({ pickFolder: vi.fn(async () => "/approved/sample"), setActiveProject: vi.fn() }));
vi.mock("../lib", () => ({ pickFolder: mocks.pickFolder, getTransport: () => ({ invoke: async () => ({}) }), onDataChanged: () => () => {} }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "", recentProjects: [], setActiveProject: mocks.setActiveProject }) }));
vi.mock("../providers/confirm", () => ({ useConfirm: () => vi.fn() }));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));
it("opens a newly selected project in the guided workflow", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); const root = createRoot(host); const navigate = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><ProjectsView onNavigate={navigate} /></I18nProvider>));
    await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent?.includes("Add project"))!.click());
    expect(navigate).toHaveBeenCalledWith("workflow");
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
