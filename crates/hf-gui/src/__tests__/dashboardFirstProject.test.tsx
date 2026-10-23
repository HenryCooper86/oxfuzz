// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { DashboardView } from "../views/DashboardView";
import { I18nProvider } from "../i18n";
const mocks = vi.hoisted(() => ({ invoke: vi.fn(() => new Promise(() => {})), toast: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }), onDataChanged: () => () => {}, openExternal: vi.fn(), useDefectDojo: () => ({ configured: false }) }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "" }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ target: "" }) }));
vi.mock("../providers/findingSelection", () => ({ useFindingSelection: () => ({ selectFinding: vi.fn() }) }));
vi.mock("../providers/confirm", () => ({ useConfirm: () => vi.fn() }));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: mocks.toast }) }));
it("offers guided first-project setup and retained workflow budget without fetching project data", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  const host = document.createElement("div"); document.body.append(host);
  const root = createRoot(host); const navigate = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><DashboardView onNavigate={navigate} /></I18nProvider>));
    expect(host.textContent).toContain("Start with a project");
    expect(mocks.invoke.mock.calls).toEqual([["model_budget_view"]]);
    expect(host.textContent).toContain("Model budget");
    const setup = [...host.querySelectorAll("button")].find((button) => button.textContent === "Open project workflow")!;
    expect(setup).toBeTruthy();
    await act(async () => setup.click());
    expect(navigate).toHaveBeenCalledWith("workflow");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
