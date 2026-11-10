// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import App from "../App";
vi.mock("../lib", async () => ({ ...(await vi.importActual<typeof import("../lib")>("../lib")), getTransport: () => ({ invoke: async () => [], listen: async () => () => {} }) }));
vi.mock("../views/DashboardView", () => ({ DashboardView: () => <p>Dashboard</p> }));
vi.mock("../components/Sidebar", () => ({ Sidebar: () => null }));
vi.mock("../components/StatusBar", () => ({ StatusBar: () => null }));
vi.mock("../components/RecoveryBanner", () => ({ RecoveryBanner: () => null }));
vi.mock("../components/CommandPalette", () => ({ CommandPalette: () => null }));
vi.mock("../components/ProgressPanel", () => ({ ProgressPanel: () => <div data-panel="progress" /> }));
vi.mock("../components/observation/DiagnosticsPanel", () => ({ DiagnosticsPanel: () => <div data-panel="diagnostics" /> }));
vi.mock("../components/observation/ObservabilityPanel", () => ({ ObservabilityPanel: () => <div data-panel="providers" /> }));
vi.mock("../components/observation/InfoPanel", () => ({ InfoPanel: () => <div data-panel="info" /> }));
it("opens at most one header panel and exposes the pressed selection", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.clear(); localStorage.setItem("hf_setup_completed", "true");
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<App />));
    for (const name of ["Progress", "Diagnostics", "Observability", "Info", "Progress"]) {
      const button = host.querySelector<HTMLButtonElement>(`button[aria-label="${name}"]`)!;
      await act(async () => button.click());
      expect(host.querySelectorAll("[data-panel]")).toHaveLength(1);
      expect(button.getAttribute("aria-pressed")).toBe("true");
    }
    await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Progress"]')!.click());
    expect(host.querySelectorAll("[data-panel]")).toHaveLength(0);
  } finally { await act(async () => root.unmount()); host.remove(); localStorage.clear(); vi.unstubAllGlobals(); }
});
