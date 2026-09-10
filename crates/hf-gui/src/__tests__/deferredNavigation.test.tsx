// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import App from "../App";
import type { ViewType } from "../types";

const loaded = vi.hoisted(() => new Set<string>());
vi.mock("../lib", async () => ({
  ...await vi.importActual("../lib"),
  getTransport: () => ({ invoke: async () => [], listen: async () => () => {} }),
  pickFolder: async () => "/fixture-project",
}));
vi.mock("../components/Sidebar", () => ({
  Sidebar: ({ onNavigate, onNewTarget }: { onNavigate: (view: ViewType) => void; onNewTarget: () => void }) => <nav>
    <button onClick={onNewTarget}>Open project</button>
    {(["dashboard", "workflow", "discover", "harness", "run", "triage", "settings"] as const).map(view =>
      <button key={view} onClick={() => onNavigate(view)}>{view}</button>)}
  </nav>,
}));
vi.mock("../components/Header", () => ({ Header: () => null }));
vi.mock("../components/StatusBar", () => ({ StatusBar: () => null }));
vi.mock("../components/RecoveryBanner", () => ({ RecoveryBanner: () => null }));
vi.mock("../components/CommandPalette", () => ({ CommandPalette: () => null }));
vi.mock("../components/ProgressPanel", () => ({ ProgressPanel: () => null }));
vi.mock("../views/DashboardView", () => ({ DashboardView: () => <p>Dashboard ready</p> }));
vi.mock("../views/WorkflowView", () => { loaded.add("workflow"); return { WorkflowView: () => <p>workflow ready</p> }; });
vi.mock("../views/DiscoverView", () => { loaded.add("discover"); return { DiscoverView: () => <p>discover ready</p> }; });
vi.mock("../views/HarnessView", () => { loaded.add("harness"); return { HarnessView: () => <p>harness ready</p> }; });
vi.mock("../views/RunView", () => { loaded.add("run"); return { RunView: () => <p>run ready</p> }; });
vi.mock("../views/TriageView", () => { loaded.add("triage"); return { TriageView: () => <p>triage ready</p> }; });
vi.mock("../components/settings/SettingsView", () => {
  loaded.add("settings");
  return { SettingsView: ({ onBack }: { onBack: () => void }) => <button onClick={onBack}>Close settings</button> };
});

it("keeps deferred modules out of startup, loads requested views, and returns from Settings", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  localStorage.setItem("hf_setup_completed", "true");
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const click = async (label: string) => {
    const button = [...host.querySelectorAll("button")].find(button => button.textContent === label);
    expect(button, label).toBeTruthy();
    await act(async () => button!.click());
  };
  try {
    await act(async () => root.render(<App />));
    expect(host.textContent).toContain("Dashboard ready");
    expect([...loaded]).toEqual([]);
    for (const view of ["workflow", "discover", "harness", "run", "triage"]) {
      await click(view);
      await act(async () => { await vi.waitFor(() => expect(loaded.has(view)).toBe(true)); });
      expect(host.textContent).toContain(`${view} ready`);
      expect(host.querySelector("nav")).not.toBeNull();
    }
    await click("settings");
    await act(async () => { await vi.waitFor(() => expect(loaded.has("settings")).toBe(true)); });
    await click("Close settings");
    expect(host.textContent).toContain("triage ready");
    await click("Open project");
    expect(host.textContent).toContain("workflow ready");
  } finally {
    await act(async () => root.unmount());
    host.remove();
    localStorage.clear();
    vi.unstubAllGlobals();
  }
});

it("remembers setup deferral and lets the user return without claiming completion", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  const host = document.createElement("div"); document.body.append(host);
  const root = createRoot(host);
  const click = async (label: string) => {
    const button = [...host.querySelectorAll("button")].find(button => button.textContent === label);
    expect(button, host.textContent ?? "").toBeTruthy();
    await act(async () => button!.click());
  };
  try {
    await act(async () => root.render(<App />));
    await click("Set up later");
    expect(localStorage.getItem("hf_setup_completed")).not.toBe("true");
    expect(localStorage.getItem("hf_setup_deferred")).toBe("true");
    expect(host.textContent).toContain("Setup is unfinished");
    await act(async () => root.render(null));
    await act(async () => root.render(<App />));
    expect(host.textContent).toContain("Setup is unfinished");
    await click("Finish setup");
    expect(host.textContent).toContain("AI connection");
  } finally {
    await act(async () => root.unmount()); host.remove(); localStorage.clear(); vi.unstubAllGlobals();
  }
});
