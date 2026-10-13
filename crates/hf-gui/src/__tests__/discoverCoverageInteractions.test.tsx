// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { DiscoverView } from "../views/DiscoverView";
import type { TargetCandidate } from "../types";

const mocks = vi.hoisted(() => ({ invoke: vi.fn(), snapshot: {} }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }), pickFolder: vi.fn() }));
vi.mock("../providers/discovery", () => ({ useDiscoveryInventory: () => ({ snapshot: mocks.snapshot, save: vi.fn() }) }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/sample", setActiveProject: vi.fn() }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ lang: "c", setLang: vi.fn(), target: "", setTarget: vi.fn() }) }));
let cleanup = async () => {};
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  mocks.invoke.mockReset();
  const candidates: TargetCandidate[] = ["a", "b"].map(id => ({
    id, project_root: "/sample", language: "C", symbol: "parse_value", kind: "Parser",
    location: { file: `/sample/${id}.c`, line: 1, col: 1 }, signature: null,
    input_surface: "Bytes", complexity: 1, fit_score: 0.9, sanitizers: [], rationale: "",
    reachable_functions: ["helper"], accumulated_complexity: 2,
  }));
  mocks.snapshot = { inventory: { project_root: "/sample", candidates, call_graph: { parse_value: ["helper"] } }, ranked: null, semgrep: null };
});
afterEach(async () => { await cleanup(); vi.unstubAllGlobals(); });

async function mount() {
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  await act(async () => root.render(<I18nProvider><DiscoverView embedded /></I18nProvider>));
  await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Toggle call tree node"]')!.click());
  return host;
}

it("loads coverage for the selected source when candidates share a symbol", async () => {
  mocks.invoke.mockImplementation(async command => command === "coverage_functions" ? ["helper"] : false);
  await mount();
  expect(mocks.invoke.mock.calls.filter(([command]) => command === "coverage_functions")).toEqual([
    ["coverage_functions", { project: "/sample", target: "a.c::parse_value" }],
  ]);
});

it("keeps the bare-symbol workspace used by a unique target", async () => {
  const snapshot = mocks.snapshot as { inventory: { candidates: TargetCandidate[] } };
  snapshot.inventory.candidates = snapshot.inventory.candidates.slice(0, 1);
  mocks.invoke.mockImplementation(async command => command === "coverage_functions" ? ["helper"] : false);
  await mount();
  expect(mocks.invoke.mock.calls.filter(([command]) => command === "coverage_functions")).toEqual([
    ["coverage_functions", { project: "/sample", target: "parse_value" }],
  ]);
});

it("shows failed coverage as unavailable and permits a successful retry", async () => {
  let failed = false;
  mocks.invoke.mockImplementation(async command => {
    if (command !== "coverage_functions") return false;
    if (!failed) { failed = true; throw new Error("coverage read failed"); }
    return ["helper"];
  });
  const host = await mount();
  expect(host.textContent).toContain("coverage read failed");
  expect(host.textContent).not.toContain("no coverage yet");
  const retry = [...host.querySelectorAll("button")].find(button => button.textContent === "Retry");
  expect(retry).toBeTruthy();
  await act(async () => retry!.click());
  expect(host.textContent).not.toContain("coverage read failed");
  expect(host.textContent).toContain("covered");
  expect(mocks.invoke.mock.calls.filter(([command]) => command === "coverage_functions")).toHaveLength(2);
});
