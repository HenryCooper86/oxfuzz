// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { DiscoverView } from "../views/DiscoverView";
import { DiscoveryProvider } from "../providers/DiscoveryContext";
import { I18nProvider } from "../i18n";
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), markDone: vi.fn(), setTarget: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }), pickFolder: vi.fn() }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/sample", setActiveProject: vi.fn() }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ lang: "c", setLang: vi.fn(), target: "", setTarget: mocks.setTarget }) }));
vi.mock("../providers/pipeline", () => ({ usePipeline: () => ({ markDone: mocks.markDone }) }));
it("retains results across navigation and explicitly hands the chosen target to Harness", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const candidate = { id: "one", symbol: "parse", fit_score: 0.8, kind: "Function", complexity: 2, location: { file: "parse.c", line: 1 } };
  const inventory = { candidates: [candidate], call_graph: {} };
  mocks.invoke.mockImplementation(async command => {
    if (command === "ranked_discovery_start") return "op-1";
    if (command === "ranked_discovery_status") return { operation_id: "op-1", state: "completed", revision: 2 };
    if (command === "ranked_discovery_result") return {
      operation_id: "op-1", revision: 2, inventory, assessments: [], assessed_count: 0,
      total_count: 1, ranking_source: "heuristic", reason_code: "no_provider",
    };
    return false;
  });
  const host = document.createElement("div"); const root = createRoot(host); const navigate = vi.fn();
  const render = (show: boolean) => <I18nProvider><DiscoveryProvider>{show && <DiscoverView embedded onNavigate={navigate} />}</DiscoveryProvider></I18nProvider>;
  try {
    await act(async () => root.render(render(true)));
    await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent === "Discover")!.click());
    expect(host.textContent).toContain("parse"); expect(navigate).not.toHaveBeenCalled();
    await act(async () => root.render(render(false)));
    await act(async () => root.render(render(true)));
    expect(host.textContent).toContain("parse");
    expect(mocks.invoke.mock.calls.filter(([c]) => c === "ranked_discovery_start")).toHaveLength(1);
    await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent?.includes("Use this target"))!.click());
    expect(mocks.setTarget).toHaveBeenCalled(); expect(navigate).toHaveBeenCalledWith("harness");
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
