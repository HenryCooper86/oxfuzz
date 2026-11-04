// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { targetScore } from "../lib/targetScore";
import { DiscoverView } from "../views/DiscoverView";
import { DiscoveryProvider } from "../providers/DiscoveryContext";
import { I18nProvider } from "../i18n";

it("picks one 0-100 score: AI assessment first, then Semgrep, then the code scan", () => {
  expect(targetScore(0.87)).toEqual({ value: 87, source: "scan" });
  expect(targetScore(0.87, undefined, 0.912)).toEqual({ value: 91, source: "semgrep" });
  expect(targetScore(0.87, { advisory_score: 0.58 }, 0.912)).toEqual({ value: 58, source: "ai" });
  expect(targetScore(1.4).value).toBe(100);
  expect(targetScore(-0.2).value).toBe(0);
});

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }), pickFolder: vi.fn() }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/sample", recentProjects: ["/sample"], setActiveProject: vi.fn() }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ lang: "c", setLang: vi.fn(), target: "", setTarget: vi.fn() }) }));
vi.mock("../providers/pipeline", () => ({ usePipeline: () => ({ markDone: vi.fn() }) }));

it("shows one score per target card, with the rest under Why this score", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const candidate = {
    id: "a", project_root: "/sample", language: "C", symbol: "parse_number", kind: "Parser",
    location: { file: "/sample/number.c", line: 22, col: 1 }, signature: null, input_surface: "Bytes",
    complexity: 10, fit_score: 0.87, sanitizers: [], rationale: "", reachable_functions: [], accumulated_complexity: 10,
  };
  const inventory = { project_root: "/sample", candidates: [candidate], call_graph: {} };
  mocks.invoke.mockImplementation(async (command: string, args?: { operationId?: string }) => {
    if (command === "ranked_discovery_start") return "op";
    if (command === "ranked_discovery_status") return { operation_id: args?.operationId, state: "completed", revision: 2 };
    if (command === "ranked_discovery_result") return {
      operation_id: args?.operationId, revision: 2, inventory, total_count: 1, assessed_count: 1, ranking_source: "mixed", reason_code: null,
      assessments: [{ target_id: "a", bug_potential: 3, reachable_code: 2, harness_feasibility: 4, rationale: "Byte parser with direct input", advisory_score: 0.58 }],
    };
    return false;
  });
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><DiscoveryProvider><DiscoverView embedded /></DiscoveryProvider></I18nProvider>));
    await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent === "Discover")!.click());
    const score = host.querySelector('[data-testid="target-score"]');
    expect(score?.textContent).toContain("58");
    expect(score?.textContent).toContain("AI assessment");
    // The plain-language reason stays visible; the numbers behind it are collapsed.
    expect(host.textContent).toContain("Byte parser with direct input");
    const why = host.querySelector("details");
    expect(why?.querySelector("summary")?.textContent).toBe("Why this score");
    expect(why?.open).toBe(false);
    expect(why?.textContent).toContain("Bug potential");
    expect(why?.textContent).toContain("0.870");
    // No second headline score outside the details.
    const outside = (host.textContent ?? "").replace(why?.textContent ?? "", "");
    expect(outside.match(/\/100/g) ?? []).toHaveLength(1);
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});

it("labels Harness target options with the same score as the Discover card", async () => {
  const { harnessTargetOptions } = await import("../lib/targetScore");
  const base = { project_root: "/p", language: "C", kind: "Parser", signature: null, input_surface: "Bytes", complexity: 1, sanitizers: [], rationale: "", reachable_functions: [], accumulated_complexity: 1 };
  const a = { ...base, id: "a", symbol: "parse_a", fit_score: 0.9, location: { file: "/p/a.c", line: 1, col: 1 } };
  const b = { ...base, id: "b", symbol: "parse_b", fit_score: 0.5, location: { file: "/p/b.c", line: 1, col: 1 } };
  const options = harnessTargetOptions([b, a], "", [{ target_id: "b", advisory_score: 0.75 }], new Map());
  expect(options).toEqual([
    { value: "parse_a", label: "parse_a · 90/100" },
    { value: "parse_b", label: "parse_b · 75/100" },
  ]);
  const withSemgrep = harnessTargetOptions([a], "", [], new Map([["a", 0.42]]));
  expect(withSemgrep[0].label).toBe("parse_a · 42/100");
});
