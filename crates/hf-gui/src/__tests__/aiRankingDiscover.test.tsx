// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { DiscoverView } from "../views/DiscoverView";
import { DiscoveryProvider } from "../providers/DiscoveryContext";
import { I18nProvider } from "../i18n";

const mocks = vi.hoisted(() => ({ invoke: vi.fn(), markDone: vi.fn(), setTarget: vi.fn(), project: "/sample" }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }), pickFolder: vi.fn() }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: mocks.project, setActiveProject: vi.fn() }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ lang: "c", setLang: vi.fn(), target: "", setTarget: mocks.setTarget }) }));
vi.mock("../providers/pipeline", () => ({ usePipeline: () => ({ markDone: mocks.markDone }) }));

const candidate = (id: string, file: string, fit: number) => ({
  id, project_root: "/sample", language: "C", symbol: "parse_value", kind: "Parser",
  location: { file: `/sample/${file}`, line: 4, col: 1 }, signature: null,
  input_surface: "Bytes", complexity: 3, fit_score: fit, sanitizers: [], rationale: "",
  reachable_functions: [], accumulated_complexity: 3,
});
const first = candidate("a", "src/a.c", 0.9);
const second = candidate("b", "src/b.c", 0.7);
const scan = { project_root: "/sample", candidates: [first, second], call_graph: {} };
const ranked = { project_root: "/sample", candidates: [second, first], call_graph: {} };

it("shows the scan before AI, then three factors with one stable target handoff", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  let phase = 1;
  mocks.invoke.mockImplementation(async (command: string) => {
    if (command === "semgrep_available") return true;
    if (command === "ranked_discovery_start") return "op-1";
    if (command === "ranked_discovery_status") return phase === 1
      ? { operation_id: "op-1", state: "ranking", revision: 1, assessed_count: 0, total_count: 2, reason_code: null }
      : { operation_id: "op-1", state: "completed", revision: 2, assessed_count: 1, total_count: 2, reason_code: null };
    if (command === "ranked_discovery_result") return {
      operation_id: "op-1", revision: phase, project_root: "/sample", language: "C",
      scanned_at: "2026-09-26T00:00:00Z", inventory: phase === 1 ? scan : ranked,
      assessments: phase === 1 ? [] : [{ target_id: "b", bug_potential: 4, reachable_code: 3, harness_feasibility: 2, rationale: "Byte input and reachable calls", advisory_score: 0.75 }],
      assessed_count: phase === 1 ? 0 : 1, total_count: 2,
      ranking_source: phase === 1 ? "pending" : "mixed", reason_code: null,
    };
    if (command === "discover") return scan;
    return false;
  });
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const navigate = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><DiscoveryProvider><DiscoverView embedded onNavigate={navigate} /></DiscoveryProvider></I18nProvider>));
    await act(async () => {
      [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click();
      await new Promise(resolve => setTimeout(resolve, 30));
    });
    expect(mocks.invoke.mock.calls.some(([command]) => command === "ranked_discovery_start")).toBe(true);
    expect(host.textContent).toContain("Assessing with AI");
    expect(host.textContent).not.toContain("Enrich with Semgrep");
    expect(host.textContent).toContain("src/a.c");
    expect(host.textContent).not.toContain("Recommended first");
    const useButtons = [...host.querySelectorAll("button")].filter(button => button.textContent?.includes("Use this target"));
    const focused = useButtons[1];
    focused.focus();

    phase = 2;
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 300)); });
    expect(host.textContent).toContain("Recommended first");
    expect(host.textContent).toContain("Enrich with Semgrep");
    expect(host.textContent?.match(/AI assessed 1 of 2 candidates/g)).toHaveLength(1);
    expect(host.textContent).toContain("Bug potential");
    expect(host.textContent).toContain("Reachable code");
    expect(host.textContent).toContain("Harness feasibility");
    expect(document.activeElement).toBe(focused);
    const orderedButtons = [...host.querySelectorAll("button")].filter(button => button.textContent?.includes("Use this target"));
    await act(async () => orderedButtons[0].click());
    expect(mocks.setTarget).toHaveBeenCalledWith("src/b.c::parse_value");
    expect(navigate).toHaveBeenCalledWith("harness");
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
    mocks.invoke.mockReset();
    mocks.project = "/sample";
  }
});

it("explains scan-only fallback and retries assessment without rescanning", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const navigate = vi.fn();
  mocks.invoke.mockImplementation(async (command: string, args?: { operationId?: string }) => {
    if (command === "ranked_discovery_start") return mocks.invoke.mock.calls.filter(([name]) => name === "ranked_discovery_start").length === 1 ? "scan-1" : "scan-2";
    if (command === "ranked_discovery_retry") return "retry-2";
    if (command === "ranked_discovery_status") return { operation_id: args?.operationId, state: "completed", revision: 2 };
    if (command === "ranked_discovery_result") {
      const retried = args?.operationId === "retry-2";
      const secondScan = mocks.invoke.mock.calls.filter(([name]) => name === "ranked_discovery_start").length > 1;
      return {
        operation_id: args?.operationId, revision: 2, inventory: scan,
        assessments: [], assessed_count: 0, total_count: 2, ranking_source: "heuristic",
        reason_code: retried || secondScan ? "partial_or_failed_ai" : "no_provider",
      };
    }
    return false;
  });
  try {
    await act(async () => root.render(<I18nProvider><DiscoveryProvider><DiscoverView embedded onNavigate={navigate} /></DiscoveryProvider></I18nProvider>));
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click());
    expect(host.textContent).toContain("Add an AI provider in Settings");
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "AI Settings")!.click());
    expect(navigate).toHaveBeenCalledWith("settings");
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click());
    expect(host.textContent).toContain("AI assessment was incomplete");
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Retry AI assessment")!.click());
    expect(mocks.invoke.mock.calls.filter(([name]) => name === "ranked_discovery_retry")).toHaveLength(1);
    expect(mocks.invoke.mock.calls.filter(([name]) => name === "ranked_discovery_start")).toHaveLength(2);
    expect(host.textContent).toContain("src/a.c");
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
    mocks.invoke.mockReset();
  }
});

it("ignores a prior project's late status after a new Discover action", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  let releaseOld: ((value: unknown) => void) | undefined;
  const oldStatus = new Promise(resolve => { releaseOld = resolve; });
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const render = () => <I18nProvider><DiscoveryProvider><DiscoverView embedded onNavigate={vi.fn()} /></DiscoveryProvider></I18nProvider>;
  mocks.invoke.mockImplementation(async (command: string, args?: { project?: string; operationId?: string }) => {
    if (command === "ranked_discovery_start") return args?.project === "/sample" ? "old-op" : "new-op";
    if (command === "ranked_discovery_status") return args?.operationId === "old-op"
      ? oldStatus
      : { operation_id: "new-op", state: "completed", revision: 2 };
    if (command === "ranked_discovery_result") return {
      operation_id: "new-op", revision: 2,
      inventory: { project_root: "/another", candidates: [candidate("new", "new_target.c", 0.6)], call_graph: {} },
      assessments: [], assessed_count: 0, total_count: 1, ranking_source: "heuristic", reason_code: "no_provider",
    };
    return false;
  });
  try {
    await act(async () => root.render(render()));
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click());
    mocks.project = "/another";
    await act(async () => root.render(render()));
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click());
    expect(host.textContent).toContain("new_target.c");
    await act(async () => releaseOld?.({ operation_id: "old-op", state: "completed", revision: 2 }));
    expect(host.textContent).toContain("new_target.c");
    expect(host.textContent).not.toContain("src/a.c");
    expect(mocks.invoke.mock.calls.filter(([name, args]) => name === "ranked_discovery_result" && args?.operationId === "old-op")).toHaveLength(0);
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
    mocks.invoke.mockReset();
    mocks.project = "/sample";
  }
});

it("retains a published scan and offers retry after interruption", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  mocks.invoke.mockImplementation(async (command: string, args?: { operationId?: string }) => {
    if (command === "ranked_discovery_start") return "interrupted-op";
    if (command === "ranked_discovery_retry") return "retry-op";
    if (command === "ranked_discovery_status") return {
      operation_id: args?.operationId,
      state: args?.operationId === "interrupted-op" ? "interrupted" : "completed",
      revision: args?.operationId === "interrupted-op" ? 1 : 2,
    };
    if (command === "ranked_discovery_result") return {
      operation_id: args?.operationId,
      revision: args?.operationId === "interrupted-op" ? 1 : 2,
      inventory: scan, assessments: [], assessed_count: 0, total_count: 2,
      ranking_source: args?.operationId === "interrupted-op" ? "pending" : "heuristic",
      reason_code: null,
    };
    return false;
  });
  try {
    await act(async () => root.render(<I18nProvider><DiscoveryProvider><DiscoverView embedded onNavigate={vi.fn()} /></DiscoveryProvider></I18nProvider>));
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click());
    expect(host.textContent).toContain("Assessment interrupted");
    expect(host.textContent).toContain("src/a.c");
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Retry AI assessment")!.click());
    expect(mocks.invoke.mock.calls.filter(([name]) => name === "ranked_discovery_retry")).toHaveLength(1);
  } finally {
    await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); mocks.invoke.mockReset();
  }
});

it("does not reattach an old pending operation while a new scan starts", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  let releaseStart: ((value: string) => void) | undefined;
  const newStart = new Promise<string>(resolve => { releaseStart = resolve; });
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  mocks.invoke.mockImplementation(async (command: string, args?: { operationId?: string }) => {
    if (command === "ranked_discovery_start") return mocks.invoke.mock.calls.filter(([name]) => name === "ranked_discovery_start").length === 1 ? "old-op" : newStart;
    if (command === "ranked_discovery_status") return args?.operationId === "old-op"
      ? { operation_id: "old-op", state: "ranking", revision: 1 }
      : { operation_id: "new-op", state: "completed", revision: 2 };
    if (command === "ranked_discovery_result") return {
      operation_id: args?.operationId, revision: args?.operationId === "old-op" ? 1 : 2,
      inventory: args?.operationId === "old-op" ? scan : ranked,
      assessments: [], assessed_count: 0, total_count: 2,
      ranking_source: args?.operationId === "old-op" ? "pending" : "heuristic", reason_code: null,
    };
    return false;
  });
  try {
    await act(async () => root.render(<I18nProvider><DiscoveryProvider><DiscoverView embedded onNavigate={vi.fn()} /></DiscoveryProvider></I18nProvider>));
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click());
    expect(host.textContent).toContain("src/a.c");
    await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === "Discover")!.click());
    expect(mocks.invoke.mock.calls.filter(([name, args]) => name === "ranked_discovery_status" && args?.operationId === "old-op")).toHaveLength(1);
    await act(async () => releaseStart?.("new-op"));
    expect(host.textContent).toContain("src/b.c");
  } finally {
    await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); mocks.invoke.mockReset();
  }
});
