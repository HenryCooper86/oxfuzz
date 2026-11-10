// @vitest-environment jsdom
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { DiagnosticsPanel } from "../components/observation/DiagnosticsPanel";
import { ObservabilityPanel } from "../components/observation/ObservabilityPanel";
import { InfoPanel } from "../components/observation/InfoPanel";
import { ProgressPanel } from "../components/ProgressPanel";
import { PipelineContext, usePipeline } from "../providers/pipeline";
const io = vi.hoisted(() => ({ invoke: vi.fn(), project: "/p", target: "new-target", run: { selectedRun: null as unknown, lastTarget: "old-target", lastEngine: "honggfuzz" } }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: io.invoke }) }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: io.project }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ target: io.target, engine: "libfuzzer" }) }));
vi.mock("../providers/runOutput", () => ({ useRunOutput: () => io.run }));
let host: HTMLDivElement; let root: Root;
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason: Error) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const summary = (model: string) => ({ calls: 1, input_tokens: 10, output_tokens: 5, cost_usd: 0.01, by_model: [{ model, calls: 1, input_tokens: 10, output_tokens: 5, cost_usd: 0.01 }] });
const snapshot = (id: string) => ({ providers: [{ id, model: "model", tags: [], is_frozen: false, active_requests: 0, max_concurrency: 3, total_requests: 0, total_errors: 0, error_rate: 0, total_input_tokens: 0, total_output_tokens: 0, estimated_cost_usd: 0 }], agents: { active_instances: 0, registered_definitions: 7, total_instances: 0, instances: [] }, memory: { pending_runs: 0, interrupted_runs: 0, llm_calls: 0, targets: 0, crashes: 0 } });
beforeEach(() => { vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); vi.useFakeTimers(); localStorage.clear(); io.invoke.mockReset(); io.project = "/p"; io.target = "new-target"; io.run.selectedRun = null; host = document.createElement("div"); document.body.append(host); root = createRoot(host); });
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.useRealTimers(); vi.unstubAllGlobals(); });
async function render(node: ReactNode) { await act(async () => root.render(<I18nProvider>{node}</I18nProvider>)); }

it("does not claim no calls while diagnostics is loading", async () => {
  io.invoke.mockReturnValue(new Promise(() => {})); await render(<DiagnosticsPanel />);
  expect(host.textContent).toContain("Loading"); expect(host.textContent).not.toContain("No LLM calls yet");
});
it.each(["diagnostics", "providers"])("ignores an older %s response after a newer refresh", async kind => {
  const old = deferred<unknown>(); const latest = deferred<unknown>(); io.invoke.mockReturnValueOnce(old.promise).mockReturnValueOnce(latest.promise);
  await render(kind === "diagnostics" ? <DiagnosticsPanel /> : <ObservabilityPanel />);
  await act(async () => { vi.advanceTimersByTime(5000); });
  await act(async () => latest.resolve(kind === "diagnostics" ? summary("new-result") : snapshot("new-result")));
  await act(async () => old.resolve(kind === "diagnostics" ? summary("old-result") : snapshot("old-result")));
  expect(host.textContent).toContain("new-result"); expect(host.textContent).not.toContain("old-result");
});
it("labels registered definitions without claiming free execution slots or verified health", async () => {
  io.invoke.mockResolvedValue(snapshot("pool-one")); await render(<ObservabilityPanel />);
  expect(host.textContent).toContain("Definitions"); expect(host.textContent).not.toContain("SLOTS"); expect(host.textContent).not.toContain("OK");
});
it("shows artifact load failures without asking to select an already selected project", async () => {
  io.invoke.mockRejectedValue(new Error("artifact read failed")); await render(<InfoPanel />);
  expect(host.textContent).toContain("artifact read failed"); expect(host.querySelector('button[aria-label="Refresh"]')).not.toBeNull();
  expect(host.textContent).not.toContain("Pick a project");
});
it("uses the selected target instead of an old completed campaign", async () => {
  io.invoke.mockResolvedValue({ harness_built: false, corpus_count: 0, crash_count: 0 });
  io.run.selectedRun = { project_root: "/p", target: "old-target", engine: "honggfuzz", status: "Done" };
  await render(<InfoPanel />); expect(io.invoke).toHaveBeenCalledWith("artifact_summary", { project: "/p", target: "new-target" });
  expect(host.textContent).not.toContain("old-target");
});
it("clears previous-target artifact counts while the new target loads", async () => {
  io.invoke.mockResolvedValueOnce({ harness_built: true, corpus_count: 12345, crash_count: 0 }).mockReturnValue(new Promise(() => {}));
  await render(<InfoPanel />); expect(host.textContent).toContain("12345"); io.target = "replacement";
  await render(<InfoPanel />); expect(host.textContent).not.toContain("12345"); expect(host.textContent).toContain("Loading");
});
it("translates the current workflow step in campaign info", async () => {
  localStorage.setItem("hf_locale", "zh"); io.invoke.mockResolvedValue({ harness_built: false, corpus_count: 0, crash_count: 0 });
  await render(<InfoPanel />); expect(host.textContent).not.toContain("Discover targets");
});
it("allows resetting partial work before a whole stage is complete", async () => {
  function Fixture() { const pipeline = usePipeline(); return <PipelineContext.Provider value={{ ...pipeline, completed: ["compile"], coreStages: pipeline.coreStages.map(stage => ({ ...stage, doneSteps: stage.id === "harness" ? 1 : 0 })) }}><ProgressPanel /></PipelineContext.Provider>; }
  await render(<Fixture />); expect(host.textContent).toContain("Reset progress");
});
