// @vitest-environment jsdom
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ProjectProvider } from "../providers/ProjectContext";
import { TargetProvider } from "../providers/TargetContext";
import { PipelineProvider } from "../providers/PipelineContext";
import { RunOutputProvider } from "../providers/RunOutputContext";
import { RunStatusProvider } from "../providers/RunStatusContext";
import { ToastProvider } from "../components/ui/Toast";
import { HarnessView } from "../views/HarnessView";
import { RunView } from "../views/RunView";
import { CorpusView } from "../views/CorpusView";
import { useTarget } from "../providers/target";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke, listen: async () => () => {} }) }));
let cleanup = async () => {};
afterEach(async () => { await cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const selector = "alternate.c::ns::parse";
const targetId = "10000000-0000-4000-8000-000000000001";
const harnessId = "20000000-0000-4000-8000-000000000002";
const attemptId = "30000000-0000-4000-8000-000000000003";
const runId = "40000000-0000-4000-8000-000000000004";
function Views() {
  const [view, setView] = useState("harness");
  const { target } = useTarget();
  return <><output data-testid="selected-target">{target}</output><button onClick={() => setView("run")}>Show Run</button><button onClick={() => setView("harness")}>Show Harness</button><button onClick={() => setView("corpus")}>Show Corpus</button>{view === "harness" ? <HarnessView embedded /> : view === "run" ? <RunView embedded /> : <CorpusView />}</>;
}
it("carries the promoted exact selector through real Harness, Run, Corpus and restored discovery without automatic execution", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear(); localStorage.setItem("hf_locale", "en");
  localStorage.setItem("hf_active_project", "/project"); localStorage.setItem("hf_recent_projects", JSON.stringify(["/project"]));
  localStorage.setItem("hf_target_selection_v1", JSON.stringify({ "/project": { target: "ns::parse", engine: "libfuzzer", lang: "c", compiled: false } }));
  let promoted = false;
  let finishDiscovery: (() => void) | undefined;
  let firstDiscovery = true;
  const discovery = () => ({ project_root: "/project", candidates: ["first.c", "alternate.c"].map((file, i) => ({ id: i ? targetId : "other-target", project_root: "/project", symbol: "ns::parse", location: { file: `/project/${file}`, line: 1, col: 1 }, language: "C", line: 1, fit_score: 1 - i / 10, reason: "parser", callees: [] })) });
  const order = { id: "a".repeat(64), schema_version: 2, payload: { target: { symbol: "ns::parse", relative_source: "alternate.c", language: "c" }, engine: "lib_fuzzer" } };
  const review = () => ({ harness_id: harnessId, target_id: targetId, target_symbol: "ns::parse", target_selector: selector, project_root: "/project", engine: "LibFuzzer", language: "C", status: promoted ? "Promoted" : "SmokePassed", build_output: "fuzz", smoke_passed: true, smoke_execs_per_sec: 128, needs_review: !promoted, next_action: "promote", source_preview: "exact imported source", ai_review: { exercises_target: true, safe_to_execute: true, reasons: ["reviewed exact source"], reviewed_at: "now" }, source_sha256: "b".repeat(64), binary_sha256: "c".repeat(64), lint: [] });
  invoke.mockReset(); invoke.mockImplementation(async (command, args) => {
    if (command === "get_fuzzing_settings") return { enabled_engines: ["libfuzzer"], default_engine: "libfuzzer", default_duration_secs: 60, sandbox: { max_mem_mb: 2048, max_cpus: 1, max_duration_secs: 7200 } };
    if (command === "discover") {
      if (firstDiscovery) {
        firstDiscovery = false;
        return new Promise(resolve => { finishDiscovery = () => resolve(discovery()); });
      }
      return discovery();
    }
    if (command === "system_status_cmd") return { docker: true, sandbox_image: true };
    if (command === "build_profile") return null;
    if (command === "build_diagnose") return { schema_version: 1, operation: "diagnose", profile: null, profile_state: "unconfigured", detected: [], dependency_statuses: [], reasons: [], plan: null, legacy_build_context_available: false, terminal: null };
    if (command === "build_history") return [];
    if (command === "work_order_list") return [order];
    if (command === "work_order_submissions") return [{ id: "submission", work_order_id: order.id, source: "exact imported source", source_sha256: "b".repeat(64), lint: [], origin: "human", submitted_at: "now" }];
    if (command === "work_order_attempts") return [{ id: attemptId, submission_id: "submission", status: "smoke_passed", current_stage: "complete", harness_id: harnessId, result: { compiled: true, smoke_verdict: "pass", repair_depth: 0, source_sha256: "b".repeat(64), binary_sha256: "c".repeat(64), execs_per_sec: 128, crashes: 0 }, started_at: "now", updated_at: "now", ended_at: "now" }];
    if (command === "harness_review_queue") return !args.target || ["ns::parse", selector].includes(args.target) ? [review()] : [];
    if (command === "work_order_promote") { expect(args.attemptId).toBe(attemptId); promoted = true; return { id: harnessId, status: "Promoted" }; }
    if (command === "artifact_summary") return { harness_built: args.target === selector };
    if (command === "run_fuzzer") return { run_id: runId, edges: 12, execs: 128, crashes: 0 };
    if (command === "run_history") return promoted ? [{ id: runId, target_id: targetId, target: "ns::parse", target_selector: selector, project_root: "/project", kind: "Campaign", status: "Done", requested_duration_secs: 60, started_at: "2026-09-08T01:00:00Z", ended_at: "2026-09-08T02:00:00Z" }] : [];
    if (command === "run_owner") return { run_id: runId, project_root: "/project", target: "ns::parse", engine: "libfuzzer", kind: "Campaign", status: "Done", started_at: "2026-09-08T01:00:00Z" };
    if (command === "campaign_health_events") return { events: [], next_cursor: null };
    if (command === "coverage_experiment_list") { expect(args.target_id).toBe(targetId); return { items: [], next_cursor: null }; }
    if (command === "corpus_capabilities") return {};
    return [];
  });
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  const mount = () => root.render(<I18nProvider><ProjectProvider><TargetProvider><PipelineProvider><RunStatusProvider><ToastProvider><RunOutputProvider><Views /></RunOutputProvider></ToastProvider></RunStatusProvider></PipelineProvider></TargetProvider></ProjectProvider></I18nProvider>);
  const flush = async () => { await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); }); };
  const click = async (label: string) => { const button = [...host.querySelectorAll("button")].find(item => item.textContent === label); expect(button, host.textContent ?? "").toBeTruthy(); await act(async () => button!.click()); await flush(); };
  await act(async () => mount()); await flush();
  await click("Promote selected attempt");
  expect(host.querySelector('[data-testid="selected-target"]')!.textContent).toBe(selector);
  // Discovery began for the old bare selection; its late reply must preserve the promoted identity.
  await act(async () => finishDiscovery!()); await flush();
  expect(host.querySelector('[data-testid="selected-target"]')!.textContent).toBe(selector);
  expect(invoke.mock.calls.filter(([command]) => command === "run_fuzzer")).toHaveLength(0);
  await click("Show Run");
  const start = [...host.querySelectorAll("button")].find(item => item.textContent?.includes("Run Fuzzer"));
  expect(start, host.textContent ?? "").toBeTruthy(); expect(start!.disabled).toBe(false);
  await act(async () => start!.click()); await flush();
  expect(invoke.mock.calls.find(([command]) => command === "run_fuzzer")?.[1]).toEqual({ project: "/project", target: selector, engine: "libfuzzer", duration: 60 });
  await click("Show Corpus");
  expect(host.querySelector('[aria-label="Baseline campaign"]')).toBeTruthy();
  await click("Show Harness");
  expect(host.querySelector('[data-testid="selected-target"]')!.textContent).toBe(selector);
  expect(host.textContent).toContain("exact imported source");
  await act(async () => root.render(null));
  await act(async () => mount()); await flush();
  expect(host.querySelector('[data-testid="selected-target"]')!.textContent).toBe(selector);
  expect([...host.querySelectorAll('[role="combobox"]')].some(item => item.textContent?.includes(selector))).toBe(true);
  expect(invoke.mock.calls.filter(([command]) => command === "run_fuzzer")).toHaveLength(1);
  await act(async () => root.render(null));
  localStorage.setItem("hf_target_selection_v1", JSON.stringify({ "/project": { target: "ns::parse", engine: "libfuzzer", lang: "c", compiled: false } }));
  await act(async () => mount()); await flush();
  expect(host.querySelector('[data-testid="selected-target"]')!.textContent).toBe("first.c::ns::parse");
  expect([...host.querySelectorAll('[role="combobox"]')].some(item => item.textContent?.includes("first.c::ns::parse"))).toBe(true);
  expect(invoke.mock.calls.filter(([command]) => command === "run_fuzzer")).toHaveLength(1);
});
