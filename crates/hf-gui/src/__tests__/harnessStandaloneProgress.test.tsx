// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ProjectProvider } from "../providers/ProjectContext";
import { TargetProvider } from "../providers/TargetContext";
import { PipelineProvider } from "../providers/PipelineContext";
import { RunOutputProvider } from "../providers/RunOutputContext";
import { RunStatusProvider } from "../providers/RunStatusContext";
import { ToastProvider } from "../components/ui/Toast";
import { useProject } from "../providers/project";
import { HarnessView } from "../views/HarnessView";

function RemoveProject({ path }: { path: string }) {
  const { removeRecent } = useProject();
  return <button onClick={() => removeRecent(path)}>remove-project</button>;
}

// When the standalone Harness view operates on a project path that is not yet
// a recent project, its hydration/qualification progress must still persist
// instead of being pruned away.
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke, listen: async () => () => {} }) }));

const SETTINGS = {
  collect_function_coverage: false,
  enabled_engines: ["libfuzzer"],
  default_engine: "libfuzzer",
  default_duration_secs: 60,
  sandbox: { max_mem_mb: 2048, max_cpus: 1, max_duration_secs: 7200 },
};

const SMOKE_PASSED = {
  harness_id: "20000000-0000-4000-8000-000000000002",
  target_id: "10000000-0000-4000-8000-000000000001",
  target_symbol: "parse",
  target_selector: "parse",
  project_root: "/new",
  engine: "libfuzzer",
  language: "C",
  status: "SmokePassed",
  smoke_passed: true,
  smoke_execs_per_sec: 128,
  needs_review: true,
  next_action: "promote",
  source_preview: "int parse(void) { return 0; }",
  source_sha256: "b".repeat(64),
  binary_sha256: "c".repeat(64),
  lint: [],
  ai_review: { exercises_target: true, safe_to_execute: true, reasons: ["reviewed"], reviewed_at: "now" },
};

let cleanup = async () => {};

afterEach(async () => {
  await cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const flush = async () => {
  await act(async () => {
    for (let i = 0; i < 6; i++) await Promise.resolve();
  });
};

function readProgress(): Record<string, { completed: string[]; skipped: string[] }> {
  return JSON.parse(localStorage.getItem("hf_pipeline_progress_v1") ?? "{}") as Record<
    string,
    { completed: string[]; skipped: string[] }
  >;
}

it("keeps hydration progress for a newly typed standalone project", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  localStorage.setItem("hf_active_project", "/old");
  localStorage.setItem("hf_recent_projects", JSON.stringify(["/old"]));
  localStorage.setItem(
    "hf_target_selection_v1",
    JSON.stringify({ "/old": { target: "parse", engine: "libfuzzer", lang: "c", compiled: false } }),
  );

  invoke.mockReset();
  invoke.mockImplementation(async (command: string) => {
    if (command === "get_fuzzing_settings") return SETTINGS;
    if (command === "discover") return { candidates: [], call_graph: {} };
    if (command === "harness_review_queue") return [{ ...SMOKE_PASSED, smoke_run_id: "smoke-hydrated" }];
    if (command === "run_owner") return { run_id: "smoke-hydrated", project_root: "/new", target: "parse", kind: "smoke" };
    if (command === "run_harness_behavior") return { version: 1, run_id: "smoke-hydrated", source_sha256: SMOKE_PASSED.source_sha256, binary_sha256: SMOKE_PASSED.binary_sha256,
      ...Object.fromEntries(["input_sensitivity", "entry_rejection", "repeated_input_stability", "persistent_state", "target_coverage_growth"].map(key => [key, { status: "unavailable", detail: "Retained qualification after reopening" }])) };
    if (command === "system_status_cmd") return { docker: true, sandbox_image: true };
    if (command === "build_profile") return null;
    if (command === "build_diagnose")
      return {
        schema_version: 1,
        operation: "diagnose",
        profile: null,
        profile_state: "unconfigured",
        detected: [],
        dependency_statuses: [],
        reasons: [],
        plan: null,
        legacy_build_context_available: false,
        terminal: null,
      };
    if (command === "build_history") return [];
    if (command === "work_order_list") return [];
    if (command === "work_order_submissions") return [];
    if (command === "work_order_attempts") return [];
    return [];
  });

  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };

  await act(async () => {
    root.render(
      <I18nProvider>
        <ProjectProvider>
          <TargetProvider>
            <PipelineProvider>
              <RunStatusProvider>
                <ToastProvider>
                  <RunOutputProvider>
                    <HarnessView />
                  </RunOutputProvider>
                </ToastProvider>
              </RunStatusProvider>
            </PipelineProvider>
          </TargetProvider>
        </ProjectProvider>
      </I18nProvider>,
    );
  });
  await flush();

  const projectInput = host.querySelector<HTMLInputElement>('input[placeholder="/path/to/project"]');
  expect(projectInput, host.textContent ?? "").toBeTruthy();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(projectInput, "/new");
    projectInput!.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await flush();

  const progress = readProgress();
  expect(progress["/new"]?.completed ?? []).toEqual(expect.arrayContaining(["harness", "compile", "smoke"]));
  expect(invoke).toHaveBeenCalledWith("run_harness_behavior", { runId: "smoke-hydrated" });
  expect(host.textContent).toContain("Retained qualification after reopening");
});

it("does not re-register a project removed while hydration is pending", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  localStorage.setItem("hf_active_project", "/old");
  localStorage.setItem("hf_recent_projects", JSON.stringify(["/new", "/old"]));
  localStorage.setItem(
    "hf_target_selection_v1",
    JSON.stringify({ "/old": { target: "parse", engine: "libfuzzer", lang: "c", compiled: false } }),
  );

  let resolveNew!: () => void;
  invoke.mockReset();
  invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
    if (command === "get_fuzzing_settings") return SETTINGS;
    if (command === "discover") return { candidates: [], call_graph: {} };
    if (command === "harness_review_queue") {
      if (args?.project === "/new") return new Promise((resolve) => { resolveNew = () => resolve([SMOKE_PASSED]); });
      return [SMOKE_PASSED];
    }
    if (command === "system_status_cmd") return { docker: true, sandbox_image: true };
    if (command === "build_profile") return null;
    if (command === "build_diagnose")
      return {
        schema_version: 1,
        operation: "diagnose",
        profile: null,
        profile_state: "unconfigured",
        detected: [],
        dependency_statuses: [],
        reasons: [],
        plan: null,
        legacy_build_context_available: false,
        terminal: null,
      };
    if (command === "build_history") return [];
    if (command === "work_order_list") return [];
    if (command === "work_order_submissions") return [];
    if (command === "work_order_attempts") return [];
    return [];
  });

  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };

  await act(async () => {
    root.render(
      <I18nProvider>
        <ProjectProvider>
          <TargetProvider>
            <PipelineProvider>
              <RunStatusProvider>
                <ToastProvider>
                  <RunOutputProvider>
                    <HarnessView />
                    <RemoveProject path="/new" />
                  </RunOutputProvider>
                </ToastProvider>
              </RunStatusProvider>
            </PipelineProvider>
          </TargetProvider>
        </ProjectProvider>
      </I18nProvider>,
    );
  });
  await flush();

  const projectInput = host.querySelector<HTMLInputElement>('input[placeholder="/path/to/project"]');
  expect(projectInput, host.textContent ?? "").toBeTruthy();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(projectInput, "/new");
    projectInput!.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await flush();

  const remover = [...host.querySelectorAll("button")].find((item) => item.textContent === "remove-project");
  expect(remover, host.textContent ?? "").toBeTruthy();
  await act(async () => remover!.click());
  await flush();

  await act(async () => {
    resolveNew();
    for (let i = 0; i < 6; i++) await Promise.resolve();
  });

  expect(JSON.parse(localStorage.getItem("hf_recent_projects") ?? "[]")).not.toContain("/new");
  expect(readProgress()["/new"]?.completed ?? []).not.toContain("harness");
});
