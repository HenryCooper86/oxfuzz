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
import { RunView } from "../views/RunView";

// Pipeline progress must belong to the project a run actually launched for,
// never to whichever project happens to be active when the run finishes.
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke, listen: async () => () => {} }) }));

const RUN_ID = "40000000-0000-4000-8000-000000000004";

const PROMOTED = {
  harness_id: "20000000-0000-4000-8000-000000000002",
  target_id: "10000000-0000-4000-8000-000000000001",
  target_symbol: "parse",
  target_selector: "parse",
  project_root: "/project",
  engine: "libfuzzer",
  language: "C",
  status: "Promoted",
  smoke_passed: true,
  smoke_execs_per_sec: 128,
  source_preview: "int parse(void) { return 0; }",
};

const SETTINGS = {
  collect_function_coverage: false,
  enabled_engines: ["libfuzzer"],
  default_engine: "libfuzzer",
  default_duration_secs: 60,
  sandbox: { max_mem_mb: 2048, max_cpus: 1, max_duration_secs: 7200 },
};

function SwitchProject({ to }: { to: string }) {
  const { setActiveProject } = useProject();
  return <button onClick={() => setActiveProject(to)}>switch-project</button>;
}

let cleanup = async () => {};

afterEach(async () => {
  await cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function seedStorage(active: string, recents: string[]) {
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  localStorage.setItem("hf_active_project", active);
  localStorage.setItem("hf_recent_projects", JSON.stringify(recents));
  localStorage.setItem(
    "hf_target_selection_v1",
    JSON.stringify({ [active]: { target: "parse", engine: "libfuzzer", lang: "c", compiled: false } }),
  );
}

function mockTransport(run: Promise<unknown>) {
  invoke.mockReset();
  invoke.mockImplementation(async (command: string) => {
    if (command === "get_fuzzing_settings") return SETTINGS;
    if (command === "artifact_summary") return { harness_built: true };
    if (command === "harness_review_queue") return [PROMOTED];
    if (command === "run_fuzzer") return run;
    if (command === "run_history") return [];
    if (command === "run_owner") return [];
    if (command === "campaign_health_events") return { events: [], next_cursor: null };
    return [];
  });
}

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

it("records progress on the project the run launched for, not the previously active project", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  seedStorage("/old", ["/old", "/new"]);
  let resolveRun!: (value: unknown) => void;
  const run = new Promise<unknown>((resolve) => { resolveRun = resolve; });
  mockTransport(run);

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
                    <RunView />
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

  const start = [...host.querySelectorAll("button")].find((item) => item.textContent?.includes("Run Fuzzer"));
  expect(start, host.textContent ?? "").toBeTruthy();
  await act(async () => start!.click());
  await flush();

  await act(async () => {
    resolveRun({ run_id: RUN_ID, edges: 12, execs: 128, crashes: 0 });
    for (let i = 0; i < 6; i++) await Promise.resolve();
  });

  const progress = readProgress();
  expect(progress["/new"]?.completed ?? []).toContain("run");
  expect(progress["/new"]?.skipped ?? []).toEqual(["triage"]);
  expect(progress["/old"]?.completed ?? []).not.toContain("run");
});

it("keeps progress on the launched project when the active project changes mid-run", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  seedStorage("/project", ["/project", "/other"]);
  let resolveRun!: (value: unknown) => void;
  const run = new Promise<unknown>((resolve) => { resolveRun = resolve; });
  mockTransport(run);

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
                    <RunView embedded />
                    <SwitchProject to="/other" />
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

  const start = [...host.querySelectorAll("button")].find((item) => item.textContent?.includes("Run Fuzzer"));
  expect(start, host.textContent ?? "").toBeTruthy();
  await act(async () => start!.click());
  await flush();

  const switcher = [...host.querySelectorAll("button")].find((item) => item.textContent === "switch-project");
  expect(switcher, host.textContent ?? "").toBeTruthy();
  await act(async () => switcher!.click());
  await flush();

  await act(async () => {
    resolveRun({ run_id: RUN_ID, edges: 12, execs: 128, crashes: 0 });
    for (let i = 0; i < 6; i++) await Promise.resolve();
  });

  const progress = readProgress();
  expect(progress["/project"]?.completed ?? []).toContain("run");
  expect(progress["/project"]?.skipped ?? []).toEqual(["triage"]);
  expect(progress["/other"]?.completed ?? []).not.toContain("run");
});

it.each([
  ["AFL++", true],
  ["afl", false],
])(
  "matches a promoted harness against the selected engine with the shared canonicalizer (retained %s)",
  async (retainedEngine, approved) => {
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    localStorage.clear();
    localStorage.setItem("hf_locale", "en");
    localStorage.setItem("hf_active_project", "/project");
    localStorage.setItem("hf_recent_projects", JSON.stringify(["/project"]));
    localStorage.setItem(
      "hf_target_selection_v1",
      JSON.stringify({ "/project": { target: "parse", engine: "afl++", lang: "c", compiled: false } }),
    );
    invoke.mockReset();
    invoke.mockImplementation(async (command: string) => {
      if (command === "get_fuzzing_settings") {
        return {
          ...SETTINGS,
          enabled_engines: ["libfuzzer", "afl++", "honggfuzz", "syzkaller"],
          default_engine: "afl++",
        };
      }
      if (command === "artifact_summary") return { harness_built: true };
      if (command === "harness_review_queue") return [{ ...PROMOTED, engine: retainedEngine }];
      if (command === "campaign_health_events") return { events: [], next_cursor: null };
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
                      <RunView embedded />
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

    // The run gate is the observable: it opens only for an approval that the
    // shared canonicalizer accepts. Bare `afl` is a different (invalid)
    // scope than `afl++`, unlike the old local normalizer.
    const start = [...host.querySelectorAll("button")].find((item) => item.textContent?.includes("Run Fuzzer"));
    expect(start, host.textContent ?? "").toBeTruthy();
    expect(start!.disabled).toBe(!approved);
  },
);
