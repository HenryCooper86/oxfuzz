// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ProjectProvider } from "../providers/ProjectContext";
import { TargetProvider } from "../providers/TargetContext";
import { PipelineProvider } from "../providers/PipelineContext";
import { RunOutputProvider } from "../providers/RunOutputContext";
import { RunStatusProvider } from "../providers/RunStatusContext";
import { ToastProvider } from "../components/ui/Toast";
import { RunView } from "../views/RunView";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke, listen: async () => () => {} }) }));

const RUN_ID = "40000000-0000-4000-8000-000000000004";
const PROMOTED = {
  harness_id: "20000000-0000-4000-8000-000000000002",
  target_id: "10000000-0000-4000-8000-000000000001",
  target_symbol: "parse",
  target_selector: "parse",
  project_root: "/project",
  engine: "afl++",
  language: "C",
  status: "Promoted",
  smoke_passed: true,
  smoke_execs_per_sec: 128,
  source_preview: "int parse(void) { return 0; }",
};
const SETTINGS = {
  collect_function_coverage: false,
  enabled_engines: ["afl++", "libfuzzer"],
  default_engine: "afl++",
  default_duration_secs: 60,
  sandbox: { max_mem_mb: 2048, max_cpus: 4, max_duration_secs: 7200 },
};

let cleanup = async () => {};
beforeEach(() => {
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  localStorage.setItem("hf_active_project", "/project");
  localStorage.setItem("hf_recent_projects", JSON.stringify(["/project"]));
  localStorage.setItem("hf_target_selection_v1", JSON.stringify({ "/project": { target: "parse", engine: "afl++", lang: "c", compiled: false } }));
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  invoke.mockReset();
  invoke.mockImplementation(async (command: string) => {
    if (command === "get_fuzzing_settings") return SETTINGS;
    if (command === "artifact_summary") return { harness_built: true };
    if (command === "harness_review_queue") return [PROMOTED];
    if (command === "harness_active_review") return PROMOTED;
    if (command === "run_fuzzer") return { run_id: RUN_ID, edges: 1, execs: 2, crashes: 1 };
    if (command === "user_dictionary") return null;
    return [];
  });
});
afterEach(async () => {
  await cleanup();
  vi.unstubAllGlobals();
});

const flush = async () => act(async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); });
async function type(el: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function mount() {
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  await act(async () => root.render(
    <I18nProvider><ProjectProvider><TargetProvider><PipelineProvider><RunStatusProvider><ToastProvider><RunOutputProvider>
      <RunView embedded />
    </RunOutputProvider></ToastProvider></RunStatusProvider></PipelineProvider></TargetProvider></ProjectProvider></I18nProvider>,
  ));
  await flush();
  return host;
}
const runButton = (host: HTMLElement) =>
  [...host.querySelectorAll("button")].find((b) => b.textContent?.includes("Run Fuzzer")) as HTMLButtonElement;
const field = (host: HTMLElement, label: string) => host.querySelector(`[aria-label="${label}"]`) as HTMLInputElement;
const runCall = () => invoke.mock.calls.find((call) => call[0] === "run_fuzzer");

it("sends no extra arguments when no run option was touched", async () => {
  const host = await mount();
  await act(async () => runButton(host).click());
  await flush();
  expect(runCall()?.[1]).toEqual({ project: "/project", target: "parse", engine: "afl++", duration: 60 });
});

it("sends the seed at the top level and the other options under options", async () => {
  const host = await mount();
  await type(field(host, "RNG seed"), "18446744073709551615");
  await type(field(host, "CPUs"), "3");
  await type(field(host, "Per-input timeout (ms)"), "250");
  await act(async () => field(host, "Resume previous AFL++ session").click());
  await act(async () => field(host, "Use CmpLog").click());
  await act(async () => runButton(host).click());
  await flush();
  expect(runCall()?.[1]).toEqual({
    project: "/project", target: "parse", engine: "afl++", duration: 60,
    seed: "18446744073709551615",
    options: { cpus: 3, timeoutMs: 250, resume: true, cmplog: true },
  });
});

it("refuses CPUs above the configured sandbox limit and blocks the run", async () => {
  const host = await mount();
  await type(field(host, "CPUs"), "5");
  expect(host.textContent).toContain("CPUs must be a whole number from 1 to 4");
  expect(runButton(host).disabled).toBe(true);
});

it("offers the campaign, CI gate, dictionary and readiness panels for the selected target", async () => {
  const host = await mount();
  for (const label of ["Campaign", "CI gate", "Fuzzing dictionary", "Readiness check"]) {
    expect(host.querySelector(`section[aria-label="${label}"]`), label).toBeTruthy();
  }
  expect(invoke).toHaveBeenCalledWith("user_dictionary", { project: "/project", target: "parse" });
});

it("shows a kernel architecture select defaulting to the sandbox preference and sends it as arch", async () => {
  localStorage.setItem("hf_target_selection_v1", JSON.stringify({ "/project": { target: "", engine: "syzkaller", lang: "c", compiled: false } }));
  const base = invoke.getMockImplementation()!;
  invoke.mockImplementation(async (command: string, args?: unknown) => {
    if (command === "get_fuzzing_settings") return { ...SETTINGS, enabled_engines: ["afl++", "syzkaller"] };
    if (command === "run_syzkaller") return { run_id: RUN_ID, edges: 1, execs: 2, crashes: 0 };
    return base(command, args);
  });
  const host = await mount();
  const select = host.querySelector('[aria-label="Kernel architecture"]');
  expect(select?.textContent).toContain("linux/arm64");
  const start = [...host.querySelectorAll("button")].find((b) => b.textContent?.includes("Launch"));
  await act(async () => start!.click());
  await flush();
  const call = invoke.mock.calls.find((c) => c[0] === "run_syzkaller");
  expect((call?.[1] as { opts: { arch: string } }).opts.arch).toBe("linux/arm64");
});
