// @vitest-environment jsdom
import { act, StrictMode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ProjectProvider } from "../providers/ProjectContext";
import { PipelineProvider } from "../providers/PipelineContext";
import { TargetProvider } from "../providers/TargetContext";
import { useProject } from "../providers/project";
import { HarnessView } from "../views/HarnessView";
import { createHttpTransport } from "../lib/httpTransport";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual<typeof import("../lib")>("../lib"), getTransport: () => ({ invoke }) }));
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const profile = { project_root: "/project-b", component_root: ".", build_system: "cmake", compile_database_path: "build/compile_commands.json", cmake_definitions: { BUILD_TESTING: "OFF" }, dependencies: [{ kind: "pkg_config", name: "zlib" }], sandbox_image_tag: "oxfuzz-sandbox:latest", sandbox_image_id: `sha256:${"a".repeat(64)}`, marker_path: "CMakeLists.txt", marker_sha256: "b".repeat(64), profile_sha256: "c".repeat(64), created_at: "2026-09-08T00:00:00Z", updated_at: "2026-09-08T00:00:00Z" };
const plan = { steps: [{ argv: ["cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DBUILD_TESTING=OFF"], working_dir: ".", purpose: "Configure project" }], component_root: ".", expected_artifact: "build/compile_commands.json", profile_sha256: profile.profile_sha256, sandbox_image_tag: profile.sandbox_image_tag, sandbox_image_id: profile.sandbox_image_id };
function diagnosis(state = "unconfigured") {
  return { schema_version: 1, operation: "diagnose", profile: state === "unconfigured" ? null : profile, detected: [{ build_system: "cmake", status: "supported", markers: ["CMakeLists.txt"], missing_tool: null }], profile_state: state, dependency_statuses: state === "invalid" ? [{ dependency: { kind: "pkg_config", name: "zlib" }, available: false }] : [], reasons: state === "invalid" ? ["missing dependency: pkg_config:zlib"] : [], plan: ["needs_build", "ready"].includes(state) ? plan : null, legacy_build_context_available: false, terminal: null };
}
const failedBuild = { ...diagnosis("invalid"), operation: "build", plan, terminal: { status: "step_failed", step_index: 0, exit_code: 2, stdout: "old configure output", stderr: "missing zlib headers", output_truncated: false, failure_code: "build_step_failed", failure_message: "configure failed" } };
const history = [{ id: "d8e6993b-1898-42c0-975b-c5fd5b535c18", project_root: "/project-b", profile_sha256: profile.profile_sha256, status: "failed", diagnosis: failedBuild, created_at: "2026-09-08T00:00:00Z" }];
let host: HTMLDivElement;
let root: Root;
let state: string;
function Switch() { const { setActiveProject } = useProject(); return <button onClick={() => setActiveProject("/project-b")}>Switch project</button>; }
async function mount() {
  await act(async () => root.render(<StrictMode><I18nProvider><ProjectProvider><TargetProvider><PipelineProvider><Switch /><HarnessView embedded /></PipelineProvider></TargetProvider></ProjectProvider></I18nProvider></StrictMode>));
  await flush();
}
async function flush() { await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); }); }
function button(text: string) { const result = [...host.querySelectorAll("button")].find((b) => b.textContent === text); if (!result) throw new Error(`Missing ${text}: ${host.textContent}`); return result; }
async function click(text: string) { await act(async () => button(text).click()); await flush(); }
async function input(label: string, value: string) {
  const field = host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;
  expect(field, label).toBeTruthy();
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(field, value); field.dispatchEvent(new Event("input", { bubbles: true })); });
}
function baseInvoke(command: string, args: Record<string, unknown>) {
  if (command === "get_fuzzing_settings") return Promise.resolve({ enabled_engines: ["libfuzzer"], default_engine: "libfuzzer", default_duration_secs: 60, sandbox: { max_mem_mb: 2048, max_cpus: 1, max_duration_secs: 7200 } });
  if (command === "system_status_cmd") return Promise.resolve({ docker: true, sandbox_image: true });
  if (command === "discover") return Promise.resolve({ project_root: args.project, candidates: [{ id: "t-1", project_root: args.project, symbol: "parse_input", language: "C", file: "parser.c", line: 1, fit_score: 0.9, reason: "parser", signature: "int parse_input(const char *data)", callees: [] }], discovered_at: "2026-09-08T00:00:00Z" });
  if (["harness_review_queue", "work_order_list"].includes(command)) return Promise.resolve([]);
  if (command === "build_profile") return Promise.resolve(state === "unconfigured" ? null : profile);
  if (command === "build_diagnose") return Promise.resolve(diagnosis(state));
  if (command === "build_history") return Promise.resolve(state === "invalid" ? history : []);
  if (command === "build_profile_set") { state = "needs_build"; return Promise.resolve(profile); }
  if (command === "build_profile_clear") { state = "unconfigured"; return Promise.resolve(null); }
  if (command === "build_run") { state = "invalid"; return Promise.resolve({ status: "step_failed", build_system: "cmake", steps_run: 1, build_context: null, diagnosis: failedBuild }); }
  return Promise.reject(new Error(`Unexpected command: ${command}`));
}
beforeEach(() => {
  localStorage.clear(); localStorage.setItem("hf_locale", "en"); localStorage.setItem("hf_recent_projects", JSON.stringify(["/project-a", "/project-b"])); localStorage.setItem("hf_active_project", "/project-a");
  state = "unconfigured"; invoke.mockReset(); invoke.mockImplementation(baseInvoke);
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("Build Doctor in the real harness workflow", () => {
  it("diagnoses on project change, saves explicit settings, runs the reviewed digest and keeps legacy generation available after clear", async () => {
    await mount();
    expect(invoke.mock.calls.some(([cmd, args]) => cmd === "build_diagnose" && args.project === "/project-a")).toBe(true);
    expect(button("Generate").disabled).toBe(false);
    await click("Switch project");
    expect(invoke.mock.calls.some(([cmd, args]) => cmd === "build_diagnose" && args.project === "/project-b")).toBe(true);
    await click("Edit build profile");
    await input("Component root", "."); await input("Compile database path", "build/compile_commands.json");
    await click("Add definition"); await input("Definition name 1", "BUILD_TESTING"); await input("Definition value 1", "OFF");
    await click("Add dependency"); await input("Dependency name 1", "zlib");
    const kind = host.querySelector<HTMLSelectElement>('select[aria-label="Dependency kind 1"]')!;
    await act(async () => { kind.value = "pkg_config"; kind.dispatchEvent(new Event("change", { bubbles: true })); });
    await click("Save profile");
    expect(invoke.mock.calls.find(([cmd]) => cmd === "build_profile_set")?.[1]).toEqual({ project: "/project-b", componentRoot: ".", buildSystem: "cmake", compileDatabasePath: "build/compile_commands.json", cmakeDefinitions: { BUILD_TESTING: "OFF" }, dependencies: [{ kind: "pkg_config", name: "zlib" }] });
    expect(button("Generate").disabled).toBe(true);
    expect(button("Build & Smoke-Test").disabled).toBe(true);
    expect(host.textContent).toContain(JSON.stringify(plan.steps[0].argv));
    expect(host.textContent).toContain(profile.sandbox_image_id);
    expect(button("Run build plan").disabled).toBe(true);
    expect(invoke.mock.calls.some(([cmd]) => cmd === "build_run" || cmd === "harness_draft")).toBe(false);
    await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());
    await click("Run build plan");
    expect(invoke.mock.calls.find(([cmd]) => cmd === "build_run")?.[1]).toEqual({ project: "/project-b", expectedProfileSha256: profile.profile_sha256 });
    expect(host.textContent).toContain("pkg_config:zlib");
    expect(host.textContent).toContain("missing zlib headers");
    expect(host.textContent).toContain("old configure output");
    await click("Clear profile");
    expect(host.textContent).toContain("Unconfigured");
    expect(button("Generate").disabled).toBe(false);
    expect(invoke.mock.calls.some(([cmd]) => cmd === "harness_draft" || cmd === "harness_compile")).toBe(false);
  });
  it.each(["build_diagnose", "build_history"])("ignores old %s completions after switching projects", async (deferredCommand) => {
    const pending: Array<(value: unknown) => void> = [];
    invoke.mockImplementation((cmd, args) => args?.project === "/project-a" && cmd === deferredCommand ? new Promise((resolve) => pending.push((value) => resolve(cmd === "build_history" ? history : value))) : baseInvoke(cmd, args));
    await mount(); expect(pending.length).toBeGreaterThan(0); await click("Switch project");
    await act(async () => pending.forEach((resolve) => resolve(diagnosis("invalid")))); await flush();
    expect(host.textContent).not.toContain("missing zlib headers"); expect(host.textContent).not.toContain("missing dependency");
    expect(button("Generate").disabled).toBe(false);
  });
  it("clears approval on refresh and never substitutes a different digest", async () => {
    state = "needs_build"; await mount();
    await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());
    const next = { ...diagnosis("needs_build"), profile: { ...profile, profile_sha256: "d".repeat(64) }, plan: { ...plan, profile_sha256: "d".repeat(64) } };
    invoke.mockImplementation((cmd, args) => cmd === "build_diagnose" ? Promise.resolve(next) : cmd === "build_profile" ? Promise.resolve(next.profile) : baseInvoke(cmd, args));
    await click("Refresh");
    expect(button("Run build plan").disabled).toBe(true);
    expect(invoke.mock.calls.some(([cmd]) => cmd === "build_run")).toBe(false);
    await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click()); await click("Run build plan");
    expect(invoke.mock.calls.find(([cmd]) => cmd === "build_run")?.[1].expectedProfileSha256).toBe("d".repeat(64));
  });
  it("loads history after diagnosis has retained its operation and displays its captured profile", async () => {
    let retained = false;
    invoke.mockImplementation((cmd, args) => {
      if (cmd === "build_diagnose") return Promise.resolve(diagnosis()).then((value) => { retained = true; return value; });
      if (cmd === "build_history") return Promise.resolve(retained ? history : []);
      return baseInvoke(cmd, args);
    });
    await mount();
    expect(host.textContent).toContain("old configure output");
    expect(host.textContent).toContain('"BUILD_TESTING": "OFF"');
  });
  it.each(["build_profile_set", "build_profile_clear", "build_run"])("ignores a late %s completion after changing projects", async (operation) => {
    state = "needs_build";
    let finish: ((value: unknown) => void) | undefined;
    invoke.mockImplementation((cmd, args) => {
      if (cmd === operation) return new Promise((resolve) => { finish = resolve; });
      return baseInvoke(cmd, args);
    });
    await mount();
    if (operation === "build_profile_set") { await click("Edit build profile"); await click("Save profile"); }
    else if (operation === "build_profile_clear") await click("Clear profile");
    else { await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click()); await click("Run build plan"); }
    expect(finish).toBeTypeOf("function");
    state = "unconfigured";
    await click("Switch project");
    await act(async () => finish!({ status: "step_failed", build_system: "cmake", steps_run: 1, build_context: null, diagnosis: failedBuild }));
    await flush();
    expect(button("Generate").disabled).toBe(false);
    expect(host.textContent).not.toContain("missing zlib headers");
    expect(invoke.mock.calls.filter(([cmd, args]) => cmd === "build_diagnose" && args.project === "/project-a")).toHaveLength(2);
  });
  it("shows save, clear and stale-digest errors without silently approving a plan", async () => {
    state = "needs_build";
    invoke.mockImplementation((cmd, args) => ["build_profile_set", "build_profile_clear", "build_run"].includes(cmd) ? Promise.reject(new Error(cmd === "build_run" ? "expected build profile digest does not match current saved profile" : `${cmd} failed`)) : baseInvoke(cmd, args));
    await mount(); await click("Edit build profile"); await click("Save profile");
    expect(host.textContent).toContain("build_profile_set failed");
    await click("Clear profile"); expect(host.textContent).toContain("build_profile_clear failed");
    await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click()); await click("Run build plan");
    expect(host.textContent).toContain("expected build profile digest does not match");
    expect(button("Run build plan").disabled).toBe(true);
    expect(button("Generate").disabled).toBe(true);
  });
  it.each([false, true])("blocks saved configuration when diagnosis fails (profile read also fails: %s), then recovers on retry", async (readFails) => {
    await mount();
    expect(button("Generate").disabled).toBe(false);
    let failed = false;
    invoke.mockImplementation((cmd, args) => {
      if (cmd === "build_profile_set") { failed = true; return baseInvoke(cmd, args); }
      if (failed && (cmd === "build_diagnose" || (readFails && cmd === "build_profile"))) return Promise.reject(new Error("refresh unavailable"));
      return baseInvoke(cmd, args);
    });
    await click("Edit build profile"); await click("Save profile");
    expect(button("Generate").disabled).toBe(true);
    expect(button("Build & Smoke-Test").disabled).toBe(true);
    expect(host.querySelector('input[type="checkbox"]')).toBeNull();
    expect(host.textContent).toContain("refresh unavailable");
    failed = false; state = "ready"; await click("Refresh");
    expect(button("Generate").disabled).toBe(false);
    expect(button("Run build plan").disabled).toBe(true);
  });
  it.each([false, true])("restores legacy use after successful clear despite failed diagnosis (profile read also fails: %s)", async (readFails) => {
    state = "needs_build"; await mount();
    let cleared = false;
    invoke.mockImplementation((cmd, args) => {
      if (cmd === "build_profile_clear") { cleared = true; return baseInvoke(cmd, args); }
      if (cleared && (cmd === "build_diagnose" || (readFails && cmd === "build_profile"))) return Promise.reject(new Error("refresh unavailable"));
      return baseInvoke(cmd, args);
    });
    await click("Clear profile");
    expect(button("Generate").disabled).toBe(false);
    expect(host.querySelector('input[type="checkbox"]')).toBeNull();
    expect(host.textContent).toContain("Unconfigured");
  });
  it.each([false, true])("keeps initial unknown profile reads blocked (diagnosis succeeds: %s) and retries to proven absence", async (diagnosisSucceeds) => {
    invoke.mockImplementation((cmd, args) => (cmd === "build_profile" || (!diagnosisSucceeds && cmd === "build_diagnose")) ? Promise.reject(new Error("initial read failed")) : baseInvoke(cmd, args));
    await mount();
    expect(button("Generate").disabled).toBe(true);
    expect(button("Build & Smoke-Test").disabled).toBe(true);
    invoke.mockImplementation(baseInvoke); await click("Refresh");
    expect(button("Generate").disabled).toBe(false);
  });
  it("removes current plan approval after failed refresh while retaining historical evidence", async () => {
    state = "ready"; await mount();
    await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());
    invoke.mockImplementation((cmd, args) => cmd === "build_diagnose" ? Promise.reject(new Error("diagnosis unavailable")) : baseInvoke(cmd, args));
    await click("Refresh");
    expect(button("Generate").disabled).toBe(true);
    expect(host.querySelector('input[type="checkbox"]')).toBeNull();
    expect([...host.querySelectorAll("button")].some((item) => item.textContent === "Run build plan")).toBe(false);
    expect(host.textContent).toContain(JSON.stringify(plan.steps[0].argv));
    invoke.mockImplementation(baseInvoke); await click("Refresh");
    expect(button("Generate").disabled).toBe(false);
    expect(button("Run build plan").disabled).toBe(true);
    expect(invoke.mock.calls.some(([cmd]) => cmd === "build_run")).toBe(false);
  });
  it.each([["ready", false], ["stale", true]] as const)("renders generation admission for %s without inspecting compile flags", async (nextState, blocked) => {
    state = nextState; await mount();
    expect(button("Generate").disabled).toBe(blocked);
    expect(button("Build & Smoke-Test").disabled).toBe(blocked);
  });
  it.each([null, profile])("renders feature-disabled HTTP responses with the actual transport (saved profile: %s)", async (saved) => {
    const requests: Array<{ method: string; path: string }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, options: RequestInit) => {
      const path = new URL(url).pathname;
      requests.push({ method: options.method!, path });
      if (path === "/build/profile" && options.method === "GET") return new Response(JSON.stringify(saved), { status: 200, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ code: "build_doctor_unavailable", error: "build diagnosis is not included in this application build" }), { status: 501, headers: { "content-type": "application/json" } });
    }));
    const http = createHttpTransport({ baseUrl: "http://localhost:8081" });
    invoke.mockImplementation((cmd, args) => cmd.startsWith("build_") ? http.invoke(cmd, args) : baseInvoke(cmd, args));
    await mount();
    expect(host.textContent).toContain("build_doctor_unavailable: build diagnosis is not included in this application build");
    expect(button("Generate").disabled).toBe(saved !== null);
    expect(host.querySelector('input[type="checkbox"]')).toBeNull();
    await click("Edit build profile"); await click("Save profile");
    expect(host.textContent).toContain("build_doctor_unavailable: build diagnosis is not included in this application build");
    if (saved) await click("Clear profile");
    expect(requests).toContainEqual({ method: "GET", path: "/build/profile" });
    expect(requests).toContainEqual({ method: "GET", path: "/build/history" });
    expect(requests).toContainEqual({ method: "POST", path: "/build/diagnose" });
    expect(requests).toContainEqual({ method: "PUT", path: "/build/profile" });
    if (saved) expect(requests).toContainEqual({ method: "DELETE", path: "/build/profile" });
    expect(requests).not.toContainEqual({ method: "POST", path: "/build/run" });
  });
  it.each(["unconfigured", "needs_build"])("shows feature-off errors with a %s profile without automatically building or generating", async (profileState) => {
    state = profileState;
    invoke.mockImplementation((cmd, args) => cmd === "build_diagnose" ? Promise.reject(new Error("build diagnosis is not included in this application build")) : cmd === "build_history" ? Promise.reject(new Error("history unavailable")) : baseInvoke(cmd, args));
    await mount();
    expect(host.textContent).toContain("build diagnosis is not included in this application build");
    expect(host.textContent).toContain("history unavailable");
    expect(button("Generate").disabled).toBe(profileState !== "unconfigured");
    expect(invoke.mock.calls.some(([cmd]) => cmd === "build_run" || cmd === "harness_draft")).toBe(false);
  });
});
