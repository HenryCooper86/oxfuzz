// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { RetainedHarnessBehavior } from "../components/RetainedHarnessBehavior";
const mock = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mock.invoke }) }));
const owner = (run: string, project = "/p") => ({ run_id: run, project_root: project, target: "parse", kind: "smoke" });
const report = (run: string | null, detail = "retained observation", status = "pass") => ({ version: 1, run_id: run, source_sha256: "source", binary_sha256: "binary", ...Object.fromEntries(["input_sensitivity", "entry_rejection", "repeated_input_stability", "persistent_state", "target_coverage_growth"].map(key => [key, { status, detail }])) });
let dispose = async () => {};
afterEach(async () => { await dispose(); mock.invoke.mockReset(); vi.unstubAllGlobals(); });
async function mount(runId: string | null = "run-a") {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.setItem("hf_locale", "en");
  const host = document.createElement("div"); const root = createRoot(host);
  const render = async (run: string | null, project = "/p") => act(async () => { root.render(<I18nProvider><RetainedHarnessBehavior runId={run} project={project} target="parse" sourceSha="source" binarySha="binary" /></I18nProvider>); });
  dispose = async () => { await act(async () => root.unmount()); };
  await render(runId); return { host, render };
}
it("hydrates retained evidence and refreshes without executing qualification", async () => {
  mock.invoke.mockImplementation(async command => command === "run_owner" ? owner("run-a") : report("run-a"));
  const { host } = await mount();
  expect(host.textContent).toContain("retained observation"); expect(host.textContent).toContain("Input sensitivity");
  await act(async () => host.querySelector("button")!.click());
  expect(mock.invoke.mock.calls.map(call => call[0])).toEqual(["run_owner", "run_harness_behavior", "run_owner", "run_harness_behavior"]);
});
it("does not display an old project response after selection changes", async () => {
  let resolveOld!: (value: unknown) => void;
  mock.invoke.mockImplementation((command, args) => command === "run_owner" ? Promise.resolve(owner(args.runId, args.runId === "run-a" ? "/p" : "/other")) : args.runId === "run-a" ? new Promise(resolve => { resolveOld = resolve; }) : Promise.resolve(report("run-b", "new project evidence")));
  const { host, render } = await mount(); await render("run-b", "/other");
  await act(async () => resolveOld(report("run-a", "stale result")));
  expect(host.textContent).toContain("new project evidence"); expect(host.textContent).not.toContain("stale result");
});
it.each(["project", "target", "kind"])("refuses a run with foreign %s before reading its evidence", async field => {
  mock.invoke.mockResolvedValue({ ...owner("run-a"), [field === "project" ? "project_root" : field]: "foreign" });
  const { host } = await mount(); expect(host.querySelector('[role="alert"]')).not.toBeNull(); expect(mock.invoke).toHaveBeenCalledTimes(1);
});
it("shows malformed or mismatched evidence as an error", async () => {
  mock.invoke.mockImplementation(async command => command === "run_owner" ? owner("run-a") : report("other-run"));
  const { host } = await mount(); expect(host.querySelector('[role="alert"]')).not.toBeNull(); expect(host.textContent).not.toContain("retained observation");
});
it("shows absent run linkage and unavailable measurements explicitly", async () => {
  const { host, render } = await mount(null); expect(host.textContent).toContain("No retained qualification run"); expect(mock.invoke).not.toHaveBeenCalled();
  mock.invoke.mockImplementation(async command => command === "run_owner" ? owner("run-a") : report(null, "Legacy run has no behavioral record", "unavailable"));
  await render("run-a"); expect(host.textContent).toContain("Legacy run has no behavioral record"); expect(host.textContent).toContain("Unavailable");
});

it("renders all check names in Chinese", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.setItem("hf_locale", "zh");
  mock.invoke.mockImplementation(async command => command === "run_owner" ? owner("run-a") : report("run-a"));
  const host = document.createElement("div"); const root = createRoot(host);
  dispose = async () => { await act(async () => root.unmount()); };
  await act(async () => root.render(<I18nProvider><RetainedHarnessBehavior runId="run-a" project="/p" target="parse" /></I18nProvider>));
  for (const label of ["输入敏感性", "入口与拒绝行为", "重复输入稳定性", "持久化状态", "目标覆盖率增长"]) expect(host.textContent).toContain(label);
});
