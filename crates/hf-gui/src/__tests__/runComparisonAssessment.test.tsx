// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { RunComparison } from "../components/RunComparison";
import { createHttpTransport } from "../lib/httpTransport";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke }) }));
let cleanup = async () => {};
afterEach(async () => { await cleanup(); cleanup = async () => {}; vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const assessment = (baseline: string, result: string) => ({ baseline_id: baseline, result_id: result, comparable: false, reason: "different_executable", setup_matches: true, harness_changed: true, binary_changed: true, edge_delta: null });
async function mount(first: string, second: string) {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  const render = async (a: string, b: string) => { await act(async () => root.render(<I18nProvider><RunComparison baselineId={a} resultId={b} /></I18nProvider>)); };
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  await render(first, second); return { host, render };
}
it("explains changed executables without inventing an edge delta", async () => {
  invoke.mockResolvedValue(assessment("a", "b"));
  const { host } = await mount("a", "b");
  expect(host.textContent).toContain("Recorded setup matches");
  expect(host.textContent).toContain("Executable changed");
  expect(host.textContent).toContain("edge identities may differ");
  expect(host.textContent).not.toContain("Observed edge change");
  expect(invoke).toHaveBeenCalledWith("run_comparison", { baselineId: "a", resultId: "b" });
});
it("ignores the previous selection's late response and preserves exact integer text", async () => {
  let finish: ((value: unknown) => void) | undefined;
  invoke.mockImplementation((_command, args) => args.resultId === "b" ? new Promise(resolve => { finish = resolve; }) : Promise.resolve({ ...assessment("a", "c"), comparable: true, reason: "comparable", edge_delta: "9007199254740993", binary_changed: false }));
  const { host, render } = await mount("a", "b");
  await render("a", "c");
  expect(host.textContent).toContain("9007199254740993");
  await act(async () => finish!(assessment("a", "b")));
  expect(host.textContent).toContain("9007199254740993");
  expect(host.textContent).not.toContain("edge identities may differ");
});
it("keeps an unavailable comparison local and supports retry", async () => {
  invoke.mockRejectedValueOnce(new Error("selected run was removed")).mockResolvedValue({ ...assessment("a", "b"), comparable: true, reason: "comparable", edge_delta: "-7", binary_changed: false });
  const { host } = await mount("a", "b");
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("selected run was removed");
  await act(async () => host.querySelector("button")!.click());
  expect(host.textContent).toContain("-7");
});
it("maps exact comparison IDs to the HTTP endpoint", async () => {
  const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(assessment("a", "b")), { headers: { "content-type": "application/json" } }));
  await createHttpTransport().invoke("run_comparison", { baselineId: "a", resultId: "b" });
  expect(fetch.mock.calls[0][0]).toBe("http://localhost:8081/runs/compare");
  expect(JSON.parse(String(fetch.mock.calls[0][1]?.body))).toEqual({ baseline_id: "a", result_id: "b" });
});

it("rejects a response for another pair of runs", async () => {
  invoke.mockResolvedValue(assessment("a", "unexpected"));
  const { host } = await mount("a", "b");
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("does not match the selected runs");
  expect(host.textContent).not.toContain("Recorded setup matches");
});
