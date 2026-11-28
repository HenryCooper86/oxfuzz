// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ClangAnalysisPanel } from "../components/ClangAnalysisPanel";
import { RemoteArmPanel } from "../components/RemoteArmPanel";
import { RestServerPanel } from "../components/RestServerPanel";
import { RunRecordPanel } from "../components/RunRecordPanel";
import { RunListFilters } from "../components/RunListFilters";
import { filterRuns, saveWorkOrderPacket } from "../lib/parityDiscovery";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke }) }));
// These panels' controls exist in the desktop app; the browser shows a note
// instead (desktopOnlyPanels.test.tsx).
vi.mock("../lib/transport", async () => ({ ...await vi.importActual("../lib/transport"), isTauriEnvironment: () => true }));

let cleanup = async () => {};
beforeEach(() => {
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  invoke.mockReset();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});
afterEach(async () => {
  await cleanup();
  vi.unstubAllGlobals();
});

async function mount(node: React.ReactElement) {
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  await act(async () => root.render(<I18nProvider>{node}</I18nProvider>));
  await flush();
  return host;
}
const flush = async () => act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); });
const settle = async () => { for (let i = 0; i < 6; i++) { await act(async () => { await new Promise((r) => setTimeout(r, 1)); }); } };
const button = (host: HTMLElement, text: string) =>
  [...host.querySelectorAll("button")].find((b) => b.textContent?.includes(text)) as HTMLButtonElement;
const type = async (input: HTMLInputElement, value: string) => {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  await act(async () => {
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
};

const run = (id: string, status: string) => ({ id, status });

it("keeps only pending and running runs when active-only is on, then applies the limit", () => {
  const runs = [run("a", "Completed"), run("b", "Running"), run("c", "pending"), run("d", "Failed"), run("e", "running")];
  expect(filterRuns(runs, { activeOnly: true, limit: null }).map((r) => r.id)).toEqual(["b", "c", "e"]);
  expect(filterRuns(runs, { activeOnly: true, limit: 2 }).map((r) => r.id)).toEqual(["b", "c"]);
  expect(filterRuns(runs, { activeOnly: false, limit: 3 }).map((r) => r.id)).toEqual(["a", "b", "c"]);
  expect(filterRuns(runs, { activeOnly: false, limit: null })).toHaveLength(5);
});

it("reports filter changes from the run list controls", async () => {
  const onChange = vi.fn();
  const host = await mount(<RunListFilters value={{ activeOnly: false, limit: null }} onChange={onChange} />);
  const box = host.querySelector("input[type=checkbox]") as HTMLInputElement;
  await act(async () => box.click());
  expect(onChange).toHaveBeenCalledWith({ activeOnly: true, limit: null });
  const select = host.querySelector("select") as HTMLSelectElement;
  await act(async () => { select.value = "20"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  expect(onChange).toHaveBeenCalledWith({ activeOnly: false, limit: 20 });
});

it("saves the work order packet through the native save dialog", async () => {
  invoke.mockResolvedValue("/tmp/order.json");
  const saved = await saveWorkOrderPacket({ id: "abc", task: "x" });
  expect(saved).toBe("/tmp/order.json");
  expect(invoke).toHaveBeenCalledWith("save_text_file", {
    fileName: "harness-work-order-abc.json",
    extensions: ["json"],
    contents: JSON.stringify({ id: "abc", task: "x" }, null, 2),
  });
});

it("hides Clang analysis when the build lacks it or the language is not C or C++", async () => {
  invoke.mockImplementation(async (command: string) => command === "clang_available" ? false : null);
  const absent = await mount(<ClangAnalysisPanel project="/p" lang="c" pollMs={0} />);
  expect(absent.textContent).toBe("");
  await cleanup();
  invoke.mockImplementation(async (command: string) => command === "clang_available" ? true : null);
  const rust = await mount(<ClangAnalysisPanel project="/p" lang="rust" pollMs={0} />);
  expect(rust.textContent).toBe("");
});

it("starts Clang analysis, polls it to completion and shows the result counts", async () => {
  let polls = 0;
  invoke.mockImplementation(async (command: string) => {
    if (command === "clang_available") return true;
    if (command === "clang_analysis_start") return { id: "op-1", state: "staging", failure: null };
    if (command === "clang_analysis_status") {
      polls += 1;
      return { id: "op-1", state: polls > 1 ? "done" : "analyzing", failure: null };
    }
    if (command === "clang_analysis_result") {
      return { index: { clang_version: "18.1", units: [1, 2], functions: [1, 2, 3], calls: [1] } };
    }
    return null;
  });
  const host = await mount(<ClangAnalysisPanel project="/p" lang="cpp" pollMs={0} />);
  await act(async () => button(host, "Run Clang analysis").click());
  await settle();
  expect(invoke).toHaveBeenCalledWith("clang_analysis_start", { project: "/p", lang: "cpp" });
  expect(invoke).toHaveBeenCalledWith("clang_analysis_status", { operationId: "op-1" });
  expect(invoke).toHaveBeenCalledWith("clang_analysis_result", { operationId: "op-1" });
  expect(host.textContent).toContain("3 functions");
  expect(host.textContent).toContain("2 translation units");
});

it("shows a Clang failure and can cancel a running analysis", async () => {
  invoke.mockImplementation(async (command: string) => {
    if (command === "clang_available") return true;
    if (command === "clang_analysis_start") return { id: "op-2", state: "analyzing", failure: null };
    if (command === "clang_analysis_status") return { id: "op-2", state: "analyzing", failure: null };
    if (command === "clang_analysis_cancel") return { id: "op-2", state: "cancelled", failure: null };
    return null;
  });
  const host = await mount(<ClangAnalysisPanel project="/p" lang="c" pollMs={50} />);
  await act(async () => button(host, "Run Clang analysis").click());
  await flush();
  await act(async () => button(host, "Stop").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("clang_analysis_cancel", { operationId: "op-2" });
  expect(host.textContent).toContain("cancelled");
});

it("arms a remote server with the entered address and token", async () => {
  invoke.mockResolvedValue(true);
  const host = await mount(<RemoteArmPanel />);
  const [url, token] = [...host.querySelectorAll("input")] as HTMLInputElement[];
  expect(token.type).toBe("password");
  expect(button(host, "Check").disabled).toBe(true);
  await type(url, "http://127.0.0.1:8081");
  await type(token, "secret");
  await act(async () => button(host, "Authorize").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("remote_schedule_arm", { url: "http://127.0.0.1:8081", action: "arm", token: "secret" });
  expect(host.textContent).toContain("authorized");
});

it("reports a remote server failure and omits an empty token", async () => {
  invoke.mockRejectedValue("connection refused");
  const host = await mount(<RemoteArmPanel />);
  await type(host.querySelector("input") as HTMLInputElement, "http://127.0.0.1:9");
  await act(async () => button(host, "Check").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("remote_schedule_arm", { url: "http://127.0.0.1:9", action: "status", token: undefined });
  expect(host.querySelector("[role=alert]")?.textContent).toContain("connection refused");
});

it("loads the full run record on request", async () => {
  invoke.mockResolvedValue({ id: "run-1", active_in_this_process: false, telemetry: null });
  const host = await mount(<RunRecordPanel runId="run-1" />);
  expect(invoke).not.toHaveBeenCalled();
  await act(async () => button(host, "Full record").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("run_detail", { runId: "run-1" });
  expect(host.querySelector("pre")?.textContent).toContain("active_in_this_process");
});

it("starts the REST server for the active project, shows the token once and stops it", async () => {
  invoke.mockImplementation(async (command: string) => {
    if (command === "rest_server_status") return null;
    if (command === "rest_server_start") return { url: "http://127.0.0.1:8081", token: "tok-123", project_roots: ["/p"] };
    if (command === "rest_server_stop") return true;
    return null;
  });
  const host = await mount(<RestServerPanel project="/p" />);
  await act(async () => button(host, "Start server").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("rest_server_start", { port: 8081, projectRoots: ["/p"] });
  expect(host.textContent).toContain("http://127.0.0.1:8081");
  expect((host.querySelector("input[readonly]") as HTMLInputElement).value).toBe("tok-123");
  await act(async () => button(host, "Stop server").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("rest_server_stop");
  expect(host.querySelector("input[readonly]")).toBeNull();
  expect(button(host, "Start server")).toBeTruthy();
});

it("shows a server that is already running without its token, and needs a project to start", async () => {
  invoke.mockImplementation(async (command: string) =>
    command === "rest_server_status" ? { url: "http://127.0.0.1:9000", project_roots: ["/p"] } : null);
  const running = await mount(<RestServerPanel project="/p" />);
  expect(running.textContent).toContain("http://127.0.0.1:9000");
  expect(running.querySelector("input[readonly]")).toBeNull();
  expect(button(running, "Stop server")).toBeTruthy();
  await cleanup();
  invoke.mockResolvedValue(null);
  const idle = await mount(<RestServerPanel project="" />);
  expect(button(idle, "Start server").disabled).toBe(true);
});
