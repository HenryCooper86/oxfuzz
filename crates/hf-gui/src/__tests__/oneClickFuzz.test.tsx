// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { OneClickFuzz, type OneClickApi } from "../components/OneClickFuzz";
import { I18nProvider } from "../i18n";

// One-click fuzzing stops at the human approval: preparation carries only the
// smoke-test consent, and a run starts only after that exact harness is approved.
const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  stage: undefined as undefined | ((payload: unknown) => void),
  runFuzzer: vi.fn(async () => 0),
  setTarget: vi.fn(), setEngine: vi.fn(), setLang: vi.fn(), markDone: vi.fn(),
}));
vi.mock("../lib", () => ({
  getTransport: () => ({
    invoke: mocks.invoke,
    listen: async (event: string, handler: (e: { payload: unknown }) => void) => {
      if (event === "fuzz:stage") mocks.stage = payload => handler({ payload });
      return () => { mocks.stage = undefined; };
    },
  }),
}));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/proj" }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ setTarget: mocks.setTarget, setEngine: mocks.setEngine, setLang: mocks.setLang }) }));
vi.mock("../providers/pipeline", () => ({ usePipeline: () => ({ markDone: mocks.markDone }) }));
vi.mock("../providers/runOutput", () => ({ useRunOutput: () => ({ runFuzzer: mocks.runFuzzer }) }));
vi.mock("../hooks/useFuzzingSettings", () => ({ useFuzzingSettings: () => ({ settings: { default_engine: "libfuzzer", default_duration_secs: 600 } }) }));

let host: HTMLDivElement; let root: Root; let api: OneClickApi | null; const open = vi.fn();
const flush = async () => act(async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); });
const button = (label: string) => [...host.querySelectorAll("button")].find(b => b.textContent?.trim() === label);
beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  for (const fn of [mocks.invoke, mocks.runFuzzer, mocks.setTarget, mocks.setEngine, mocks.setLang, mocks.markDone, open]) fn.mockClear();
  api = null;
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await act(async () => root.render(<I18nProvider><OneClickFuzz onOpen={open} apiRef={(value) => { api = value; }} /></I18nProvider>));
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

it("prepares, stops at approval, and starts one run only after that harness is approved", async () => {
  let finish!: (value: unknown) => void;
  mocks.invoke.mockImplementation((command: string) => command === "fuzz_prepare" ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(null));
  expect(host.textContent).toContain("10 min");
  await act(async () => button("Fuzz this project")!.click());
  expect(mocks.invoke).toHaveBeenCalledWith("fuzz_prepare", { project: "/proj", engine: "libfuzzer" });
  await act(async () => mocks.stage!({ stage: "smoke", target: "parse_number", reused: false }));
  expect(host.textContent).toContain("Smoke-testing the harness for parse_number");
  await act(async () => finish({ target: "parse_number", lang: "C", engine: "libfuzzer", harness_reused: false, repairs_used: 0, smoke_repairs: 0 }));
  await flush();
  expect(mocks.setTarget).toHaveBeenCalledWith("parse_number");
  expect(mocks.setLang).toHaveBeenCalledWith("c");
  expect(mocks.markDone).toHaveBeenCalledWith("discover", "/proj");
  expect(open).toHaveBeenCalledWith("harness");
  expect(host.textContent).toContain("approve it to start a 10 min run");
  expect(mocks.runFuzzer).not.toHaveBeenCalled();

  // Approval of a different target does nothing.
  await act(async () => api!.approved({ project: "/proj", target: "other", engine: "libfuzzer" }));
  expect(mocks.runFuzzer).not.toHaveBeenCalled();
  await act(async () => api!.approved({ project: "/proj", target: "parse_number", engine: "libfuzzer" }));
  await flush();
  expect(mocks.runFuzzer).toHaveBeenCalledWith({ project: "/proj", target: "parse_number", engine: "libfuzzer", duration: 600 });
  expect(open).toHaveBeenCalledWith("run");
  expect(host.textContent).toContain("Started a 10 min run of parse_number");
});

it("asks before running when the target already had an approved harness", async () => {
  mocks.invoke.mockResolvedValue({ target: "parse_number", lang: "Cpp", engine: "afl++", harness_reused: true, repairs_used: 0, smoke_repairs: 0 });
  await act(async () => button("Fuzz this project")!.click());
  await flush();
  expect(mocks.setLang).toHaveBeenCalledWith("cpp");
  expect(host.textContent).toContain("parse_number already has an approved harness");
  expect(mocks.runFuzzer).not.toHaveBeenCalled();
  await act(async () => button("Start a 10 min run")!.click());
  await flush();
  expect(mocks.runFuzzer).toHaveBeenCalledWith({ project: "/proj", target: "parse_number", engine: "afl++", duration: 600 });
});

it("shows a preparation failure", async () => {
  mocks.invoke.mockRejectedValue(new Error("fuzz smoke failed for 'parse': hollow pass"));
  await act(async () => button("Fuzz this project")!.click());
  await flush();
  expect(host.textContent).toContain("hollow pass");
  expect(button("Fuzz this project")).toBeTruthy();
});
