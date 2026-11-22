// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { OneClickFuzz } from "../components/OneClickFuzz";
import { I18nProvider } from "../i18n";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  settings: { default_engine: "libfuzzer", default_duration_secs: 600, enabled_engines: ["libfuzzer", "afl++", "go-native", "atheris", "jazzer", "jazzer-js"] },
}));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke, listen: async () => () => undefined }) }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/proj" }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ setTarget: vi.fn(), setEngine: vi.fn(), setLang: vi.fn() }) }));
vi.mock("../providers/pipeline", () => ({ usePipeline: () => ({ markDone: vi.fn(), markSkipped: vi.fn() }) }));
vi.mock("../providers/runOutput", () => ({ useRunOutput: () => ({ runFuzzer: vi.fn(async () => 0) }) }));
vi.mock("../hooks/useFuzzingSettings", () => ({ useFuzzingSettings: () => ({ settings: mocks.settings }) }));

let host: HTMLDivElement; let root: Root;
const flush = async () => act(async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); });
beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  mocks.invoke.mockReset();
  mocks.invoke.mockResolvedValue({ target: "t", lang: "Python", engine: "atheris", harness_reused: true });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await act(async () => root.render(<I18nProvider><OneClickFuzz onOpen={vi.fn()} /></I18nProvider>));
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

const start = async () => {
  const run = [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === "Fuzz this project")!;
  await act(async () => run.click());
  await flush();
};

it("offers a language choice and a start-fresh checkbox", () => {
  expect(host.querySelector("[aria-label='Language']")).not.toBeNull();
  expect(host.querySelector("input[type='checkbox']")).not.toBeNull();
  expect(host.textContent).toContain("Start fresh (ignore the existing harness)");
});

it("sends fresh when the checkbox is ticked and omits lang on auto-detect", async () => {
  const box = host.querySelector<HTMLInputElement>("input[type='checkbox']")!;
  await act(async () => box.click());
  await start();
  expect(mocks.invoke).toHaveBeenCalledWith("fuzz_prepare", { project: "/proj", engine: "libfuzzer", fresh: true });
});

it("uses the language engine when the language is chosen", async () => {
  const select = host.querySelector<HTMLSelectElement>("select[aria-label='Language']");
  expect(select).not.toBeNull();
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!;
    setter.call(select, "python");
    select!.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await start();
  expect(mocks.invoke).toHaveBeenCalledWith("fuzz_prepare", { project: "/proj", engine: "atheris", lang: "python" });
});
