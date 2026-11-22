// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { DictionaryPanel } from "../components/DictionaryPanel";
import { CampaignPanel } from "../components/CampaignPanel";
import { CiGatePanel } from "../components/CiGatePanel";
import { PreflightPanel } from "../components/PreflightPanel";

const invoke = vi.hoisted(() => vi.fn());
const listen = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke, listen }) }));

let cleanup = async () => {};
beforeEach(() => {
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  invoke.mockReset();
  listen.mockReset();
  listen.mockResolvedValue(() => {});
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
const flush = async () => act(async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); });
const button = (host: HTMLElement, text: string) =>
  [...host.querySelectorAll("button")].find((b) => b.textContent?.includes(text)) as HTMLButtonElement;
const byLabel = (host: HTMLElement, label: string) =>
  host.querySelector(`[aria-label="${label}"]`) as HTMLInputElement & HTMLTextAreaElement;
async function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  await act(async () => {
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

it("shows the stored dictionary, saves a new one with its token count, and clears it", async () => {
  invoke.mockImplementation(async (command: string) => {
    if (command === "user_dictionary") return "\"GET\"";
    if (command === "set_user_dictionary") return 3;
    return undefined;
  });
  const host = await mount(<DictionaryPanel project="/p" target="parse" />);
  expect(invoke).toHaveBeenCalledWith("user_dictionary", { project: "/p", target: "parse" });
  expect(host.textContent).toContain("\"GET\"");

  await type(byLabel(host, "Dictionary text"), "\"a\"\n\"b\"\n\"c\"");
  await act(async () => button(host, "Save dictionary").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("set_user_dictionary", { project: "/p", target: "parse", text: "\"a\"\n\"b\"\n\"c\"" });
  expect(host.textContent).toContain("3 tokens");

  await act(async () => button(host, "Clear dictionary").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("clear_user_dictionary", { project: "/p", target: "parse" });
});

it("shows an empty state when no dictionary is stored and surfaces a rejected save", async () => {
  invoke.mockImplementation(async (command: string) => {
    if (command === "user_dictionary") return null;
    if (command === "set_user_dictionary") throw new Error("bad token on line 2");
    return undefined;
  });
  const host = await mount(<DictionaryPanel project="/p" target="parse" />);
  expect(host.textContent).toContain("No dictionary stored");
  await type(byLabel(host, "Dictionary text"), "x");
  await act(async () => button(host, "Save dictionary").click());
  await flush();
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("bad token on line 2");
});

it("runs a campaign with the entered options, streams its log and names the refine proposal", async () => {
  let progress: ((event: { payload: unknown }) => void) | undefined;
  listen.mockImplementation(async (event: string, cb: (event: { payload: unknown }) => void) => {
    if (event === "campaign:progress") progress = cb;
    return () => {};
  });
  invoke.mockImplementation(async (command: string) => {
    if (command !== "run_campaign") return undefined;
    progress?.({ payload: { type: "LogLine", data: "iteration 1 started" } });
    return {
      target: "parse", harness_status: "Promoted", crashes: 2, edges: 99, iterations: 2, auto_reverts: 0,
      termination: "completed", refine: { note: "refined harness compiled", harness_id: "abc-123", compiled: true, frontier_locations: 4 },
    };
  });
  const host = await mount(<CampaignPanel project="/p" target="" engine="afl++" lang="c" defaultDurationSecs={60} maxDurationSecs={7200} disabled={false} />);
  await type(byLabel(host, "Campaign iterations"), "2");
  await type(byLabel(host, "Seconds per iteration"), "30");
  await type(byLabel(host, "Campaign target (optional)"), "");
  await type(host.querySelectorAll<HTMLInputElement>('[aria-label="RNG seed"]')[0], "42");
  await act(async () => button(host, "Start campaign").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("run_campaign", {
    options: { project: "/p", engine: "afl++", lang: "c", durationSecs: 30, iterations: 2, seed: "42" },
  });
  expect(listen).toHaveBeenCalledWith("campaign:progress", expect.any(Function));
  expect(host.textContent).toContain("iteration 1 started");
  expect(host.textContent).toContain("2 crashes");
  expect(host.textContent).toContain("abc-123");
  expect(host.textContent).toContain("refined harness compiled");
  expect(host.textContent).toContain("Harness page");
});

it("reports the CI gate verdict and saves the SARIF document", async () => {
  invoke.mockImplementation(async (command: string) => {
    if (command === "run_ci_gate") {
      return { passed: false, findings: [{ kind: "heap-buffer-overflow", summary: "parse reads past the end" }], seed_warning: null, sarif: "{\"version\":\"2.1.0\"}" };
    }
    if (command === "save_text_file") return "/tmp/oxfuzz.sarif";
    return undefined;
  });
  const host = await mount(<CiGatePanel project="/p" target="parse" engine="libfuzzer" maxDurationSecs={7200} disabled={false} />);
  await type(byLabel(host, "CI gate duration (seconds)"), "90");
  await act(async () => button(host, "Run CI gate").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("run_ci_gate", { project: "/p", target: "parse", engine: "libfuzzer", durationSecs: 90 });
  expect(host.textContent).toContain("FAIL");
  expect(host.textContent).toContain("parse reads past the end");
  await act(async () => button(host, "Save SARIF").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("save_text_file", { fileName: "oxfuzz.sarif", extensions: ["sarif", "json"], contents: "{\"version\":\"2.1.0\"}" });
  expect(host.textContent).toContain("/tmp/oxfuzz.sarif");
});

it("shows PASS when the CI gate finds nothing", async () => {
  invoke.mockResolvedValue({ passed: true, findings: [], seed_warning: "seed model unavailable", sarif: "{}" });
  const host = await mount(<CiGatePanel project="/p" target="parse" engine="libfuzzer" maxDurationSecs={7200} disabled={false} />);
  await act(async () => button(host, "Run CI gate").click());
  await flush();
  expect(host.textContent).toContain("PASS");
  expect(host.textContent).toContain("seed model unavailable");
});

it("checks readiness for the engine and duration and lists the checks and problems", async () => {
  invoke.mockResolvedValue({
    engine: "afl++",
    status: { docker: true, sandbox_image: true, aflplusplus: false },
    provider_configured: false,
    ready: false,
    problems: ["no model provider is configured"],
  });
  const host = await mount(<PreflightPanel engine="afl++" durationSecs={120} />);
  await act(async () => byLabel(host, "Require a model").click());
  await act(async () => button(host, "Check readiness").click());
  await flush();
  expect(invoke).toHaveBeenCalledWith("fuzzing_preflight", { engine: "afl++", durationSecs: 120, requireProvider: true });
  expect(host.textContent).toContain("Not ready");
  expect(host.textContent).toContain("no model provider is configured");
  expect(host.textContent).toContain("Docker");
});
