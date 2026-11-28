// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ConfirmContext } from "../providers/confirm";
import { ProjectContext } from "../providers/project";
import { enParityBinary } from "../i18n.parityBinary";
import { BinaryView } from "../views/BinaryView";
import type { BinaryFuzzOutcome, BinaryProfile, BinarySessionSummary } from "../lib/parityBinary";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  pickFile: vi.fn(),
  pickFolder: vi.fn(),
  openExternal: vi.fn(),
  confirm: vi.fn(),
}));

vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: mocks.invoke }),
  isTauriEnvironment: () => true,
  pickFile: mocks.pickFile,
  pickFolder: mocks.pickFolder,
  openExternal: mocks.openExternal,
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const SHA = "a".repeat(64);
const outcome: BinaryFuzzOutcome = {
  session: "11111111-1111-1111-1111-111111111111",
  workspace: "/ws/session-1",
  target_args: ["-p", "8080"],
  binary_name: "server",
  binary_sha256: "b".repeat(64),
  machine: "x86_64",
  input: "socket",
  duration_secs: 60,
  execs_done: 12345,
  execs_per_sec: 205.5,
  edges_found: 77,
  corpus_count: 9,
  saved_hangs: 2,
  distinct_findings: 1,
  findings_omitted: 3,
  findings: [{
    input: "/ws/session-1/findings/a", sha256: SHA, size: 42, fuzzer_signal: 11, replay_signal: 11,
    replayed: true, confirmed: true, kind: "heap-buffer-overflow", signature: "sig", summary: "write in parse",
    frames: ["parse+0x10", "main+0x4"], duplicate_of: null, minimized: { input: "/m", sha256: "c".repeat(64), size: 7 },
  }],
};

const summary: BinarySessionSummary = {
  session: outcome.session, workspace: "/ws/session-1", binary_name: "server", binary_sha256: "b".repeat(64),
  machine: "x86_64", input: "socket", duration_secs: 60, started_at: null, finished_at: "2026-11-26T00:00:00Z",
  execs_done: 12345, findings: 1, distinct_findings: 1, confirmed: 1, minimized: 1, continued_from: null, can_continue: true,
};

const profile: BinaryProfile = {
  machine: "x86_64", size: 4096, sha256: "b".repeat(64), linking: "dynamic", imports: ["accept", "recv"],
  suggested_input: "socket", suggestion_reasons: ["imports accept: it serves stream connections"],
  strings: ["LOGIN"], dictionary: ["LOGIN", "\\x00\\xff"], notes: [],
};

/** Let the analysis delay and pending promises run. */
const settle = () => act(async () => { await new Promise((resolve) => setTimeout(resolve, 600)); });

let host: HTMLDivElement;
let root: Root;

function render(project = "/proj") {
  const t = (key: string, params?: Record<string, string | number>) =>
    Object.entries(params ?? {}).reduce((text, [k, v]) => text.replace(`{${k}}`, String(v)), enParityBinary[key] ?? key);
  act(() => root.render(
    <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t }}>
      <ProjectContext.Provider value={{
        activeProject: project, recentProjects: [], setActiveProject: () => undefined,
        addRecent: () => undefined, removeRecent: () => undefined, deleteProjectData: async () => undefined,
      }}>
        <ConfirmContext.Provider value={mocks.confirm}>
          <BinaryView />
        </ConfirmContext.Provider>
      </ProjectContext.Provider>
    </I18nContext.Provider>,
  ));
}

const button = (name: string) => [...host.querySelectorAll("button")].find((b) => b.textContent === name) as HTMLButtonElement;
async function setValue(el: HTMLInputElement, value: string) {
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
const click = (el: HTMLElement) => act(async () => { el.click(); });

beforeEach(() => {
  mocks.invoke.mockReset(); mocks.pickFile.mockReset(); mocks.confirm.mockReset(); mocks.openExternal.mockReset();
  mocks.invoke.mockResolvedValue(null);
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

describe("BinaryView", () => {
  it("explains the page and keeps Start disabled until a binary is named", () => {
    render();
    expect(host.textContent).toContain(enParityBinary["binary.emptyTitle"]);
    expect(host.textContent).toContain("Linux ELF");
    expect(button("Start session").disabled).toBe(true);
    expect(host.querySelectorAll('input[type="radio"]')).toHaveLength(4);
    expect((host.querySelector("#binary-timeout") as HTMLInputElement).value).toBe("1000");
  });

  it("starts a session with every option and shows the result", async () => {
    mocks.invoke.mockResolvedValue(outcome);
    mocks.pickFile.mockResolvedValue("/bin/server");
    mocks.pickFolder.mockResolvedValueOnce("/seeds");
    render();
    await click(button("Browse"));
    await click(button("Choose folder"));
    await setValue(host.querySelector("#binary-libraries") as HTMLInputElement, "/libs");
    await setValue(host.querySelector("#binary-timeout") as HTMLInputElement, "250");
    await setValue(host.querySelector("#binary-target-args") as HTMLInputElement, " -p  8080 ");
    await click(host.querySelector('input[value="socket"]') as HTMLElement);
    await click(button("Start session"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: {
      project: "/proj", binary: "/bin/server", input: "socket", seeds: "/seeds",
      libraries: "/libs", durationSecs: 60, timeoutMs: 250, dictionary: [], continueFrom: undefined,
      compcov: true, targetArgs: ["-p", "8080"],
    } });
    expect(host.textContent).toContain("12,345");
    // The arguments the session ran with are part of its result.
    expect(host.textContent).toContain("-p 8080");
    expect(host.textContent).toContain("aaaaaaaa");
    expect(host.textContent).toContain("heap-buffer-overflow");
    expect(host.textContent).toContain("3 crash files");
  });

  it("shows stack frames on demand and drafts an issue from the session report", async () => {
    mocks.invoke.mockImplementation(async (name: string) => name === "binary_fuzz" ? outcome : {
      crash_id: SHA, title: "Crash in parse", description: "body text", labels: ["fuzzing"],
      provider: "github", project_web_url: null, issue_url: null, can_file: true,
    });
    mocks.pickFile.mockResolvedValue("/bin/server");
    render();
    await click(button("Browse"));
    await click(button("Start session"));
    await click(button("Show stack frames"));
    expect(host.textContent).toContain("parse+0x10");
    await click(button("Draft issue"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_issue_export", { project: "/proj", report: "/ws/session-1/report.json", finding: SHA });
    expect(host.textContent).toContain("Crash in parse");
  });

  it("opens an earlier session from history and files an issue only after confirmation", async () => {
    mocks.invoke.mockImplementation(async (name: string) => {
      if (name === "binary_sessions") return [summary];
      if (name === "binary_session") return outcome;
      if (name === "binary_file_issue") return { url: "https://example.test/issues/5", number: 5 };
      return null;
    });
    render();
    await settle();
    expect(host.textContent).toContain(enParityBinary["binary.history"]);
    await click(button("Open"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_session", { project: "/proj", session: outcome.session });
    await click(button("Show stack frames"));
    mocks.confirm.mockResolvedValueOnce(false);
    await click(button("File issue"));
    expect(mocks.invoke).not.toHaveBeenCalledWith("binary_file_issue", expect.anything());
    mocks.confirm.mockResolvedValueOnce(true);
    await click(button("File issue"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_file_issue", { project: "/proj", report: "/ws/session-1/report.json", finding: SHA });
    expect(host.textContent).toContain("https://example.test/issues/5");
  });

  it("analyzes the binary, applies the suggested mode and sends the dictionary", async () => {
    mocks.invoke.mockImplementation(async (name: string) => {
      if (name === "binary_inspect") return profile;
      if (name === "binary_fuzz") return outcome;
      return null;
    });
    render();
    await setValue(host.querySelector("#binary-path") as HTMLInputElement, "/bin/server");
    await settle();
    expect(mocks.invoke).toHaveBeenCalledWith("binary_inspect", { binary: "/bin/server" });
    expect(host.textContent).toContain("accept");
    expect(host.textContent).toContain("imports accept");
    expect((host.querySelector('input[value="socket"]') as HTMLInputElement).checked).toBe(true);
    expect(host.textContent).toContain("Use the dictionary (2)");
    await click(button("Start session"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: expect.objectContaining({
      input: "socket", dictionary: ["LOGIN", "\\x00\\xff"],
    }) });
  });

  it("starts without the dictionary when it is switched off", async () => {
    mocks.invoke.mockImplementation(async (name: string) => name === "binary_inspect" ? profile : name === "binary_fuzz" ? outcome : null);
    render();
    await setValue(host.querySelector("#binary-path") as HTMLInputElement, "/bin/server");
    await settle();
    await click(button("Use the dictionary (2)"));
    await click(button("Start session"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: expect.objectContaining({ dictionary: [] }) });
  });

  it("uses AI seed drafts only after the operator chooses them", async () => {
    mocks.invoke.mockImplementation(async (name: string) => {
      if (name === "binary_seed_drafts") return {
        draft: "d1", directory: "/ws/.binary/x/seed-drafts/d1",
        seeds: [{ name: "ai-seed-00", size: 5, sha256: "e".repeat(64), preview: "LOGIN" }],
      };
      if (name === "binary_fuzz") return outcome;
      return null;
    });
    render();
    await setValue(host.querySelector("#binary-path") as HTMLInputElement, "/bin/server");
    await setValue(host.querySelector('input[aria-label="What does the input look like? (optional)"]') as HTMLInputElement, "a login line");
    await click(button("Draft seeds"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_seed_drafts", {
      project: "/proj", binary: "/bin/server", input: "file", description: "a login line", count: 8,
    });
    expect(host.textContent).toContain("Proposed seeds: 1");
    expect((host.querySelector("#binary-seeds") as HTMLInputElement).value).toBe("");
    await click(button("Use these seeds"));
    expect((host.querySelector("#binary-seeds") as HTMLInputElement).value).toBe("/ws/.binary/x/seed-drafts/d1");
    await click(button("Start session"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: expect.objectContaining({ seeds: "/ws/.binary/x/seed-drafts/d1" }) });
  });

  it("shows live progress while a session runs", async () => {
    let finish: (value: BinaryFuzzOutcome) => void = () => undefined;
    mocks.invoke.mockImplementation((name: string) => {
      if (name === "binary_fuzz") return new Promise<BinaryFuzzOutcome>((resolve) => { finish = resolve; });
      if (name === "binary_progress") return Promise.resolve({
        session: "s", binary_name: "server", stage: "fuzzing", started_at: "2026-11-26T00:00:00Z",
        duration_secs: 60, elapsed_secs: 30, execs_done: 4200, execs_per_sec: 140, edges_found: 31,
        corpus_count: 7, saved_crashes: 2, saved_hangs: 0, stopping: false,
      });
      return Promise.resolve(null);
    });
    mocks.pickFile.mockResolvedValue("/bin/server");
    render();
    await click(button("Browse"));
    await click(button("Start session"));
    await settle();
    const panel = host.querySelector('[aria-label="Session progress"]') as HTMLElement;
    expect(panel.textContent).toContain("4,200");
    expect(panel.querySelector('[data-state="current"]')?.textContent).toBe("Fuzzing");
    expect(panel.querySelector('[data-state="done"]')?.textContent).toBe("Preparing");
    await act(async () => finish(outcome));
    expect(host.querySelector('[aria-label="Session progress"]')).toBeNull();
  });

  it("splits comparisons by default and lets the operator turn it off", async () => {
    mocks.invoke.mockImplementation(async (name: string) => name === "binary_fuzz" ? outcome : null);
    mocks.pickFile.mockResolvedValue("/bin/server");
    render();
    await click(button("Browse"));
    expect(host.textContent).toContain("Split comparisons (CompCov)");
    await click(button("Split comparisons (CompCov)"));
    await click(button("Start session"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: expect.objectContaining({ compcov: false }) });
  });

  it("runs a persistent session on the suggested entry, for file input only", async () => {
    const fileProfile: BinaryProfile = {
      ...profile, suggested_input: "file", functions: ["main", "parse_header"], persistent_entry: "main",
    };
    mocks.invoke.mockImplementation(async (name: string) => name === "binary_inspect" ? fileProfile
      : name === "binary_fuzz" ? { ...outcome, input: "file", persistent_entry: "main (target+0x9d8)", stability_pct: 72.5 } : null);
    mocks.pickFile.mockResolvedValue("/bin/picinfo");
    render();
    await click(button("Browse"));
    await settle();
    expect(host.textContent).toContain("Persistent mode");
    await click(button("Persistent mode"));
    const entry = host.querySelector("#binary-persistent-entry") as HTMLInputElement;
    expect(entry.value).toBe("main");
    expect([...host.querySelectorAll("#binary-functions option")].map((o) => (o as HTMLOptionElement).value))
      .toEqual(["main", "parse_header"]);
    const iterations = host.querySelector("#binary-persistent-iterations") as HTMLInputElement;
    expect(iterations.value).toBe("1000");

    await setValue(iterations, "0");
    expect(host.textContent).toContain("Enter a whole number from 1 to 100,000.");
    expect(button("Start session").disabled).toBe(true);
    await setValue(iterations, "5000");
    await setValue(entry, "");
    expect(host.textContent).toContain(enParityBinary["binary.invalidEntry"]);
    expect(button("Start session").disabled).toBe(true);
    await setValue(entry, "0x9d8");
    await click(button("Restore memory each iteration"));
    await click(button("Start session"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: expect.objectContaining({
      input: "file", persistent: { entry: "0x9d8", iterations: 5000, restore_memory: true },
    }) });
    expect(host.textContent).toContain("Persistent: main (target+0x9d8)");
    expect(host.textContent).toContain("72.5%");
    expect(host.textContent).toContain(enParityBinary["binary.lowStability"]);

    // Other input modes hide the switch and send no persistent loop, even when it was on.
    await click(host.querySelector('input[value="stdin"]') as HTMLElement);
    expect(host.textContent).not.toContain("Persistent mode");
    await click(button("Start session"));
    const fuzzCalls = mocks.invoke.mock.calls.filter(([name]) => name === "binary_fuzz");
    expect(fuzzCalls).toHaveLength(2);
    expect(fuzzCalls[1][1].options).toMatchObject({ input: "stdin" });
    expect(fuzzCalls[1][1].options.persistent).toBeUndefined();
  });

  it("shows the loop's stability while a session runs", async () => {
    mocks.invoke.mockImplementation((name: string) => {
      if (name === "binary_fuzz") return new Promise<BinaryFuzzOutcome>(() => undefined);
      if (name === "binary_progress") return Promise.resolve({
        session: "s-run", binary_name: "server", stage: "fuzzing", started_at: "2026-11-26T00:00:00Z",
        duration_secs: 600, elapsed_secs: 12, execs_done: 1000, execs_per_sec: 8126, edges_found: 10,
        corpus_count: 2, saved_crashes: 0, saved_hangs: 0, stopping: false, stability_pct: 100,
      });
      return Promise.resolve(null);
    });
    mocks.pickFile.mockResolvedValue("/bin/server");
    render();
    await click(button("Browse"));
    await click(button("Start session"));
    await settle();
    const panel = host.querySelector('[aria-label="Session progress"]') as HTMLElement;
    expect(panel.textContent).toContain("Stability");
    expect(panel.textContent).toContain("100.0%");
    expect(panel.textContent).not.toContain(enParityBinary["binary.lowStability"]);
  });

  it("stops a running session and marks the result as stopped early", async () => {
    let finish: (value: BinaryFuzzOutcome) => void = () => undefined;
    let stopping = false;
    mocks.invoke.mockImplementation((name: string, args: Record<string, unknown>) => {
      if (name === "binary_fuzz") return new Promise<BinaryFuzzOutcome>((resolve) => { finish = resolve; });
      if (name === "binary_stop") { stopping = true; return Promise.resolve(args.session === "s-run"); }
      if (name === "binary_progress") return Promise.resolve({
        session: "s-run", binary_name: "server", stage: "fuzzing", started_at: "2026-11-26T00:00:00Z",
        duration_secs: 600, elapsed_secs: 12, execs_done: 1000, execs_per_sec: 90, edges_found: 10,
        corpus_count: 2, saved_crashes: 0, saved_hangs: 0, stopping,
      });
      return Promise.resolve(null);
    });
    mocks.pickFile.mockResolvedValue("/bin/server");
    render();
    await click(button("Browse"));
    await click(button("Start session"));
    await settle();
    await click(button("Stop"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_stop", { project: "/proj", session: "s-run" });
    expect(host.textContent).toContain("Stopping...");
    await act(async () => finish({ ...outcome, stopped: true, compcov: true }));
    expect(host.textContent).toContain("Stopped early");
    expect(host.textContent).toContain("CompCov");
  });

  it("continues an earlier session of the same binary", async () => {
    mocks.invoke.mockImplementation(async (name: string) => name === "binary_sessions" ? [summary] : name === "binary_fuzz" ? outcome : null);
    render();
    await settle();
    await click(button("Continue"));
    expect((host.querySelector("#binary-path") as HTMLInputElement).value).toBe("/ws/session-1/target");
    expect(host.textContent).toContain("Continuing session 11111111 of server");
    // The form's start button now reads Continue; it comes before the history row's.
    await click(button("Continue"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: expect.objectContaining({
      binary: "/ws/session-1/target", input: "socket", continueFrom: outcome.session,
    }) });
  });

  it("shows a stored AI note and drafts a new one on request", async () => {
    mocks.invoke.mockImplementation(async (name: string) => {
      if (name === "binary_sessions") return [summary];
      if (name === "binary_session") return outcome;
      if (name === "binary_finding_explanation") return { session: outcome.session, finding_sha256: SHA, text: "Likely bug class: stored note", created_at: "2026-11-26T00:00:00Z" };
      if (name === "binary_finding_explain") return {
        session: outcome.session, finding_sha256: SHA, text: "Likely bug class: out-of-bounds write", created_at: "2026-11-26T00:01:00Z",
        disassembly: "faulting frame at target+0xcbc:\n=>      cbc: ldrb w2, [x22, x0]\n",
      };
      return null;
    });
    render();
    await settle();
    await click(button("Open"));
    await click(button("Show stack frames"));
    await settle();
    expect(host.textContent).toContain("stored note");
    expect(host.textContent).toContain("Model output");
    await click(button("Explain again"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_finding_explain", { project: "/proj", session: outcome.session, finding: SHA });
    expect(host.textContent).toContain("out-of-bounds write");
    expect(host.textContent).toContain("Disassembly sent with the request");
    expect(host.querySelector('[aria-label="Disassembly sent with the request"]')?.textContent).toContain("=>      cbc: ldrb w2, [x22, x0]");
  });

  it("reports a failed session", async () => {
    mocks.invoke.mockRejectedValue("sandbox unavailable");
    mocks.pickFile.mockResolvedValue("/bin/server");
    render();
    await click(button("Browse"));
    await click(button("Start session"));
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("sandbox unavailable");
  });
});
