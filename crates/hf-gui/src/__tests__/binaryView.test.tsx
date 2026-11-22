// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ConfirmContext } from "../providers/confirm";
import { ProjectContext } from "../providers/project";
import { enParityBinary } from "../i18n.parityBinary";
import { BinaryView } from "../views/BinaryView";
import type { BinaryFuzzOutcome } from "../lib/parityBinary";

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
    await click(host.querySelector('input[value="socket"]') as HTMLElement);
    await click(button("Start session"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_fuzz", { options: {
      project: "/proj", binary: "/bin/server", input: "socket", seeds: "/seeds",
      libraries: "/libs", durationSecs: 60, timeoutMs: 250,
    } });
    expect(host.textContent).toContain("12,345");
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

  it("files an issue only after confirmation and shows the URL", async () => {
    mocks.invoke.mockResolvedValue({ url: "https://example.test/issues/5", number: 5 });
    render();
    await setValue(host.querySelector("#binary-report") as HTMLInputElement, "/old/report.json");
    await setValue(host.querySelector("#binary-finding") as HTMLInputElement, "deadbeef");
    mocks.confirm.mockResolvedValueOnce(false);
    await click(button("File issue"));
    expect(mocks.invoke).not.toHaveBeenCalled();
    mocks.confirm.mockResolvedValueOnce(true);
    await click(button("File issue"));
    expect(mocks.invoke).toHaveBeenCalledWith("binary_file_issue", { project: "/proj", report: "/old/report.json", finding: "deadbeef" });
    expect(host.textContent).toContain("https://example.test/issues/5");
  });

  it("rejects a finding id shorter than 8 hex digits", async () => {
    render();
    await setValue(host.querySelector("#binary-report") as HTMLInputElement, "/old/report.json");
    await setValue(host.querySelector("#binary-finding") as HTMLInputElement, "abc");
    expect(host.textContent).toContain(enParityBinary["binary.invalidFinding"]);
    expect(button("File issue")).toBeUndefined();
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
