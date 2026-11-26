// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ConfirmContext } from "../providers/confirm";
import { enParityBinary } from "../i18n.parityBinary";
import { BinaryTriageSection } from "../components/binary/BinaryTriage";
import type { BinaryFuzzOutcome, BinarySessionSummary } from "../lib/parityBinary";

const mocks = vi.hoisted(() => ({ invoke: vi.fn(), confirm: vi.fn() }));

vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: mocks.invoke }),
  isTauriEnvironment: () => true,
  openExternal: vi.fn(),
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const SHA = "a".repeat(64);
const session = (id: string, findings: number): BinarySessionSummary => ({
  session: id, workspace: `/ws/${id}`, binary_name: "picinfo", binary_sha256: "b".repeat(64), machine: "aarch64",
  input: "file", duration_secs: 60, started_at: null, finished_at: "2026-11-26T00:00:00Z", execs_done: 157418,
  findings, distinct_findings: findings, confirmed: findings, minimized: 0, continued_from: null, can_continue: true,
});
const outcome: BinaryFuzzOutcome = {
  session: "s-1", workspace: "/ws/s-1", binary_name: "picinfo", binary_sha256: "b".repeat(64), machine: "aarch64",
  input: "file", duration_secs: 60, execs_done: 157418, execs_per_sec: 2623.5, edges_found: 55, corpus_count: 4,
  saved_hangs: 0, distinct_findings: 1, findings_omitted: 0,
  findings: [{
    input: "/ws/s-1/findings/crash", sha256: SHA, size: 8, fuzzer_signal: 11, replay_signal: 11, replayed: true,
    confirmed: true, kind: "Segv", signature: "sig", summary: "SEGV (signal 11) at (/work/target+0xcbc)",
    frames: ["#0 0x5500000cbc (/work/target+0xcbc)"], duplicate_of: null, minimized: null,
  }],
};

let host: HTMLDivElement;
let root: Root;

function render() {
  const t = (key: string, params?: Record<string, string | number>) =>
    Object.entries(params ?? {}).reduce((text, [k, v]) => text.replace(`{${k}}`, String(v)), enParityBinary[key] ?? key);
  act(() => root.render(
    <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t }}>
      <ConfirmContext.Provider value={mocks.confirm}>
        <BinaryTriageSection project="/proj" />
      </ConfirmContext.Provider>
    </I18nContext.Provider>,
  ));
}

const settle = () => act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
const button = (name: string) => [...host.querySelectorAll("button")].find((b) => b.textContent === name) as HTMLButtonElement;

beforeEach(() => {
  mocks.invoke.mockReset();
  mocks.invoke.mockResolvedValue(null);
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

describe("BinaryTriageSection", () => {
  it("stays hidden when the project has no binary sessions or they cannot be read", async () => {
    mocks.invoke.mockResolvedValueOnce([]);
    render();
    await settle();
    expect(host.textContent).toBe("");
    mocks.invoke.mockRejectedValueOnce("Unsupported command in web mode");
    render();
    await settle();
    expect(host.textContent).toBe("");
  });

  it("lists sessions with their finding counts and opens a session's findings", async () => {
    mocks.invoke.mockImplementation(async (name: string) => {
      if (name === "binary_sessions") return [session("s-1", 1), session("s-2", 0)];
      if (name === "binary_session") return outcome;
      return null;
    });
    render();
    await settle();
    expect(host.textContent).toContain(enParityBinary["binary.triageSection"]);
    expect(host.textContent).toContain("1/2");
    expect(host.textContent).toContain("1 distinct, 1 confirmed");
    expect(host.textContent).toContain("157,418 execs");
    expect([...host.querySelectorAll("button")].filter((b) => b.textContent === "Show findings")).toHaveLength(1);
    await act(async () => { button("Show findings").click(); });
    expect(mocks.invoke).toHaveBeenCalledWith("binary_session", { project: "/proj", session: "s-1" });
    expect(host.textContent).toContain("SEGV (signal 11)");
    expect(button("Hide findings")).toBeDefined();
  });
});
