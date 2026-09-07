// @vitest-environment jsdom

import { act, StrictMode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { RunCloseoutPanel } from "../components/RunCloseoutPanel";
import { WorkOrderPanel } from "../components/WorkOrderPanel";
import { enExtra } from "../i18n.extra";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("../lib", async () => {
  const actual = await vi.importActual<typeof import("../lib")>("../lib");
  return { ...actual, getTransport: () => ({ invoke }) };
});

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement;
let root: Root;

function providers(child: React.ReactNode) {
  const t = (key: string, params?: Record<string, string | number>) => {
    let value = enExtra[key] ?? key;
    for (const [name, replacement] of Object.entries(params ?? {})) {
      value = value.replaceAll(`{${name}}`, String(replacement));
    }
    return value;
  };
  return (
    <StrictMode>
      <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t }}>
        {child}
      </I18nContext.Provider>
    </StrictMode>
  );
}

async function render(child: React.ReactNode) {
  await act(async () => {
    root.render(providers(child));
    await Promise.resolve();
  });
}

async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

function button(label: string) {
  const found = [...host.querySelectorAll("button")].find((item) => item.textContent === label);
  if (!found) throw new Error(`button '${label}' is missing`);
  return found as HTMLButtonElement;
}

beforeEach(() => {
  invoke.mockReset();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

describe("expert workflow panels", () => {
  it("reads retained closeout on open and executes only after Analyze is clicked", async () => {
    invoke.mockImplementation((command: string) => Promise.resolve({
      schema_version: 2,
      run_id: "run-1",
      availability: { status: "available" },
      steps: command === "run_closeout" ? [{ step: "triage", outcome: { outcome: "completed", detail: "0 crashes" } }] : [],
      resumed_at: null,
    }));

    await render(<RunCloseoutPanel runId="run-1" runKind="Campaign" runStatus="Done" />);
    await flush();
    expect(invoke.mock.calls.length).toBeGreaterThan(0);
    expect(invoke.mock.calls.every(([command]) => command === "run_closeout_report")).toBe(true);

    await act(async () => button("Analyze / Resume").click());
    expect(invoke.mock.calls.at(-1)).toEqual(["run_closeout", { runId: "run-1" }]);
    expect(host.textContent).toContain("0 crashes");
  });

  it("shows initial closeout loading and every retained outcome label", async () => {
    const resolvers: Array<(value: unknown) => void> = [];
    invoke.mockImplementation((command: string) => {
      if (command !== "run_closeout_report") return Promise.reject(new Error(command));
      return new Promise((resolve) => { resolvers.push(resolve); });
    });
    await render(<RunCloseoutPanel runId="run-labels" runKind="Campaign" runStatus="Failed" />);
    expect(host.textContent).toContain("Loading retained closeout...");
    const report = {
      schema_version: 2,
      run_id: "run-labels",
      availability: { status: "available" },
      steps: [
        { step: "triage", outcome: { outcome: "completed", detail: "triaged" } },
        { step: "minimize", outcome: { outcome: "skipped", reason: "nothing to minimize" } },
        { step: "corpus_absorb", outcome: { outcome: "failed", error: "retained disk failure" } },
        { step: "coverage", outcome: { outcome: "blocked", dependency: "corpus_absorb" } },
      ],
      resumed_at: "corpus_absorb",
    };
    await act(async () => { for (const resolve of resolvers) resolve(report); });
    await flush();
    expect(host.textContent).toContain("Completed: triaged");
    expect(host.textContent).toContain("Skipped: nothing to minimize");
    expect(host.textContent).toContain("Failed: retained disk failure");
    expect(host.textContent).toContain("Blocked: Blocked by Corpus absorb");
    expect(host.textContent).toContain("Pending: Pending");
    expect(host.textContent).toContain("Analyze may triage crashes in the sandbox");
  });

  it("imports, qualifies, ranks, and promotes the exact selected attempt", async () => {
    let qualification = 0;
    invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "work_order_list") return Promise.resolve([]);
      if (command === "work_order_export") return Promise.resolve({ schema_version: 2, id: "wo-1", payload: { target: { symbol: "parse" } } });
      if (command === "work_order_submissions") return Promise.resolve([]);
      if (command === "work_order_import") return Promise.resolve({ id: "submission-1", source_sha256: "a".repeat(64), source: args.source, origin: args.origin, lint: [], submitted_at: "now" });
      if (command === "work_order_qualify") {
        qualification += 1;
        return Promise.resolve(qualification === 1
          ? { id: "attempt-failed", submission_id: "submission-1", status: "smoke_failed", current_stage: "smoke", result: null, failure_code: "smoke_failed", failure_message: "retained smoke failure", started_at: "now", updated_at: "now", ended_at: "now" }
          : { id: "attempt-passed", submission_id: "submission-1", status: "smoke_passed", current_stage: "smoke", harness_id: "harness-1", result: { compiled: true, smoke_verdict: "pass", repair_depth: 0, source_sha256: "a".repeat(64), binary_sha256: "b".repeat(64), execs_per_sec: 400, crashes: 0 }, failure_code: null, failure_message: null, started_at: "now", updated_at: "now", ended_at: "now" });
      }
      if (command === "work_order_attempts") return Promise.resolve([]);
      if (command === "work_order_rank") return Promise.resolve({ attempt_ids: ["attempt-passed", "attempt-failed"], winner_attempt_id: "attempt-passed" });
      if (command === "work_order_promote") return Promise.resolve({ id: "harness-1", status: "Promoted" });
      if (command === "harness_review_queue") return Promise.resolve([{ harness_id: "harness-1", target_id: "target-1", project_root: "/project", target_symbol: "parse", engine: "LibFuzzer", language: "C", status: "SmokePassed", build_output: "fuzz", smoke_passed: true, smoke_execs_per_sec: 400, needs_review: true, next_action: "promote", source_preview: "source", ai_review: { exercises_target: true, safe_to_execute: true, reasons: ["reviewed"], reviewed_at: "now" }, source_sha256: "a".repeat(64), binary_sha256: "b".repeat(64), lint: [] }]);
      return Promise.reject(new Error(command));
    });

    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await act(async () => button("Export work order").click());
    await flush();
    const source = host.querySelector("textarea")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(
        source,
        "int LLVMFuzzerTestOneInput(void) { return 0; }",
      );
      source.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => button("Import submission").click());
    await flush();
    expect(invoke.mock.calls.some(([command]) => command === "work_order_qualify")).toBe(false);
    expect(invoke.mock.calls.some(([command]) => command === "work_order_promote")).toBe(false);
    await act(async () => button("Qualify in sandbox").click());
    await flush();
    expect(host.textContent).toContain("retained smoke failure");
    expect(button("Promote selected attempt").disabled).toBe(true);
    await act(async () => button("Qualify in sandbox").click());
    await flush();
    await act(async () => button("Rank this submission's attempts").click());
    await flush();
    await act(async () => button("Promote selected attempt").click());
    await flush();

    expect(invoke.mock.calls).toContainEqual(["work_order_promote", { attemptId: "attempt-passed" }]);
  });

  it("renders structured native adapter failures and discards a stale project response", async () => {
    let resolveFirst: (value: unknown[]) => void = () => undefined;
    invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command !== "work_order_list") return Promise.reject(new Error(command));
      if (args.project === "/a") return new Promise((resolve) => { resolveFirst = resolve; });
      return Promise.reject({ code: "unavailable", message: "Work Order is unavailable in this build" });
    });

    await render(<WorkOrderPanel project="/a" target="one" language="c" engine="libfuzzer" />);
    await render(<WorkOrderPanel project="/b" target="two" language="c" engine="libfuzzer" />);
    await flush();
    expect(host.textContent).toContain("unavailable: Work Order is unavailable in this build");
    expect(button("Export work order").disabled).toBe(true);
    await act(async () => resolveFirst([{ id: "stale", schema_version: 2, payload: {} }]));
    expect(host.textContent).not.toContain("stale");
    expect(host.textContent).not.toContain("[object Object]");
  });

  it("clears populated Work Order state when the target scope changes", async () => {
    let resolveSecond: (value: unknown[]) => void = () => undefined;
    invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "work_order_list" && args.project === "/a") {
        return Promise.resolve([
          { id: "wrong-target", schema_version: 2, payload: { target: { symbol: "other", language: "c" }, engine: "lib_fuzzer" } },
          { id: "wrong-engine", schema_version: 2, payload: { target: { symbol: "alpha", language: "c" }, engine: "afl_plus_plus" } },
          { id: "order-a", schema_version: 2, payload: { target: { symbol: "alpha", language: "c" }, engine: "lib_fuzzer" } },
        ]);
      }
      if (command === "work_order_list") return new Promise((resolve) => { resolveSecond = resolve; });
      if (command === "work_order_submissions") return Promise.resolve([]);
      return Promise.reject(new Error(command));
    });
    await render(<WorkOrderPanel project="/a" target="alpha" language="c" engine="libfuzzer" />);
    await flush();
    expect(host.textContent).toContain("alpha");
    expect(host.textContent).not.toContain("wrong-target");
    expect(host.textContent).not.toContain("wrong-engine");

    await render(<WorkOrderPanel project="/b" target="beta" language="c" engine="libfuzzer" />);
    expect(host.textContent).not.toContain("alpha");
    await act(async () => resolveSecond([]));
  });

  it("shows exact attempt evidence before approval and drops a late promotion after target switch", async () => {
    let resolvePromotion: (value: { id: string }) => void = () => undefined;
    const onPromoted = vi.fn();
    const order = { id: "order-a", schema_version: 2, payload: { target: { symbol: "alpha", language: "c" }, engine: "lib_fuzzer" } };
    const submission = { id: "submission-a", work_order_id: "order-a", source: "exact source", source_sha256: "a".repeat(64), origin: "human", parent_submission_id: null, lint: [{ severity: "warning", rule: "retained-rule", message: "retained lint message", line: 4 }], submitted_at: "now" };
    const attempt = { id: "attempt-a", submission_id: "submission-a", status: "smoke_passed", current_stage: "smoke", harness_id: "harness-a", smoke_run_id: "smoke-a", result: { compiled: true, smoke_verdict: "pass", repair_depth: 0, source_sha256: "a".repeat(64), binary_sha256: "b".repeat(64), execs_per_sec: 400, crashes: 0 }, failure_code: null, failure_message: null, started_at: "now", updated_at: "now", ended_at: "now" };
    invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "work_order_list") return Promise.resolve(args.project === "/a" ? [order] : []);
      if (command === "work_order_submissions") return Promise.resolve([submission]);
      if (command === "work_order_attempts") return Promise.resolve([attempt]);
      if (command === "work_order_export") return Promise.resolve(order);
      if (command === "harness_review_queue") return Promise.resolve([{ harness_id: "harness-a", target_id: "target-a", project_root: "/a", target_symbol: "alpha", engine: "LibFuzzer", language: "C", status: "SmokePassed", build_output: "fuzz", smoke_passed: true, smoke_execs_per_sec: 400, needs_review: true, next_action: "promote", source_preview: "exact source", ai_review: { exercises_target: true, safe_to_execute: true, reasons: ["exact independent review"], reviewed_at: "now" }, source_sha256: "a".repeat(64), binary_sha256: "b".repeat(64), lint: [] }]);
      if (command === "work_order_promote") return new Promise((resolve) => { resolvePromotion = resolve; });
      return Promise.reject(new Error(command));
    });
    await render(<WorkOrderPanel project="/a" target="alpha" language="c" engine="libfuzzer" onPromoted={onPromoted} />);
    await flush();
    await flush();
    await flush();
    expect(host.textContent).toContain("exact source");
    expect(host.textContent).toContain("retained lint message");
    expect(host.textContent).toContain("exact independent review");
    await act(async () => button("Promote selected attempt").click());
    await render(<WorkOrderPanel project="/b" target="beta" language="c" engine="libfuzzer" onPromoted={onPromoted} />);
    await act(async () => resolvePromotion({ id: "harness-a" }));
    expect(onPromoted).not.toHaveBeenCalled();
  });

  it("does not let a late closeout completion replace the newly selected run", async () => {
    let resolveAnalyze: (value: unknown) => void = () => undefined;
    invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "run_closeout" && args.runId === "run-a") return new Promise((resolve) => { resolveAnalyze = resolve; });
      return Promise.resolve({ schema_version: 2, run_id: args.runId, availability: { status: "available" }, steps: [{ step: "triage", outcome: { outcome: "completed", detail: `${args.runId} retained` } }], resumed_at: null });
    });
    await render(<RunCloseoutPanel runId="run-a" runKind="Campaign" runStatus="Done" />);
    await flush();
    await act(async () => button("Analyze / Resume").click());
    await render(<RunCloseoutPanel runId="run-b" runKind="Campaign" runStatus="Done" />);
    await flush();
    await act(async () => resolveAnalyze({ schema_version: 2, run_id: "run-a", availability: { status: "available" }, steps: [{ step: "triage", outcome: { outcome: "completed", detail: "late run-a" } }], resumed_at: null }));
    expect(host.textContent).toContain("run-b retained");
    expect(host.textContent).not.toContain("late run-a");
  });

  it("reopens a running qualification from retained state and refreshes it to terminal", async () => {
    let terminal = false;
    const order = { id: "order-running", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    const submission = { id: "submission-running", work_order_id: order.id, source: "source", source_sha256: "a".repeat(64), origin: "human", parent_submission_id: null, lint: [], submitted_at: "now" };
    const baseAttempt = { id: "attempt-running", submission_id: submission.id, current_stage: "smoke", harness_id: "harness-running", smoke_run_id: "smoke-running", result: null, failure_code: null, failure_message: null, started_at: "now", updated_at: "now", ended_at: null };
    invoke.mockImplementation((command: string) => {
      if (command === "work_order_list") return Promise.resolve([order]);
      if (command === "work_order_submissions") return Promise.resolve([submission]);
      if (command === "work_order_attempts") {
        return Promise.resolve([{ ...baseAttempt, status: terminal ? "smoke_failed" : "running", failure_code: terminal ? "smoke_failed" : null, failure_message: terminal ? "retained terminal failure" : null }]);
      }
      if (command === "harness_review_queue") return Promise.resolve([]);
      return Promise.reject(new Error(command));
    });
    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await flush();
    expect(button("Qualify in sandbox").disabled).toBe(true);
    terminal = true;
    await act(async () => button("Refresh attempts").click());
    await flush();
    expect(host.textContent).toContain("retained terminal failure");
    expect(button("Qualify in sandbox").disabled).toBe(false);
  });

  it("does not let an older retained-attempt read erase a new qualification", async () => {
    let resolveOldRead: (value: unknown[]) => void = () => undefined;
    const order = { id: "order-race", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    const submission = { id: "submission-race", work_order_id: order.id, source: "source", source_sha256: "a".repeat(64), origin: "human", parent_submission_id: null, lint: [], submitted_at: "now" };
    invoke.mockImplementation((command: string) => {
      if (command === "work_order_list") return Promise.resolve([order]);
      if (command === "work_order_submissions") return Promise.resolve([submission]);
      if (command === "work_order_attempts") return new Promise((resolve) => { resolveOldRead = resolve; });
      if (command === "work_order_qualify") return Promise.resolve({ id: "new-attempt", submission_id: submission.id, status: "smoke_failed", current_stage: "smoke", harness_id: "harness-new", smoke_run_id: "smoke-new", result: null, failure_code: "smoke_failed", failure_message: "new retained result", started_at: "now", updated_at: "now", ended_at: "now" });
      return Promise.reject(new Error(command));
    });
    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await act(async () => button("Qualify in sandbox").click());
    await flush();
    expect(host.textContent).toContain("new retained result");
    await act(async () => resolveOldRead([]));
    expect(host.textContent).toContain("new retained result");
  });

  it("clears the repair parent when export selects a new work order", async () => {
    const firstOrder = { id: "order-first", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    const secondOrder = { id: "order-second", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    const parent = { id: "submission-parent", work_order_id: firstOrder.id, source: "parent source", source_sha256: "a".repeat(64), origin: "human", parent_submission_id: null, lint: [], submitted_at: "now" };
    invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "work_order_list") return Promise.resolve([firstOrder]);
      if (command === "work_order_submissions") return Promise.resolve(args.workOrderId === firstOrder.id ? [parent] : []);
      if (command === "work_order_attempts") return Promise.resolve([]);
      if (command === "work_order_export") return Promise.resolve(secondOrder);
      return Promise.reject(new Error(command));
    });

    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await flush();
    const parentSelect = host.querySelector("select")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(parentSelect, parent.id);
      parentSelect.dispatchEvent(new Event("change", { bubbles: true }));
    });
    expect(parentSelect.value).toBe(parent.id);
    await act(async () => button("Export work order").click());
    await flush();
    expect((host.querySelector("select") as HTMLSelectElement).value).toBe("");
  });

  it("shows missing exact review evidence with a retry action", async () => {
    const order = { id: "order-review", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    const submission = { id: "submission-review", work_order_id: order.id, source: "source", source_sha256: "a".repeat(64), origin: "human", parent_submission_id: null, lint: [], submitted_at: "now" };
    const attempt = { id: "attempt-review", submission_id: submission.id, status: "smoke_passed", current_stage: "smoke", harness_id: "harness-missing", smoke_run_id: "smoke-review", result: null, failure_code: null, failure_message: null, started_at: "now", updated_at: "now", ended_at: "now" };
    let reviewAvailable = false;
    const exactReview = { harness_id: "harness-missing", target_id: "target-review", project_root: "/project", target_symbol: "parse", engine: "LibFuzzer", language: "C", status: "SmokePassed", build_output: "fuzz", smoke_passed: true, smoke_execs_per_sec: 200, needs_review: true, next_action: "promote", source_preview: "review source", ai_review: { exercises_target: true, safe_to_execute: true, reasons: ["review loaded after retry"], reviewed_at: "now" }, source_sha256: "a".repeat(64), binary_sha256: "b".repeat(64), lint: [] };
    invoke.mockImplementation((command: string) => {
      if (command === "work_order_list") return Promise.resolve([order]);
      if (command === "work_order_submissions") return Promise.resolve([submission]);
      if (command === "work_order_attempts") return Promise.resolve([attempt]);
      if (command === "harness_review_queue") return Promise.resolve(reviewAvailable ? [exactReview] : []);
      return Promise.reject(new Error(command));
    });

    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await flush();
    await flush();
    expect(host.textContent).toContain("Exact independent review evidence is unavailable.");
    expect(host.textContent).not.toContain("Loading exact review evidence");
    expect(button("Retry").disabled).toBe(false);
    expect(button("Promote selected attempt").disabled).toBe(true);
    reviewAvailable = true;
    await act(async () => button("Retry").click());
    await flush();
    expect(host.textContent).toContain("review loaded after retry");
    expect(button("Promote selected attempt").disabled).toBe(false);
  });

  it("keeps new export and import results when older scoped reads finish later", async () => {
    const listResolvers: Array<(value: unknown[]) => void> = [];
    const submissionResolvers: Array<(value: unknown[]) => void> = [];
    const order = { id: "order-new", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "work_order_list") return new Promise((resolve) => { listResolvers.push(resolve); });
      if (command === "work_order_export") return Promise.resolve(order);
      if (command === "work_order_submissions") return new Promise((resolve) => { submissionResolvers.push(resolve); });
      if (command === "work_order_import") return Promise.resolve({ id: "submission-new", work_order_id: order.id, source: args.source, source_sha256: "c".repeat(64), origin: "human", parent_submission_id: null, lint: [], submitted_at: "now" });
      return Promise.reject(new Error(command));
    });

    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await act(async () => button("Export work order").click());
    await flush();
    const source = host.querySelector("textarea")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(source, "new exact source");
      source.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => button("Import submission").click());
    await flush();
    expect(host.textContent).toContain("new exact source");

    await act(async () => {
      for (const resolve of listResolvers) resolve([]);
      for (const resolve of submissionResolvers) resolve([]);
    });
    expect(host.textContent).toContain("order-new");
    expect(host.textContent).toContain("new exact source");
  });

  it("shows external tool and UTF-8 source admission requirements", async () => {
    const order = { id: "order-limits", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    invoke.mockImplementation((command: string) => {
      if (command === "work_order_list") return Promise.resolve([order]);
      if (command === "work_order_submissions") return Promise.resolve([]);
      return Promise.reject(new Error(command));
    });
    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();

    const source = host.querySelector("textarea")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(source, "source");
      source.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(host.textContent).toContain("External tool name is required.");
    expect(button("Import submission").disabled).toBe(false);

    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(source, "é".repeat(32_769));
      source.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(host.textContent).toContain("65,538 / 65,536 UTF-8 bytes");
    expect(host.textContent).toContain("source is too large");
    expect(button("Import submission").disabled).toBe(true);
  });

  it("surfaces clipboard failures", async () => {
    const order = { id: "order-copy", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    invoke.mockImplementation((command: string) => {
      if (command === "work_order_list") return Promise.resolve([order]);
      if (command === "work_order_submissions") return Promise.resolve([]);
      return Promise.reject(new Error(command));
    });
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await act(async () => button("Copy packet").click());
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("Clipboard access is unavailable");
  });

  it("keeps retained evidence when the selected order and submission are clicked again", async () => {
    const order = { id: "order-repeat", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    const submission = { id: "submission-repeat", work_order_id: order.id, source: "repeat source", source_sha256: "d".repeat(64), origin: "human", parent_submission_id: null, lint: [], submitted_at: "now" };
    const attempt = { id: "attempt-repeat", submission_id: submission.id, status: "smoke_failed", current_stage: "smoke", harness_id: null, smoke_run_id: null, result: null, failure_code: "smoke_failed", failure_message: "repeat retained failure", started_at: "now", updated_at: "now", ended_at: "now" };
    invoke.mockImplementation((command: string) => {
      if (command === "work_order_list") return Promise.resolve([order]);
      if (command === "work_order_export") return Promise.resolve(order);
      if (command === "work_order_submissions") return Promise.resolve([submission]);
      if (command === "work_order_attempts") return Promise.resolve([attempt]);
      return Promise.reject(new Error(command));
    });

    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await flush();
    expect(host.textContent).toContain("repeat retained failure");
    await act(async () => button("order-repeat...").click());
    expect(host.textContent).toContain("repeat retained failure");
    await act(async () => button(`${"d".repeat(16)}... · human · new · 0 lint findings`).click());
    expect(host.textContent).toContain("repeat retained failure");
    await act(async () => button("Export work order").click());
    await flush();
    expect(host.textContent).toContain("repeat retained failure");
  });

  it("lets an in-flight history read finish when export returns the same order", async () => {
    const historyResolvers: Array<(value: unknown[]) => void> = [];
    const order = { id: "order-same", schema_version: 2, payload: { target: { symbol: "parse", language: "c" }, engine: "lib_fuzzer" } };
    const submission = { id: "submission-same", work_order_id: order.id, source: "same order retained history", source_sha256: "e".repeat(64), origin: "human", parent_submission_id: null, lint: [], submitted_at: "now" };
    invoke.mockImplementation((command: string) => {
      if (command === "work_order_list") return Promise.resolve([order]);
      if (command === "work_order_submissions") return new Promise((resolve) => { historyResolvers.push(resolve); });
      if (command === "work_order_export") return Promise.resolve(order);
      if (command === "work_order_attempts") return Promise.resolve([]);
      return Promise.reject(new Error(command));
    });
    await render(<WorkOrderPanel project="/project" target="parse" language="c" engine="libfuzzer" />);
    await flush();
    await act(async () => button("Export work order").click());
    await flush();
    await act(async () => { for (const resolve of historyResolvers) resolve([submission]); });
    await flush();
    expect(host.textContent).toContain("same order retained history");
  });
});
