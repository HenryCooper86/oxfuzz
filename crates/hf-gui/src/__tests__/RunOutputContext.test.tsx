// @vitest-environment jsdom

import { StrictMode, act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ProjectContext } from "../providers/project";
import { RunOutputController } from "../providers/runOutputController";
import { RunOutputProvider } from "../providers/RunOutputContext";
import { useRunOutput } from "../providers/runOutput";
import { RunView } from "../views/RunView";
import { RunsView } from "../views/RunsView";
import { TriageView } from "../views/TriageView";
import { TargetContext, type TargetContextValue } from "../providers/target";
import { PipelineContext } from "../providers/pipeline";
import { InfoPanel } from "../components/observation/InfoPanel";
import { ToastContext } from "../components/ui/toastContext";
import { RunStatusContext } from "../providers/runStatus";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const listeners = new Map<string, Array<(event: { payload: unknown }) => void>>();
const invoke = vi.fn();
const toast = vi.fn();
const changeProject = vi.fn();
const addRecent = vi.fn();
let delayRegistrations = false;
const registrations: Array<{ resolve: (dispose: () => void) => void; dispose: () => void }> = [];

vi.mock("../lib", async () => {
  const actual = await vi.importActual<typeof import("../lib")>("../lib");
  return {
    ...actual,
    getTransport: () => ({
      invoke,
      listen: async (event: string, callback: (payload: { payload: unknown }) => void) => {
        const current = listeners.get(event) ?? [];
        listeners.set(event, [...current, callback]);
        const dispose = () => {
          listeners.set(
            event,
            (listeners.get(event) ?? []).filter((entry) => entry !== callback),
          );
        };
        if (delayRegistrations)
          return new Promise<() => void>((resolve) => registrations.push({ resolve, dispose }));
        return dispose;
      },
    }),
  };
});

function Probe() {
  const output = useRunOutput();
  return (
    <div>
      <output data-run>{JSON.stringify({ ...output, target: output.lastTarget })}</output>
      <button
        type="button"
        onClick={() =>
          void output
            .runFuzzer({ project: "/project", target: "parse", engine: "libfuzzer", duration: 1 })
            .catch(() => {
              /* Probe observes surfaced errors. */
            })
        }
      >
        start
      </button>
      <button type="button" onClick={() => void output.cancelRun()}>
        stop
      </button>
      <button type="button" onClick={() => void output.loadOlderHealthEvents?.()}>
        older
      </button>
      <button
        type="button"
        onClick={() =>
          void output.runSyzkaller({}).catch(() => {
            /* Probe observes surfaced errors. */
          })
        }
      >
        syzkaller
      </button>
    </div>
  );
}

function TerminalCompletionProbe() {
  const output = useRunOutput();
  const [result, setResult] = useState<number | null>(null);
  return (
    <>
      <button
        onClick={() =>
          void output
            .runFuzzer({ project: "/project", target: "parse", engine: "libfuzzer", duration: 1 })
            .then(setResult)
        }
      >
        launch-and-observe
      </button>
      <output data-terminal-result>{result}</output>
    </>
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

function payload() {
  return JSON.parse(container.querySelector("[data-run]")?.textContent ?? "{}");
}

async function emit(event: string, value: unknown) {
  await act(async () => {
    for (const callback of listeners.get(event) ?? []) callback({ payload: value });
    await Promise.resolve();
  });
}

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  window.localStorage.clear();
  listeners.clear();
  delayRegistrations = false;
  registrations.length = 0;
  invoke.mockReset();
  toast.mockReset();
  changeProject.mockReset();
  addRecent.mockReset();
  invoke.mockResolvedValue([]);
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  window.localStorage.clear();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

async function mount(project = "/project", children: React.ReactNode = null) {
  await act(async () => {
    root.render(
      <StrictMode>
        <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: (key) => key }}>
          <ProjectContext.Provider
            value={{
              activeProject: project,
              recentProjects: ["/project"],
              setActiveProject: changeProject,
              addRecent,
              removeRecent: () => undefined,
              deleteProjectData: async () => undefined,
            }}
          >
            <RunStatusContext.Provider
              value={{ activeEngine: null, setActiveEngine: () => undefined }}
            >
              <ToastContext.Provider value={{ toast }}>
                <RunOutputProvider>
                  <Probe />
                  <section data-presentation>{children}</section>
                </RunOutputProvider>
              </ToastContext.Provider>
            </RunStatusContext.Provider>
          </ProjectContext.Provider>
        </I18nContext.Provider>
      </StrictMode>,
    );
    await Promise.resolve();
  });
}

describe("RunOutputProvider", () => {
  it("migrates v1 output without inventing a run UUID and preserves old throughput only as peak", async () => {
    window.localStorage.setItem(
      "hf_run_summary_v1",
      JSON.stringify({
        "/project": {
          stats: { execs: 80, edges: 4, crashes: 3 },
          summary: { execs: 70, edges: 4, crashes: 1 },
          lastTarget: "parse",
          lastEngine: "libfuzzer",
        },
      }),
    );

    await mount();

    const persisted = JSON.parse(window.localStorage.getItem("hf_run_summary_v2") ?? "null");
    expect(persisted).toMatchObject({
      schema_version: 2,
      runs: {},
      latest_run_by_project: {},
      legacy_by_project: {
        "/project": {
          stats: {
            currentExecs: null,
            meanExecs: null,
            peakExecs: 80,
            edges: 4,
            rawCrashSignals: null,
          },
        },
      },
    });
    expect(window.localStorage.getItem("hf_run_summary_v1")).toBeNull();
  });

  it("routes interleaved run progress by durable owner and displays service telemetry without a browser average", async () => {
    const ownerA = deferred<Record<string, unknown>>();
    const ownerB = deferred<Record<string, unknown>>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_owner")
        return args?.runId === "00000000-0000-4000-8000-000000000001"
          ? ownerA.promise
          : ownerB.promise;
      if (command === "campaign_telemetry")
        return Promise.resolve({
          schema_version: 2,
          throughput_sample_count: 2,
          throughput_sample_sum: 125,
          run_id: args?.runId,
          observed_at: "2026-09-07T00:00:00Z",
          current_execs: args?.runId === "00000000-0000-4000-8000-000000000001" ? 25 : 7,
          mean_execs: args?.runId === "00000000-0000-4000-8000-000000000001" ? 62.5 : 7,
          peak_execs: args?.runId === "00000000-0000-4000-8000-000000000001" ? 100 : 7,
          edges: 9,
        });
      if (command === "campaign_health_events")
        return Promise.resolve({ events: [], next_cursor: null });
      return Promise.resolve([]);
    });
    await mount();

    await emit("run:progress", {
      run_id: "00000000-0000-4000-8000-000000000001",
      type: "LogLine",
      data: "A only",
    });
    await emit("run:progress", {
      run_id: "00000000-0000-4000-8000-000000000002",
      type: "LogLine",
      data: "B only",
    });
    await emit("run:progress", {
      run_id: "00000000-0000-4000-8000-000000000001",
      type: "ExecsPerSec",
      data: 100,
    });
    await emit("run:progress", {
      run_id: "00000000-0000-4000-8000-000000000001",
      type: "ExecsPerSec",
      data: 25,
    });
    await act(async () =>
      ownerB.resolve({
        run_id: "00000000-0000-4000-8000-000000000002",
        project_root: "/other",
        target: "other",
        engine: "afl++",
        kind: "Campaign",
        status: "Running",
        started_at: "2026-09-07T02:00:00Z",
      }),
    );
    await act(async () =>
      ownerA.resolve({
        run_id: "00000000-0000-4000-8000-000000000001",
        project_root: "/project",
        target: "parse",
        engine: "libfuzzer",
        kind: "Campaign",
        status: "Running",
        started_at: "2026-09-07T01:00:00Z",
      }),
    );
    await act(async () => Promise.resolve());

    expect(changeProject).not.toHaveBeenCalled();
    expect(addRecent).not.toHaveBeenCalled();
    expect(payload()).toMatchObject({
      log: ["  A only"],
      stats: { currentExecs: 25, meanExecs: 62.5, peakExecs: 100, edges: 9 },
      target: "parse",
    });
  });

  it("recovers a healthy scheduled run from retained history without any pushed progress or log", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return Promise.resolve([{ id: "00000000-0000-4000-8000-000000000003" }]);
      if (command === "run_owner")
        return Promise.resolve({
          run_id: "00000000-0000-4000-8000-000000000003",
          project_root: "/project",
          target: "nightly",
          engine: "afl++",
          kind: "Campaign",
          status: "Running",
          started_at: "2026-09-07T03:00:00Z",
        });
      if (command === "campaign_telemetry")
        return Promise.resolve({
          schema_version: 2,
          throughput_sample_count: 2,
          throughput_sample_sum: 18,
          run_id: args?.runId,
          observed_at: "2026-09-07T03:01:00Z",
          current_execs: 12,
          mean_execs: 9,
          peak_execs: 14,
          edges: 5,
        });
      if (command === "campaign_health_events")
        return Promise.resolve({ events: [], next_cursor: null });
      return Promise.resolve([]);
    });
    await mount();
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(payload()).toMatchObject({
      target: "nightly",
      stats: { currentExecs: 12, meanExecs: 9, peakExecs: 14, edges: 5 },
    });
    expect(invoke.mock.calls.some(([command]) => command === "run_history")).toBe(true);
  });

  it("keeps foreground control pending through admission and cancels the exact admitted UUID before terminal completion", async () => {
    const terminal = deferred<{
      run_id: string;
      edges: number;
      crashes: number;
      execs: number;
      exit_code: null;
      termination: "completed";
    }>();
    let admitted: ((runId: string) => void) | undefined;
    invoke.mockImplementation(
      (
        command: string,
        _args?: Record<string, unknown>,
        options?: { onRunStarted?: (runId: string) => void },
      ) => {
        if (command === "run_fuzzer") {
          admitted = options?.onRunStarted;
          return terminal.promise;
        }
        if (command === "cancel_run") return Promise.resolve(1);
        if (command === "run_history") return Promise.resolve([]);
        return Promise.resolve({ events: [], next_cursor: null });
      },
    );
    await mount();
    await act(async () => {
      container.querySelector<HTMLButtonElement>("button")?.click();
    });
    expect(payload()).toMatchObject({ running: true });
    await act(async () => admitted?.("00000000-0000-4000-8000-000000000001"));
    await act(async () => container.querySelectorAll<HTMLButtonElement>("button")[1]?.click());
    expect(invoke).toHaveBeenCalledWith("cancel_run", {
      runId: "00000000-0000-4000-8000-000000000001",
    });
    await act(async () =>
      terminal.resolve({
        run_id: "00000000-0000-4000-8000-000000000001",
        edges: 1,
        crashes: 0,
        execs: 1,
        exit_code: null,
        termination: "completed",
      }),
    );
    expect(payload()).toMatchObject({ running: false, cancelling: false });
  });

  it("keeps the durably newer same-project owner when owner responses settle in one batch", async () => {
    const older = deferred<Record<string, unknown>>();
    const newer = deferred<Record<string, unknown>>();
    const olderId = "00000000-0000-4000-8000-000000000010";
    const newerId = "00000000-0000-4000-8000-000000000011";
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_owner") return args?.runId === olderId ? older.promise : newer.promise;
      if (command === "run_history") return Promise.resolve([]);
      return Promise.resolve({ events: [], next_cursor: null });
    });
    await mount();
    await emit("run:progress", { run_id: olderId, type: "LogLine", data: "old" });
    await emit("run:progress", { run_id: newerId, type: "LogLine", data: "new" });
    await act(async () => {
      newer.resolve({
        run_id: newerId,
        project_root: "/project",
        target: "new-target",
        engine: "afl++",
        kind: "Campaign",
        status: "Running",
        started_at: "2026-09-07T02:00:00Z",
      });
      older.resolve({
        run_id: olderId,
        project_root: "/project",
        target: "old-target",
        engine: "afl++",
        kind: "Campaign",
        status: "Running",
        started_at: "2026-09-07T01:00:00Z",
      });
      await Promise.resolve();
    });
    expect(payload()).toMatchObject({ target: "new-target", log: ["  new"] });
  });
});

const A = "00000000-0000-4000-8000-000000000001";
const B = "00000000-0000-4000-8000-000000000002";
function owner(id = A, project = "/project", status = "Running") {
  return {
    run_id: id,
    project_root: project,
    target: "parse",
    engine: "libfuzzer",
    kind: "Campaign",
    status,
    started_at: "2026-09-07T01:00:00Z",
  };
}
function telemetry(id = A, extra: Record<string, unknown> = {}) {
  return {
    schema_version: 2,
    run_id: id,
    observed_at: "2026-09-07T01:01:00Z",
    current_execs: 25,
    mean_execs: 62.5,
    peak_execs: 100,
    throughput_sample_count: 2,
    throughput_sample_sum: 125,
    edges: null,
    ...extra,
  };
}
function health(id: string, severity = "error", runId = A) {
  return {
    schema_version: 2,
    id,
    run_id: runId,
    condition: "run_failed",
    severity,
    detail: id,
    observed_at: "2026-09-07T01:00:00Z",
    dedup_key: id,
    evidence: {
      schema_version: 2,
      run_id: runId,
      condition: "run_failed",
      observed_at: "2026-09-07T01:00:00Z",
    },
  };
}
function standard(command: string, args?: Record<string, unknown>): Promise<unknown> {
  if (command === "run_closeout_report")
    return Promise.reject(new Error("closeout unavailable in fixture"));
  if (command === "run_owner") return Promise.resolve(owner(String(args?.runId)));
  if (command === "campaign_telemetry") return Promise.resolve(telemetry(String(args?.runId)));
  if (command === "campaign_health_events")
    return Promise.resolve({ events: [], next_cursor: null });
  return Promise.resolve([]);
}
async function click(text: string) {
  await act(async () =>
    Array.from(container.querySelectorAll("button"))
      .find((button) => button.textContent === text)
      ?.click(),
  );
}

describe("frontend correction acceptance", () => {
  it("recovers valid v1 after malformed v2 and preserves absent terminal evidence as Unknown", async () => {
    localStorage.setItem("hf_run_summary_v2", "{");
    localStorage.setItem(
      "hf_run_summary_v1",
      JSON.stringify({ "/project": { stats: { execs: 80 }, lastTarget: "legacy" } }),
    );
    await mount();
    expect(payload()).toMatchObject({
      target: "legacy",
      summary: null,
      stats: { currentExecs: null, meanExecs: null, peakExecs: 80 },
    });
  });
  it("retains recoverable v1 when writing v2 fails", async () => {
    const legacy = JSON.stringify({ "/project": { stats: { execs: 80 } } });
    localStorage.setItem("hf_run_summary_v1", legacy);
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota");
    });
    await mount();
    expect(localStorage.getItem("hf_run_summary_v1")).toBe(legacy);
    expect(payload().stats.peakExecs).toBe(80);
  });
  it("rejects malformed v2 members and cross-project owner indexes", async () => {
    localStorage.setItem(
      "hf_run_summary_v2",
      JSON.stringify({
        schema_version: 2,
        runs: { [A]: { owner: owner(A, "/other"), stats: null } },
        latest_run_by_project: { "/project": A },
        legacy_by_project: {},
      }),
    );
    await mount();
    expect(payload()).toMatchObject({ target: "", stats: { currentExecs: null } });
  });
  it("surfaces request pending and rejection and ignores null-ID broadcasts", async () => {
    let reject!: (error: Error) => void;
    invoke.mockImplementation((command: string) =>
      command === "run_fuzzer"
        ? new Promise((_resolve, no) => {
            reject = no;
          })
        : Promise.resolve([]),
    );
    await mount();
    await click("start");
    expect(payload().requestState).toBe("pending");
    await emit("run:progress", { run_id: null, type: "LogLine", data: "foreign staging" });
    expect(payload().log).toEqual([]);
    await act(async () => reject(new Error("service rejected launch")));
    expect(payload()).toMatchObject({ running: false, requestError: "service rejected launch" });
    invoke.mockRejectedValue(new Error("run_syzkaller is unavailable in web mode"));
    await click("syzkaller");
    expect(payload().requestError).toContain("run_syzkaller is unavailable in web mode");
  });
  it("preserves pre-admission Stop and selected foreign output through foreground completion", async () => {
    const done = deferred<unknown>();
    let admitted!: (id: string) => void;
    invoke.mockImplementation(
      (
        command: string,
        args?: Record<string, unknown>,
        opts?: { onRunStarted?: (id: string) => void },
      ) => {
        if (command === "run_fuzzer") {
          admitted = opts!.onRunStarted!;
          return done.promise;
        }
        if (command === "run_owner")
          return Promise.resolve(
            owner(String(args?.runId), args?.runId === A ? "/project" : "/other"),
          );
        return standard(command, args);
      },
    );
    await mount();
    await click("start");
    await click("stop");
    await mount("/other");
    await emit("run:progress", { run_id: B, type: "LogLine", data: "foreign scheduled" });
    await act(async () => admitted(A));
    expect(invoke).toHaveBeenCalledWith("cancel_run", { runId: A });
    expect(payload().log).toEqual(["  foreign scheduled"]);
    await act(async () => done.resolve({ run_id: A, edges: 1, crashes: 1, execs: 25 }));
    expect(payload().running).toBe(false);
    expect(payload().log).toEqual(["  foreign scheduled"]);
  });
  it("rejects mismatched owners and unsafe metrics without inventing coverage or crash counts", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner" ? Promise.resolve(owner(B)) : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "unowned" });
    expect(payload().target).toBe("");
    invoke.mockImplementation(standard);
    await emit("run:progress", { run_id: A, type: "CrashesFound", data: 3 });
    await emit("run:progress", { run_id: A, type: "CrashesFound", data: Number.MAX_SAFE_INTEGER });
    await emit("run:progress", { run_id: A, type: "LogLine", data: "crash repeated" });
    expect(payload().stats).toMatchObject({ rawCrashSignals: 3, edges: null });
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_telemetry"
        ? Promise.resolve(
            telemetry(A, {
              observed_at: "2026-09-07T01:02:00Z",
              current_execs: Number.MAX_SAFE_INTEGER + 1,
              mean_execs: "12",
              peak_execs: -3,
              edges: Infinity,
            }),
          )
        : standard(command, args),
    );
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 10 });
    expect(payload().stats).toMatchObject({
      currentExecs: null,
      meanExecs: null,
      peakExecs: null,
      edges: null,
    });
  });
  it("coalesces telemetry callbacks and rejects an older follow-up snapshot", async () => {
    const first = deferred<unknown>();
    const second = deferred<unknown>();
    let reads = 0;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_telemetry"
        ? ++reads === 1
          ? first.promise
          : second.promise
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 100 });
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 25 });
    await act(async () => first.resolve(telemetry()));
    expect(payload().stats).toMatchObject({ currentExecs: 25, meanExecs: 62.5, peakExecs: 100 });
    expect(reads).toBe(2);
    await act(async () =>
      second.resolve(
        telemetry(A, { observed_at: "2026-09-07T01:00:00Z", current_execs: 100, mean_execs: 100 }),
      ),
    );
    expect(payload().stats.meanExecs).toBe(62.5);
  });
  it("rediscovers no-push scheduled work on reconnect and polls native owner until terminal", async () => {
    vi.useFakeTimers();
    let connected = false;
    let status = "Running";
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return Promise.resolve(connected ? [{ id: A, edges: 9, crashes: 1, execs: 25 }] : []);
      if (command === "run_owner") return Promise.resolve(owner(A, "/project", status));
      return standard(command, args);
    });
    await mount();
    connected = true;
    await emit("stream:connected", {});
    expect(payload().target).toBe("parse");
    for (let i = 0; i < 5; i++) {
      await act(async () => vi.advanceTimersByTimeAsync(1000));
      await emit("run:progress", { run_id: B, type: "LogLine", data: "noise" });
    }
    expect(
      invoke.mock.calls.filter(([command, args]) => command === "run_owner" && args.runId === A)
        .length,
    ).toBeGreaterThan(1);
    status = "Done";
    await act(async () => vi.advanceTimersByTimeAsync(5000));
    expect(payload().selectedRun?.status).toBe("Done");
    const count = invoke.mock.calls.length;
    await act(async () => vi.advanceTimersByTimeAsync(15000));
    expect(invoke.mock.calls.length).toBe(count);
    expect(invoke.mock.calls.some(([command]) => command === "run_status")).toBe(false);
  });
  it("silently merges retained pages with once-only live errors and explicit pagination", async () => {
    const initial = deferred<unknown>();
    const older = deferred<unknown>();
    const H1 = "00000000-0000-4000-8000-000000000101";
    const H2 = "00000000-0000-4000-8000-000000000102";
    const H3 = "00000000-0000-4000-8000-000000000103";
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_health_events"
        ? args?.cursor
          ? older.promise
          : initial.promise
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "start" });
    await emit("campaign:health", { owner: owner(), event: health(H2) });
    await emit("campaign:health", { owner: owner(), event: health(H2) });
    await emit("campaign:health", { owner: owner(), event: health(H3, "warning") });
    expect(toast).toHaveBeenCalledTimes(1);
    await act(async () => initial.resolve({ events: [health(H1), health(H2)], next_cursor: H1 }));
    expect(payload().healthEvents).toHaveLength(3);
    expect(payload().healthState).toMatchObject({ loading: false, hasOlder: true, error: null });
    await click("older");
    await click("older");
    expect(
      invoke.mock.calls.filter(
        ([command, args]) => command === "campaign_health_events" && args.cursor === H1,
      ),
    ).toHaveLength(1);
    expect(payload().healthState.loading).toBe(true);
    await act(async () =>
      older.resolve({
        events: [health("00000000-0000-4000-8000-000000000100")],
        next_cursor: null,
      }),
    );
    expect(payload().healthState.hasOlder).toBe(false);
    expect(payload().healthEvents).toHaveLength(4);
    expect(toast).toHaveBeenCalledTimes(1);
  });
});

describe("retention and asynchronous cleanup", () => {
  it("bounds unresolved owner admission without losing foreground cancellation", async () => {
    const pending = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner" ? pending.promise : standard(command, args),
    );
    await mount();
    for (let i = 0; i < 90; i++)
      await emit("run:progress", {
        run_id: `00000000-0000-4000-8000-${String(i + 1000).padStart(12, "0")}`,
        type: "LogLine",
        data: "unresolved",
      });
    expect(
      invoke.mock.calls.filter(([command]) => command === "run_owner").length,
    ).toBeLessThanOrEqual(8);
    const saved = JSON.parse(localStorage.getItem("hf_run_summary_v2")!);
    expect(Object.keys(saved.runs).length).toBeLessThanOrEqual(64);
  });
  it("ignores a delayed Running owner after terminal push and stops polling on project switch", async () => {
    vi.useFakeTimers();
    const old = deferred<unknown>();
    let reads = 0;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return Promise.resolve(args?.project === "/project" ? [{ id: A }] : []);
      if (command === "run_owner") return ++reads === 1 ? Promise.resolve(owner()) : old.promise;
      return standard(command, args);
    });
    await mount();
    await act(async () => vi.advanceTimersByTimeAsync(5000));
    await emit("run:status", { run_id: A, status: "Done" });
    await act(async () => old.resolve(owner()));
    expect(payload().selectedRun?.status).toBe("Done");
    const count = invoke.mock.calls.length;
    await act(async () => vi.advanceTimersByTimeAsync(10000));
    expect(invoke.mock.calls.length).toBe(count);
    await mount("/other");
    expect(payload().target).toBe("");
  });
  it("exposes health unavailability without losing owned output", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_health_events"
        ? Promise.reject(new Error("campaign-health unavailable"))
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "still usable" });
    expect(payload()).toMatchObject({
      target: "parse",
      log: ["  still usable"],
      healthState: { loading: false, error: "campaign-health unavailable" },
    });
  });
});

describe("actual presentation acceptance", () => {
  it("renders scheduled and recovered terminal rate and distinct crash labels in RunView", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return Promise.resolve([{ id: A, edges: 9, crashes: 1, execs: 25 }]);
      if (command === "run_owner") return Promise.resolve(owner(A, "/project", "Done"));
      return standard(command, args);
    });
    await mount("/project", <RunView embedded />);
    await emit("run:progress", { run_id: A, type: "CrashesFound", data: 3 });
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.currentExecs25",
    );
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.meanExecs62.5",
    );
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.execsPeak100",
    );
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.rawCrashSignals3",
    );
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.retainedCrashes1",
    );
    expect(container.querySelector("[data-presentation]")?.textContent).toContain("Done");
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain(
      "run.execsPerSec",
    );
  });
  it("renders local pending and named launch errors in RunView", async () => {
    let reject!: (error: Error) => void;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_syzkaller"
        ? new Promise((_yes, no) => {
            reject = no;
          })
        : standard(command, args),
    );
    await mount("/project", <RunView embedded />);
    await click("syzkaller");
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.requestPending",
    );
    await act(async () => reject(new Error("run_syzkaller is unavailable in web mode")));
    expect(container.querySelector("[data-run-request-error]")?.textContent).toContain(
      "run_syzkaller is unavailable in web mode",
    );
  });
  it("keeps history available when morning health is unavailable and navigates exact overlapping category IDs", async () => {
    let healthAvailable = false;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return Promise.resolve([
          {
            id: A,
            ...owner(),
            engine: "history-engine",
            crashes: 1,
            edges: null,
            execs: null,
            duration_secs: 1,
          },
        ]);
      if (command === "morning_health_summary")
        return healthAvailable
          ? Promise.resolve({
              schema_version: 2,
              project_root: "/project",
              failed: [A],
              stalled: [A],
              interrupted: [],
              unprocessed: [],
            })
          : Promise.reject(new Error("campaign-health unavailable"));
      return standard(command, args);
    });
    await mount("/project", <RunsView />);
    expect(container.querySelector("[data-presentation]")?.textContent).toContain("history-engine");
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "runs.healthUnavailable",
    );
    healthAvailable = true;
    await mount("/other", <RunsView />);
    await mount("/project", <RunsView />);
    const links = container.querySelectorAll<HTMLAnchorElement>(`a[href="#run-${A}"]`);
    expect(links).toHaveLength(2);
    await act(async () => links[0].click());
    expect(container.querySelector(`#run-${A}`)?.textContent).toContain("runs.noCoverageSamples");
    expect(
      invoke.mock.calls.some(([command]) =>
        ["run_fuzzer", "run_syzkaller", "cancel_run"].includes(command),
      ),
    ).toBe(false);
  });
  it("discards deferred previous-project history and morning results during the pending replacement", async () => {
    const historyA = deferred<unknown>();
    const morningA = deferred<unknown>();
    const historyB = deferred<unknown>();
    const morningB = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return args?.project === "/project" ? historyA.promise : historyB.promise;
      if (command === "morning_health_summary")
        return args?.project === "/project" ? morningA.promise : morningB.promise;
      return standard(command, args);
    });
    await mount("/project", <RunsView />);
    await mount("/other", <RunsView />);
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "runs.healthLoading",
    );
    await act(async () => {
      historyB.resolve([
        { id: B, ...owner(B, "/other"), engine: "B-history", crashes: 0, edges: null, execs: null },
      ]);
      morningB.resolve({
        schema_version: 2,
        project_root: "/other",
        failed: [],
        stalled: [],
        interrupted: [],
        unprocessed: [],
      });
    });
    await act(async () => {
      historyA.resolve([
        { id: A, ...owner(), engine: "A-history", crashes: 0, edges: null, execs: null },
      ]);
      morningA.resolve({
        schema_version: 2,
        project_root: "/project",
        failed: [A],
        stalled: [],
        interrupted: [],
        unprocessed: [],
      });
    });
    expect(container.querySelector("[data-presentation]")?.textContent).toContain("B-history");
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain("A-history");
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "runs.healthMeasuredZero",
    );
  });
  it("keeps Triage and InfoPanel target and engine project-correct after batched owners and project switches", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_owner")
        return Promise.resolve({
          ...owner(String(args?.runId), args?.runId === A ? "/project" : "/other"),
          target: args?.runId === A ? "A-target" : "B-target",
        });
      if (command === "artifact_summary")
        return Promise.resolve({ harness_built: true, corpus_count: 2, crash_count: 1 });
      return standard(command, args);
    });
    await mount(
      "/project",
      <>
        <TriageView embedded />
        <InfoPanel />
      </>,
    );
    await emit("run:progress", { run_id: A, type: "LogLine", data: "A" });
    await emit("run:progress", { run_id: B, type: "LogLine", data: "B" });
    expect(container.querySelector("[data-presentation]")?.textContent).toContain("A-target");
    await mount(
      "/other",
      <>
        <TriageView embedded />
        <InfoPanel />
      </>,
    );
    expect(container.querySelector("[data-presentation]")?.textContent).toContain("B-target");
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain("A-target");
    expect(invoke).toHaveBeenCalledWith("artifact_summary", {
      project: "/other",
      target: "B-target",
    });
    await click("triage.scanForCrashes");
    expect(invoke).toHaveBeenCalledWith("triage", { project: "/other", target: "B-target" });
  });
});

describe("completion race and retention evidence", () => {
  it("guards delayed StrictMode registrations and disposes each listener without duplicate deltas or toasts", async () => {
    vi.useFakeTimers();
    delayRegistrations = true;
    invoke.mockImplementation(standard);
    await mount();
    expect(listeners.get("run:progress")).toHaveLength(2);
    await emit("run:progress", { run_id: A, type: "CrashesFound", data: 3 });
    const H = "00000000-0000-4000-8000-000000000101";
    await emit("campaign:health", { owner: owner(), event: health(H) });
    expect(payload().stats.rawCrashSignals).toBe(3);
    expect(toast).toHaveBeenCalledTimes(1);
    await act(async () => {
      for (const registration of registrations) registration.resolve(registration.dispose);
    });
    expect(listeners.get("run:progress")).toHaveLength(1);
    await act(async () => root.unmount());
    expect([...listeners.values()].every((callbacks) => callbacks.length === 0)).toBe(true);
    const calls = invoke.mock.calls.length;
    await act(async () => vi.advanceTimersByTimeAsync(15000));
    expect(invoke.mock.calls.length).toBe(calls);
    root = createRoot(container);
  });
  it("bounds resolved runs, legacy indexes and logs while keeping selected recovery and foreground identity", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner"
        ? Promise.resolve(
            owner(
              String(args?.runId),
              args?.runId === A ? "/project" : String(args?.runId),
              "Done",
            ),
          )
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "selected" });
    for (let i = 0; i < 80; i++)
      await emit("run:progress", {
        run_id: `00000000-0000-4000-8000-${String(i + 1000).padStart(12, "0")}`,
        type: "LogLine",
        data: "other",
      });
    const saved = JSON.parse(localStorage.getItem("hf_run_summary_v2")!);
    expect(Object.keys(saved.runs)).toHaveLength(64);
    expect(Object.keys(saved.latest_run_by_project).length).toBeLessThanOrEqual(64);
    expect(saved.latest_run_by_project["/project"]).toBe(A);
    for (let i = 0; i < 620; i++)
      await emit("run:progress", { run_id: A, type: "LogLine", data: String(i) });
    expect(payload().log).toHaveLength(600);
    expect(payload().log.at(-1)).toBe("  619");
    expect(JSON.parse(localStorage.getItem("hf_run_summary_v2")!).runs[A].log).toBeUndefined();
  });
  it("caps health memory but keeps every explicitly requested older page reachable and silent", async () => {
    let page = 0;
    const makeId = (n: number) => `00000000-0000-4000-8000-${String(n + 2000).padStart(12, "0")}`;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "campaign_health_events") {
        const index = page++;
        return Promise.resolve({
          events: Array.from({ length: 100 }, (_, i) => health(makeId(index * 100 + i))),
          next_cursor: index < 2 ? makeId(index * 100 + 99) : null,
        });
      }
      return standard(command, args);
    });
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "ready" });
    await click("older");
    await click("older");
    expect(payload().healthEvents).toHaveLength(200);
    expect(payload().healthEvents.some((event: { id: string }) => event.id === makeId(299))).toBe(
      true,
    );
    expect(payload().healthState.hasOlder).toBe(false);
    expect(toast).not.toHaveBeenCalled();
  });
  it("keeps page cursor progression through deferred reconnect and lag without foreign event ingestion", async () => {
    const page2 = deferred<unknown>();
    const H1 = "00000000-0000-4000-8000-000000000101";
    const H2 = "00000000-0000-4000-8000-000000000102";
    let initialReads = 0;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "campaign_health_events") {
        if (args?.cursor) return page2.promise;
        initialReads++;
        return Promise.resolve({ events: [health(H1)], next_cursor: H1 });
      }
      return standard(command, args);
    });
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "ready" });
    await click("older");
    await emit("stream:connected", {});
    await emit("stream:lagged", {});
    await emit("campaign:health", { owner: owner(), event: health(H2, "error", B) });
    await act(async () => page2.resolve({ events: [health(H2)], next_cursor: null }));
    expect(initialReads).toBe(2);
    expect(payload().healthState).toMatchObject({ hasOlder: false, loading: false });
    expect(payload().healthEvents).toHaveLength(2);
    expect(toast).not.toHaveBeenCalled();
  });
  it("ignores stale health pages after project switch and renders loading, error and exhausted controls", async () => {
    const page = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_owner")
        return Promise.resolve(
          owner(String(args?.runId), args?.runId === A ? "/project" : "/other"),
        );
      if (command === "campaign_health_events")
        return args?.runId === A ? page.promise : Promise.reject(new Error("health disabled"));
      return standard(command, args);
    });
    await mount("/project", <RunView embedded />);
    await emit("run:progress", { run_id: A, type: "LogLine", data: "ready" });
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.healthLoading",
    );
    await mount("/other", <RunView embedded />);
    await emit("run:progress", { run_id: B, type: "LogLine", data: "other" });
    await act(async () =>
      page.resolve({ events: [health("00000000-0000-4000-8000-000000000101")], next_cursor: null }),
    );
    expect(payload().healthEvents).toEqual([]);
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "run.healthUnavailable",
    );
    expect(
      [...container.querySelectorAll("button")].some(
        (button) => button.textContent === "run.loadOlderHealth",
      ),
    ).toBe(false);
  });
  it("never persists log-only updates and preserves auto-revert terminal evidence", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_fuzzer")
        return Promise.resolve({
          run_id: A,
          edges: 9,
          crashes: 1,
          execs: 25,
          auto_revert: {
            reverted_to_run: B,
            from_rev: "before",
            to_rev: "after",
            previous_edges: 10,
            regressed_edges: 9,
            drop_pct: 10,
            reverted: true,
          },
        });
      return standard(command, args);
    });
    await mount();
    await click("start");
    expect(payload().summary.autoRevert).toMatchObject({ reverted: true, to_rev: "after" });
    const set = vi.spyOn(Storage.prototype, "setItem");
    await emit("run:progress", { run_id: A, type: "LogLine", data: "new line" });
    expect(set).not.toHaveBeenCalled();
  });
});

describe("remaining foreign-data and unavailable-state cases", () => {
  it("renders Unknown rates with a recovered retained artifact count when other history metrics are absent", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return Promise.resolve([{ id: A, edges: null, crashes: 1, execs: null }]);
      if (command === "run_owner") return Promise.resolve(owner(A, "/project", "Done"));
      if (command === "campaign_telemetry") return Promise.reject(new Error("unavailable"));
      return standard(command, args);
    });
    await mount("/project", <RunView embedded />);
    const text = container.querySelector("[data-presentation]")?.textContent;
    expect(text).toContain("run.currentExecsrun.unknown");
    expect(text).toContain("run.meanExecsrun.unknown");
    expect(text).toContain("run.retainedCrashes1");
    expect(text).toContain("run.rawCrashSignalsrun.unknown");
  });
  it("rejects changed immutable ownership from a live health delivery", async () => {
    invoke.mockImplementation(standard);
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "owned" });
    await emit("campaign:health", {
      owner: owner(A, "/foreign"),
      event: health("00000000-0000-4000-8000-000000000101"),
    });
    expect(payload().target).toBe("parse");
    expect(payload().healthEvents).toEqual([]);
    expect(toast).not.toHaveBeenCalled();
  });
  it("preserves independently available morning categories when history fails", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history") return Promise.reject(new Error("history unavailable"));
      if (command === "morning_health_summary")
        return Promise.resolve({
          schema_version: 2,
          project_root: "/project",
          failed: [A],
          stalled: [],
          interrupted: [],
          unprocessed: [],
        });
      return standard(command, args);
    });
    await mount("/project", <RunsView />);
    expect(container.querySelector("[data-presentation]")?.textContent).toContain("runs.loadError");
    expect(container.querySelector(`a[href="#run-${A}"]`)).not.toBeNull();
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain(
      "runs.healthUnavailable",
    );
  });
  it("rejects invalid terminal metrics and bounds individual log lines", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_fuzzer"
        ? Promise.resolve({
            run_id: A,
            edges: "1",
            crashes: Number.MAX_SAFE_INTEGER + 1,
            execs: NaN,
          })
        : standard(command, args),
    );
    await mount();
    await click("start");
    expect(payload().summary).toBeNull();
    expect(payload().requestError).toBe("Invalid run result metrics");
    await emit("run:progress", { run_id: A, type: "LogLine", data: "x".repeat(20000) });
    expect(payload().log[0].length).toBeLessThanOrEqual(4096);
  });
  it("keeps a retained error silent if it is redelivered live after initial hydration", async () => {
    const H = "00000000-0000-4000-8000-000000000101";
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_health_events"
        ? Promise.resolve({ events: [health(H)], next_cursor: null })
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "ready" });
    await emit("campaign:health", { owner: owner(), event: health(H) });
    expect(toast).not.toHaveBeenCalled();
    expect(payload().healthEvents).toHaveLength(1);
  });
});

describe("foreground and final asynchronous ordering", () => {
  it("ignores a previous cancellation failure after a new invocation starts", async () => {
    const first = deferred<unknown>();
    const second = deferred<unknown>();
    let rejectCancel!: (error: Error) => void;
    let started = 0;
    invoke.mockImplementation(
      (
        command: string,
        args?: Record<string, unknown>,
        opts?: { onRunStarted?: (id: string) => void },
      ) => {
        if (command === "run_fuzzer") {
          opts?.onRunStarted?.(++started === 1 ? A : B);
          return started === 1 ? first.promise : second.promise;
        }
        if (command === "cancel_run")
          return new Promise((_yes, no) => {
            rejectCancel = no;
          });
        return standard(command, args);
      },
    );
    await mount();
    await click("start");
    await click("stop");
    await act(async () => first.resolve({ run_id: A, edges: 1, crashes: 0, execs: 25 }));
    await click("start");
    await act(async () => rejectCancel(new Error("old cancel failed")));
    expect(payload()).toMatchObject({ running: true, requestError: null, cancelling: false });
    await act(async () => second.resolve({ run_id: B, edges: 1, crashes: 0, execs: 25 }));
  });
  it("does not let delayed terminal history erase a newer foreground terminal result", async () => {
    const history = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history") return history.promise;
      if (command === "run_owner") return Promise.resolve(owner(A, "/project", "Done"));
      if (command === "run_fuzzer")
        return Promise.resolve({ run_id: A, edges: 9, crashes: 1, execs: 25 });
      return standard(command, args);
    });
    await mount();
    await click("start");
    await act(async () =>
      history.resolve([{ id: A, edges: null, crashes: 0, execs: null, status: "Running" }]),
    );
    expect(payload().summary).toMatchObject({ edges: 9, crashes: 1, execs: 25 });
  });
  it("coalesces a trailing telemetry snapshot into the final service mean without adding callbacks", async () => {
    const first = deferred<unknown>();
    let reads = 0;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_telemetry"
        ? ++reads === 1
          ? first.promise
          : Promise.resolve(telemetry())
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 100 });
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 25 });
    await act(async () =>
      first.resolve(
        telemetry(A, {
          observed_at: "2026-09-07T01:00:00Z",
          current_execs: 100,
          mean_execs: 100,
          throughput_sample_count: 1,
          throughput_sample_sum: 100,
        }),
      ),
    );
    expect(reads).toBe(2);
    expect(payload().stats).toMatchObject({ currentExecs: 25, meanExecs: 62.5, peakExecs: 100 });
  });
  it("keeps pagination retry available after an older-page failure", async () => {
    const H = "00000000-0000-4000-8000-000000000101";
    let failed = false;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "campaign_health_events") {
        if (!args?.cursor) return Promise.resolve({ events: [health(H)], next_cursor: H });
        if (!failed) {
          failed = true;
          return Promise.reject(new Error("page unavailable"));
        }
        return Promise.resolve({ events: [], next_cursor: null });
      }
      return standard(command, args);
    });
    await mount("/project", <RunView embedded />);
    await emit("run:progress", { run_id: A, type: "LogLine", data: "ready" });
    await click("run.loadOlderHealth");
    expect(payload().healthState).toMatchObject({
      hasOlder: true,
      loading: false,
      error: "page unavailable",
    });
    await click("run.loadOlderHealth");
    expect(payload().healthState).toMatchObject({ hasOlder: false, loading: false, error: null });
  });
});

describe("durable selection and legacy semantics", () => {
  it("leaves v1 callback-count crash evidence Unknown as raw deltas while retaining artifact totals", async () => {
    localStorage.setItem(
      "hf_run_summary_v1",
      JSON.stringify({
        "/project": {
          stats: { execs: 80, crashes: 3 },
          summary: { edges: 4, crashes: 1, execs: 70 },
        },
      }),
    );
    await mount();
    expect(payload().stats.rawCrashSignals).toBeNull();
    expect(payload().summary.crashes).toBe(1);
  });
  it("uses the deterministic larger UUID for equal-start owners resolved in one batch", async () => {
    const first = deferred<unknown>();
    const second = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner"
        ? args?.runId === A
          ? first.promise
          : second.promise
        : standard(command, args),
    );
    await mount("/project", <RunView embedded />);
    await emit("run:progress", { run_id: A, type: "LogLine", data: "lower UUID" });
    await emit("run:progress", { run_id: B, type: "LogLine", data: "higher UUID" });
    await act(async () => {
      second.resolve({ ...owner(B), target: "higher" });
      first.resolve({ ...owner(A), target: "lower" });
    });
    expect(payload().selectedRun.run_id).toBe(B);
    expect(container.querySelector("[data-presentation]")?.textContent).toContain("higher UUID");
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain("lower UUID");
  });
});

describe("bounded refresh admission", () => {
  it("bounds outstanding health reads across rapid selected-project changes", async () => {
    const page = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_owner")
        return Promise.resolve(owner(String(args?.runId), String(args?.runId), "Done"));
      if (command === "campaign_health_events") return page.promise;
      return standard(command, args);
    });
    await mount();
    for (let i = 0; i < 20; i++) {
      const id = `00000000-0000-4000-8000-${String(i + 1000).padStart(12, "0")}`;
      await emit("run:progress", { run_id: id, type: "LogLine", data: "known" });
      await mount(id);
    }
    expect(
      invoke.mock.calls.filter(([command]) => command === "campaign_health_events").length,
    ).toBeLessThanOrEqual(8);
    expect(payload().healthState.loading).toBe(false);
  });
  it("caps combined legacy recovery even when both persisted versions contain different projects", async () => {
    const old = Object.fromEntries(
      Array.from({ length: 80 }, (_, n) => [`old-${n}`, { stats: { execs: 80 } }]),
    );
    const prior = Object.fromEntries(
      Array.from({ length: 80 }, (_, n) => [`prior-${n}`, { stats: { peakExecs: 70 } }]),
    );
    localStorage.setItem("hf_run_summary_v1", JSON.stringify(old));
    localStorage.setItem(
      "hf_run_summary_v2",
      JSON.stringify({
        schema_version: 2,
        runs: {},
        latest_run_by_project: {},
        legacy_by_project: prior,
      }),
    );
    await mount();
    expect(
      Object.keys(JSON.parse(localStorage.getItem("hf_run_summary_v2")!).legacy_by_project).length,
    ).toBeLessThanOrEqual(64);
  });
});

describe("selected presentation versus foreground control", () => {
  it("keeps scheduled metrics owned by the displayed run after project and launch-engine changes", async () => {
    const terminal = deferred<unknown>();
    invoke.mockImplementation(
      (
        command: string,
        args?: Record<string, unknown>,
        options?: { onRunStarted?: (id: string) => void },
      ) => {
        if (command === "run_fuzzer") {
          options?.onRunStarted?.(A);
          return terminal.promise;
        }
        if (command === "run_owner")
          return Promise.resolve(
            owner(
              String(args?.runId),
              args?.runId === A ? "/project" : "/other",
              args?.runId === A ? "Running" : "Done",
            ),
          );
        return standard(command, args);
      },
    );
    const target: TargetContextValue = {
      target: "new-launch",
      engine: "syzkaller",
      lang: "c",
      compiled: false,
      selectionRepair: null,
      storageError: null,
      setTarget: () => {},
      setEngine: () => {},
      setLang: () => {},
      setCompiled: () => {},
      canResetTargetSelections: false,
      resetTargetSelections: () => {},
      retryStorage: () => {},
    };
    const views = (
      <TargetContext.Provider value={target}>
        <RunView embedded />
        <PipelineContext.Provider
          value={{
            completed: [],
            isDone: () => false,
            isSkipped: () => false,
            currentStage: "triage",
            coreStages: [
              {
                id: "triage",
                label: "Selected triage",
                done: false,
                skipped: false,
                current: true,
                doneSteps: 0,
                totalSteps: 1,
              },
            ],
            markDone: () => {},
            markSkipped: () => {},
            reset: () => {},
          }}
        >
          <InfoPanel />
        </PipelineContext.Provider>
      </TargetContext.Provider>
    );
    await mount("/project", views);
    await click("start");
    await emit("run:progress", { run_id: B, type: "CrashesFound", data: 3 });
    await mount("/other", views);
    const text = container.querySelector("[data-presentation]")?.textContent;
    expect(text).toContain("run.meanExecs62.5");
    expect(text).toContain("run.rawCrashSignals3");
    expect(container.querySelector("[data-presentation] .text-accent")?.textContent).toBe(
      "Selected triage",
    );
    expect(text).not.toContain("run.coverage");
    await click("stop");
    expect(invoke).toHaveBeenCalledWith("cancel_run", { runId: A });
    await act(async () => terminal.resolve({ run_id: A, edges: 1, crashes: 0, execs: 25 }));
  });
  it("clears loaded previous-project history immediately while replacement history and morning are pending", async () => {
    const later = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "run_history")
        return args?.project === "/project"
          ? Promise.resolve([
              {
                id: A,
                ...owner(),
                engine: "old-project-row",
                edges: null,
                execs: null,
                crashes: 0,
              },
            ])
          : later.promise;
      if (command === "morning_health_summary")
        return args?.project === "/project"
          ? Promise.resolve({
              schema_version: 2,
              project_root: "/project",
              failed: [A],
              stalled: [],
              interrupted: [],
              unprocessed: [],
            })
          : later.promise;
      return standard(command, args);
    });
    await mount("/project", <RunsView />);
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "old-project-row",
    );
    await mount("/other", <RunsView />);
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain(
      "old-project-row",
    );
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "runs.healthLoading",
    );
  });
  it("stops active scheduled polling on project switch and ignores deferred dirty telemetry after unmount", async () => {
    vi.useFakeTimers();
    const response = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_telemetry" ? response.promise : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 100 });
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 25 });
    await mount("/other");
    const reads = invoke.mock.calls.length;
    await act(async () => vi.advanceTimersByTimeAsync(15000));
    expect(invoke.mock.calls.length).toBe(reads);
    await act(async () => root.unmount());
    await act(async () => response.resolve(telemetry()));
    expect(invoke.mock.calls.length).toBe(reads);
    root = createRoot(container);
  });
});

describe("reconnect retry and foreign page limits", () => {
  it("retries unavailable ownership on reconnect without changing project selection or recents", async () => {
    let available = false;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner"
        ? available
          ? Promise.resolve(owner())
          : Promise.reject(new Error("owner unavailable"))
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "recoverable" });
    expect(payload().target).toBe("");
    available = true;
    await emit("stream:connected", {});
    expect(payload().target).toBe("parse");
    expect(payload().log).toEqual(["  recoverable"]);
    expect(changeProject).not.toHaveBeenCalled();
    expect(addRecent).not.toHaveBeenCalled();
  });
  it("bounds foreign health detail text and rejects invalid health schema without notifications", async () => {
    invoke.mockImplementation(standard);
    await mount();
    const H = "00000000-0000-4000-8000-000000000101";
    await emit("campaign:health", { owner: owner(), event: { ...health(H), schema_version: 1 } });
    expect(payload().healthEvents).toEqual([]);
    expect(toast).not.toHaveBeenCalled();
    await emit("campaign:health", {
      owner: owner(),
      event: { ...health(H), detail: "x".repeat(20000) },
    });
    expect(payload().healthEvents[0].detail.length).toBeLessThanOrEqual(4096);
  });
  it("renders malformed morning run IDs as unavailable without hiding basic history", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "morning_health_summary"
        ? Promise.resolve({
            schema_version: 2,
            project_root: "/project",
            failed: ["invalid-run-id"],
            stalled: [],
            interrupted: [],
            unprocessed: [],
          })
        : standard(command, args),
    );
    await mount("/project", <RunsView />);
    expect(container.querySelector("[data-presentation]")?.textContent).toContain(
      "runs.healthUnavailable",
    );
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain(
      "invalid-run-id",
    );
  });
});

describe("precise service timestamps", () => {
  it("orders owners by sub-millisecond start time before applying the UUID tie break", async () => {
    const first = deferred<unknown>();
    const second = deferred<unknown>();
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner"
        ? args?.runId === A
          ? first.promise
          : second.promise
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "newer lower UUID" });
    await emit("run:progress", { run_id: B, type: "LogLine", data: "older higher UUID" });
    await act(async () => {
      first.resolve({ ...owner(A), started_at: "2026-09-07T01:00:00.000200+00:00" });
      second.resolve({ ...owner(B), started_at: "2026-09-07T01:00:00.000100+00:00" });
    });
    expect(payload().selectedRun.run_id).toBe(A);
    expect(payload().log).toEqual(["  newer lower UUID"]);
  });
  it("rejects an older telemetry snapshot within the same millisecond", async () => {
    let observed = "2026-09-07T01:00:00.000200+00:00";
    let current = 25;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_telemetry"
        ? Promise.resolve(telemetry(A, { observed_at: observed, current_execs: current }))
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 25 });
    observed = "2026-09-07T01:00:00.000100+00:00";
    current = 100;
    await emit("run:progress", { run_id: A, type: "ExecsPerSec", data: 100 });
    expect(payload().stats.currentExecs).toBe(25);
  });
  it("rejects non-RFC3339 and impossible calendar timestamps from ownership ingress", async () => {
    let started = "2026-02-31T00:00:00Z";
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner"
        ? Promise.resolve({ ...owner(), started_at: started })
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "unowned" });
    expect(payload().selectedRun).toBeNull();
    started = "September 7, 2026";
    await emit("run:progress", { run_id: A, type: "LogLine", data: "still unowned" });
    expect(payload().selectedRun).toBeNull();
  });
});

describe("legacy persistence recovery", () => {
  it("keeps v1 recoverable when reading it fails even if writing v2 succeeds", async () => {
    const legacy = JSON.stringify({ "/project": { stats: { execs: 80 } } });
    localStorage.setItem("hf_run_summary_v1", legacy);
    const get = Storage.prototype.getItem;
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(function (
      this: Storage,
      key: string,
    ) {
      if (key === "hf_run_summary_v1") throw new Error("temporary read failure");
      return get.call(this, key);
    });
    await mount();
    expect(get.call(localStorage, "hf_run_summary_v1")).toBe(legacy);
  });
  it("does not reinterpret callback counts in already-migrated legacy v2 records", async () => {
    localStorage.setItem(
      "hf_run_summary_v2",
      JSON.stringify({
        schema_version: 2,
        runs: {},
        latest_run_by_project: {},
        legacy_by_project: {
          "/project": {
            stats: { peakExecs: 80, rawCrashSignals: 3 },
            summary: { edges: 4, crashes: 1, execs: 70 },
          },
        },
      }),
    );
    await mount();
    expect(payload().stats.rawCrashSignals).toBeNull();
    expect(payload().summary.crashes).toBe(1);
  });
  it("rejects a cross-project persisted latest index even when stored stats and owner are valid", async () => {
    localStorage.setItem(
      "hf_run_summary_v2",
      JSON.stringify({
        schema_version: 2,
        runs: {
          [A]: {
            owner: owner(A, "/other"),
            stats: {
              currentExecs: 25,
              meanExecs: 62.5,
              peakExecs: 100,
              edges: 1,
              rawCrashSignals: 3,
            },
            lastTarget: "foreign",
          },
        },
        latest_run_by_project: { "/project": A },
        legacy_by_project: {},
      }),
    );
    await mount();
    expect(payload().selectedRun).toBeNull();
    expect(payload().target).toBe("");
    expect(payload().stats.currentExecs).toBeNull();
  });
});

describe("retained page recovery after exhaustion", () => {
  it("makes newly retained pages reachable after an exhausted history reconnects", async () => {
    const H1 = "00000000-0000-4000-8000-000000000101";
    const H2 = "00000000-0000-4000-8000-000000000102";
    let reconnected = false;
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "campaign_health_events")
        return Promise.resolve(
          reconnected
            ? { events: [health(H2)], next_cursor: H2 }
            : { events: [health(H1)], next_cursor: null },
        );
      return standard(command, args);
    });
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "ready" });
    expect(payload().healthState.hasOlder).toBe(false);
    reconnected = true;
    await emit("stream:connected", {});
    expect(payload().healthState.hasOlder).toBe(true);
    await click("older");
    expect(invoke).toHaveBeenCalledWith("campaign_health_events", {
      runId: A,
      cursor: H2,
      limit: 100,
    });
    expect(toast).not.toHaveBeenCalled();
  });
  it("restarts retained pagination when reselecting a run whose earlier display pages were trimmed", async () => {
    const H = "00000000-0000-4000-8000-000000000101";
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "campaign_health_events"
        ? Promise.resolve({ events: [health(H)], next_cursor: args?.cursor ? null : H })
        : standard(command, args),
    );
    await mount();
    await emit("run:progress", { run_id: A, type: "LogLine", data: "ready" });
    await click("older");
    expect(payload().healthState.hasOlder).toBe(false);
    await mount("/other");
    await mount("/project");
    expect(payload().healthState.hasOlder).toBe(true);
  });
});

it("renders an Unknown morning summary separately from measured-zero categories", async () => {
  invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
    command === "morning_health_summary" ? Promise.resolve(null) : standard(command, args),
  );
  await mount("/project", <RunsView />);
  expect(container.querySelector("[data-presentation]")?.textContent).toContain(
    "runs.healthUnknown",
  );
  expect(container.querySelector("[data-presentation]")?.textContent).not.toContain(
    "runs.healthMeasuredZero",
  );
});

describe("review round 2 ownership and terminal cleanup", () => {
  it("returns foreground controls to idle before admission ownership resolves and isolates later invocations", async () => {
    const ownerFirst = deferred<unknown>();
    const ownerSecond = deferred<unknown>();
    const first = deferred<unknown>();
    const second = deferred<unknown>();
    let launches = 0;
    invoke.mockImplementation(
      (
        command: string,
        args?: Record<string, unknown>,
        options?: { onRunStarted?: (id: string) => void },
      ) => {
        if (command === "run_owner")
          return args?.runId === A ? ownerFirst.promise : ownerSecond.promise;
        if (command === "run_fuzzer") {
          options?.onRunStarted?.(++launches === 1 ? A : B);
          return launches === 1 ? first.promise : second.promise;
        }
        return standard(command, args);
      },
    );
    await mount(
      "/project",
      <>
        <RunView embedded />
        <TerminalCompletionProbe />
      </>,
    );
    await click("launch-and-observe");
    expect(payload().running).toBe(true);
    await act(async () => first.resolve({ run_id: A, edges: 9, crashes: 1, execs: 25 }));
    expect(payload().running).toBe(false);
    expect(container.querySelector("[data-terminal-result]")?.textContent).toBe("1");
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain(
      "common.stop",
    );
    await click("start");
    await act(async () => ownerFirst.resolve(owner()));
    expect(payload()).toMatchObject({ running: true, summary: { edges: 9, crashes: 1 } });
    await act(async () => second.resolve({ run_id: B, edges: 10, crashes: 2, execs: 30 }));
    expect(payload().running).toBe(false);
    await act(async () => ownerSecond.resolve(owner(B)));
    expect(payload()).toMatchObject({ running: false, summary: { crashes: 2 } });
  });

  it("does not revive a stale persisted target when its durable owner has no target", async () => {
    const pending = deferred<unknown>();
    localStorage.setItem(
      "hf_run_summary_v2",
      JSON.stringify({
        schema_version: 2,
        runs: {
          [A]: {
            owner: { ...owner(), target: null },
            stats: {},
            lastTarget: "stale-owned-target",
            lastEngine: "wrong-engine",
          },
        },
        latest_run_by_project: { "/project": A },
        legacy_by_project: {
          "/legacy": { stats: {}, lastTarget: "real-legacy-target", lastEngine: "afl++" },
        },
      }),
    );
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) =>
      command === "run_owner" ? pending.promise : standard(command, args),
    );
    await mount(
      "/project",
      <>
        <TriageView embedded />
        <InfoPanel />
      </>,
    );
    expect(payload().target).toBe("");
    expect(container.querySelector("[data-presentation]")?.textContent).not.toContain(
      "stale-owned-target",
    );
    expect(
      invoke.mock.calls.some(
        ([command, args]) => command === "artifact_summary" && args.target === "stale-owned-target",
      ),
    ).toBe(false);
    const triage = [...container.querySelectorAll<HTMLButtonElement>("button")].find(
      (button) => button.textContent === "triage.scanForCrashes",
    );
    expect(triage?.disabled).toBe(true);
    await mount("/legacy");
    expect(payload().target).toBe("real-legacy-target");
  });
});

it("keeps per-run bookkeeping bounded when protected cache records refuse new foreground UUIDs", async () => {
  const controllers = new Set<RunOutputController>();
  const configure = RunOutputController.prototype.configure;
  vi.spyOn(RunOutputController.prototype, "configure").mockImplementation(function (
    this: RunOutputController,
    ...args: Parameters<typeof configure>
  ) {
    controllers.add(this);
    configure.apply(this, args);
  });
  let launchId = "";
  let terminal = deferred<unknown>();
  invoke.mockImplementation(
    (
      command: string,
      args?: Record<string, unknown>,
      options?: { onRunStarted?: (id: string) => void },
    ) => {
      if (command === "run_fuzzer") {
        options?.onRunStarted?.(launchId);
        return terminal.promise;
      }
      return standard(command, args);
    },
  );
  await mount();
  for (let i = 0; i < 64; i++)
    await emit("run:progress", {
      run_id: `00000000-0000-4000-8000-${String(i + 1000).padStart(12, "0")}`,
      type: "LogLine",
      data: "protected active run",
    });
  for (let i = 0; i < 70; i++) {
    launchId = `00000000-0000-4000-8000-${String(i + 5000).padStart(12, "0")}`;
    terminal = deferred<unknown>();
    await click("start");
    await click("stop");
    expect(invoke).toHaveBeenCalledWith("cancel_run", { runId: launchId });
    await act(async () => terminal.resolve({ run_id: launchId, edges: 1, crashes: 0, execs: 25 }));
    expect(payload()).toMatchObject({ running: false, cancelling: false });
  }
  const controller = [...controllers].at(-1)!;
  expect(Object.keys(controller.state.runs)).toHaveLength(64);
  // Inspect retained map sizes after real mounted operations, without exposing test APIs.
  const retainedMaps = Object.values(controller).filter(
    (value): value is Map<unknown, unknown> => value instanceof Map,
  );
  expect(retainedMaps.every((map) => map.size <= 64)).toBe(true);
});

it("keeps terminal foreground controls idle when late owner hydration fails", async () => {
  let rejectOwner!: (error: Error) => void;
  const pending = new Promise((_resolve, reject) => {
    rejectOwner = reject;
  });
  invoke.mockImplementation(
    (
      command: string,
      args?: Record<string, unknown>,
      options?: { onRunStarted?: (id: string) => void },
    ) => {
      if (command === "run_owner") return pending;
      if (command === "run_fuzzer") {
        options?.onRunStarted?.(A);
        return Promise.resolve({ run_id: A, edges: 9, crashes: 1, execs: 25 });
      }
      return standard(command, args);
    },
  );
  await mount();
  await click("start");
  expect(payload()).toMatchObject({ running: false, requestError: null });
  await act(async () => rejectOwner(new Error("late ownership unavailable")));
  expect(payload()).toMatchObject({ running: false, requestError: null });
});
