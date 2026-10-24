// @vitest-environment jsdom

import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ConfirmContext, type ConfirmFn } from "../providers/confirm";
import { ProjectContext } from "../providers/project";
import { MiniTrend, RunsView } from "../views/RunsView";
import type { RunHistoryItem } from "../types";
import type * as LibModule from "../lib";
import { ToastProvider } from "../components/ui/Toast";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  desktop: false,
  listeners: new Set<() => void>(),
}));

vi.mock("../lib", async (importOriginal) => ({
  ...(await importOriginal<typeof LibModule>()),
  getTransport: () => ({ invoke: mocks.invoke }),
  isTauriEnvironment: () => mocks.desktop,
  emitDataChanged: () => {
    for (const listener of mocks.listeners) listener();
  },
  onDataChanged: (listener: () => void) => {
    mocks.listeners.add(listener);
    return () => {
      mocks.listeners.delete(listener);
    };
  },
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function run(id: string, target: string): RunHistoryItem {
  return {
    id,
    target_id: null,
    requested_duration_secs: null,
    kind: "Campaign",
    project_root: "/project",
    target,
    target_selector: null,
    comparison_key: null,
    engine: "libfuzzer",
    status: "Done",
    started_at: "2026-09-08T01:00:00Z",
    ended_at: "2026-09-08T02:00:00Z",
    duration_secs: 60,
    crashes: 0,
    edges: null,
    execs: null,
    harness_rev: null,
    binary_rev: null,
    evidence_dir: null,
  };
}

const runs = [
  run("10000000-0000-4000-8000-000000000001", "parse"),
  run("10000000-0000-4000-8000-000000000002", "lex"),
];

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function translate(key: string, params?: Record<string, string | number>) {
  // The real dictionary names the scoped project inside this confirmation;
  // render the param so the assertion observes actual dialog text.
  if (key === "runs.clearProjectMsg" && params) return `Delete runs recorded for ${params.project}?`;
  if (!params) return key;
  return Object.entries(params).reduce(
    (text, [name, value]) => text.replace(`{${name}}`, String(value)),
    key,
  );
}

function Providers({ confirm, project }: { confirm?: ConfirmFn; project: string }) {
  return (
    <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: translate }}>
      <ProjectContext.Provider value={{
        activeProject: project,
        recentProjects: project ? [project] : [],
        setActiveProject: () => undefined,
        addRecent: () => undefined,
        removeRecent: () => undefined,
        deleteProjectData: async () => undefined,
      }}>
        <ConfirmContext.Provider value={confirm ?? (async () => true)}>
          <RunsView />
        </ConfirmContext.Provider>
      </ProjectContext.Provider>
    </I18nContext.Provider>
  );
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
  });
}

function clearAllButton(container: HTMLElement): HTMLButtonElement | undefined {
  return [...container.querySelectorAll("button")].find((candidate) =>
    candidate.textContent?.includes("common.clearAll"),
  );
}

describe("RunsView destructive interactions", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    vi.useFakeTimers();
    mocks.invoke.mockReset();
    mocks.desktop = false;
    mocks.listeners.clear();
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.useRealTimers();
  });

  it("keeps the destructive clear unavailable in a browser session without a project scope", async () => {
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "run_history") return Promise.resolve(runs);
      if (command === "clear_all_runs") throw new Error("must not be invoked without a scope");
      if (command === "read_config") return Promise.resolve("");
      if (command === "config_toml_to_value") return Promise.resolve({});
      return Promise.resolve(null);
    });

    await act(async () => root.render(<StrictMode><Providers project="" /></StrictMode>));
    await flush();

    // The browser route clears exactly one project, so with no project
    // selected the action has no valid scope and must not be offered even
    // though the unscoped history list shows runs.
    expect(container.textContent).toContain("parse");
    expect(clearAllButton(container)).toBeUndefined();
  });

  it.each([false, true])("clears only the selected project's history (desktop=%s)", async (desktop) => {
    mocks.desktop = desktop;
    const clearing = deferred<unknown>();
    const foreign = { ...run("10000000-0000-4000-8000-000000000003", "foreign_target"), project_root: "/other" };
    let history = [...runs, foreign];
    const confirm = vi.fn<ConfirmFn>(async () => true);
    mocks.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "run_history") return history.filter((item) => !args?.project || item.project_root === args.project);
      if (command === "clear_all_runs") {
        await clearing.promise;
        history = history.filter((item) => args?.project && item.project_root !== args.project);
        return;
      }
      if (command === "read_config") return "";
      if (command === "config_toml_to_value") return {};
      return null;
    });

    await act(async () => root.render(<StrictMode><Providers confirm={confirm} project="/project" /></StrictMode>));
    await flush();
    await act(async () => clearAllButton(container)?.click());
    expect(confirm).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining("/project") }));
    await act(async () => clearing.resolve(undefined));
    await flush();
    expect(container.textContent).not.toContain("parse");
    expect(container.textContent).not.toContain("lex");

    await act(async () => root.render(<StrictMode><Providers project="/other" /></StrictMode>));
    await flush();
    expect(container.textContent).toContain("foreign_target");
  });

  it("clears every project only from an unselected desktop history view", async () => {
    mocks.desktop = true;
    let history = [
      ...runs,
      { ...run("10000000-0000-4000-8000-000000000003", "foreign_target"), project_root: "/other" },
    ];
    mocks.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "run_history") return history.filter((item) => !args?.project || item.project_root === args.project);
      if (command === "clear_all_runs") {
        history = history.filter((item) => args?.project && item.project_root !== args.project);
        return;
      }
      if (command === "read_config") return "";
      if (command === "config_toml_to_value") return {};
      return null;
    });
    await act(async () => root.render(<StrictMode><Providers project="" /></StrictMode>));
    await flush();
    expect(container.textContent).toContain("parse");
    expect(container.textContent).toContain("foreign_target");
    await act(async () => clearAllButton(container)?.click());
    await flush();
    expect(container.textContent).not.toContain("parse");
    expect(container.textContent).not.toContain("foreign_target");
    await act(async () => root.render(<StrictMode><Providers project="/other" /></StrictMode>));
    await flush();
    expect(container.textContent).not.toContain("foreign_target");
  });

  it("does not queue duplicate destructive deletes or clears", async () => {
    const confirm = vi.fn<ConfirmFn>(async () => true);
    const removal = deferred<unknown>();
    let deletes = 0;
    let history = runs;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "run_history") return Promise.resolve(history);
      if (command === "delete_run") {
        deletes += 1;
        // A queued second delete of the same run reaches the service after the
        // run is already gone and reports a failure for work that succeeded.
        return deletes === 1
          ? removal.promise.then(() => { history = history.filter((item) => item.id !== runs[0].id); })
          : Promise.reject(new Error("run not found"));
      }
      if (command === "clear_all_runs") {
        history = [];
        return Promise.resolve(undefined);
      }
      if (command === "read_config") return Promise.resolve("");
      if (command === "config_toml_to_value") return Promise.resolve({});
      if (command === "morning_health_summary") return Promise.resolve(null);
      if (command === "project_auto_revert_override") return Promise.resolve(null);
      return Promise.resolve(null);
    });

    await act(async () => root.render(<StrictMode><Providers confirm={confirm} project="/project" /></StrictMode>));
    await flush();

    const remove = container.querySelector<HTMLButtonElement>('[aria-label="runs.deleteRunAria"]');
    if (!remove) throw new Error(`delete button not found: ${container.textContent}`);
    await act(async () => {
      remove.click();
      remove.click();
    });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(deletes).toBe(1);

    await act(async () => removal.resolve(undefined));
    await flush();
    expect(container.textContent).toContain("lex");

    const clear = clearAllButton(container);
    expect(clear).toBeDefined();
    await act(async () => {
      clear?.click();
      clear?.click();
    });
    expect(mocks.invoke.mock.calls.filter(([command]) => command === "clear_all_runs")).toHaveLength(1);
    await flush();
    expect(container.textContent).not.toContain("lex");
  });

  it("reports a harness-source read failure instead of silently closing the comparison", async () => {
    const history = runs.map((item, index) => ({
      ...item,
      comparison_key: "same-target-and-engine",
      harness_rev: index === 0 ? "b".repeat(64) : "a".repeat(64),
      edges: index === 0 ? 20 : 10,
    }));
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "run_history") return history;
      if (command === "run_harness_source") throw new Error("retained source unavailable");
      if (command === "read_config") return "";
      if (command === "config_toml_to_value") return {};
      return null;
    });
    await act(async () => root.render(
      <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: translate }}>
        <ToastProvider><Providers project="/project" /></ToastProvider>
      </I18nContext.Provider>,
    ));
    await flush();
    const marker = container.querySelector<HTMLButtonElement>('[aria-label="runs.viewHarnessDiff"]');
    expect(marker).not.toBeNull();
    await act(async () => marker!.click());
    await flush();
    expect(document.querySelector('[role="alert"]')?.textContent).toContain("retained source unavailable");
  });
});

describe("MiniTrend absent measurements", () => {
  let host: HTMLDivElement;
  let miniRoot: Root;

  beforeEach(() => {
    host = document.createElement("div");
    document.body.append(host);
    miniRoot = createRoot(host);
  });

  afterEach(async () => {
    await act(async () => miniRoot.unmount());
    host.remove();
  });

  function barCount(): number {
    const bars = host.querySelector<HTMLDivElement>('div[style*="height: 40px"]');
    return bars ? bars.children.length : -1;
  }

  function item(id: string, edges: number | null): RunHistoryItem {
    return { ...run(id, "parse"), edges, started_at: `2026-09-08T0${id.slice(-1)}:00:00Z` };
  }

  it("skips null points instead of drawing them as a zero collapse", async () => {
    const runs = [
      item("10000000-0000-4000-8000-000000000001", 100),
      item("10000000-0000-4000-8000-000000000002", null),
      item("10000000-0000-4000-8000-000000000003", 50),
    ];
    await act(async () => miniRoot.render(
      <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: (key) => key }}>
        <MiniTrend
          title="runs.coverageEdges"
          icon={<span>icon</span>}
          runs={runs}
          value={(r) => r.edges}
          color="var(--success)"
          marks={[false, true, false]}
          onMark={() => undefined}
        />
      </I18nContext.Provider>,
    ));

    // The unmeasured middle run is absent from the chart, the latest value is
    // its own (no zero bar), and the change mark that belonged to the skipped
    // run does not shift onto a measured one.
    expect(barCount()).toBe(2);
    expect(host.querySelector("span.text-lg")?.textContent).toBe("50");
    expect(host.textContent).not.toContain("▲");
  });

  it("keeps a change marker on its own run when other points are absent", async () => {
    const runs = [
      item("10000000-0000-4000-8000-000000000001", 100),
      item("10000000-0000-4000-8000-000000000002", null),
      item("10000000-0000-4000-8000-000000000003", 50),
    ];
    await act(async () => miniRoot.render(
      <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: (key) => key }}>
        <MiniTrend
          title="runs.coverageEdges"
          icon={<span>icon</span>}
          runs={runs}
          value={(r) => r.edges}
          color="var(--success)"
          marks={[true, false, false]}
          onMark={() => undefined}
        />
      </I18nContext.Provider>,
    ));

    expect(barCount()).toBe(2);
    expect([...host.querySelectorAll("button")].filter((button) => button.textContent === "▲"))
      .toHaveLength(1);
  });
});
