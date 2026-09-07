// @vitest-environment jsdom

import { StrictMode, act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ConfirmContext, type ConfirmFn } from "../providers/confirm";
import { ProjectContext } from "../providers/project";
import { TargetContext } from "../providers/target";
import { CorpusView } from "../views/CorpusView";
import type { CorpusEntry } from "../types";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  pickFolder: vi.fn(),
  desktop: false,
  listener: undefined as undefined | (() => void),
}));

vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: mocks.invoke }),
  isTauriEnvironment: () => mocks.desktop,
  pickFolder: mocks.pickFolder,
  onDataChanged: (listener: () => void) => {
    mocks.listener = listener;
    return () => {
      if (mocks.listener === listener) mocks.listener = undefined;
    };
  },
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const PROJECT = "/workspace/project";

function entry(name: string, size: number): CorpusEntry {
  return {
    path: `/workspace/corpus/${name}`,
    sha256: name.padEnd(64, "0"),
    size,
    source: "Manual",
    coverage_hash: null,
  };
}

type CapabilitySet = Record<"seed_survival" | "coverage_prune" | "minimize", {
  available: boolean;
  reason_code: string | null;
  reason: string | null;
}>;

const ready: CapabilitySet = {
  seed_survival: { available: true, reason_code: null, reason: null },
  coverage_prune: { available: true, reason_code: null, reason: null },
  minimize: { available: true, reason_code: null, reason: null },
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function Providers({ confirm = async () => true, initialTarget = "target-a" }: { confirm?: ConfirmFn; initialTarget?: string }) {
  const [target, setTarget] = useState(initialTarget);
  const translate = (key: string, params?: Record<string, string | number>) => {
    if (key === "corpus.importResult" && params) {
      return `Imported ${params.added} inputs / ${params.bytes} bytes; ${params.duplicates} duplicates and ${params.skipped} skipped.`;
    }
    if (key === "corpus.inventory" && params) {
      return `Inventory ${params.inputs}/${params.bytes}`;
    }
    if (!params) return key;
    return Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, String(value)),
      key,
    );
  };
  return (
    <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: translate }}>
      <ProjectContext.Provider value={{
        activeProject: PROJECT,
        recentProjects: [PROJECT],
        setActiveProject: () => undefined,
        addRecent: () => undefined,
        removeRecent: () => undefined,
        deleteProjectData: async () => undefined,
      }}>
        <TargetContext.Provider value={{
          target,
          engine: "afl++",
          lang: "c",
          compiled: true,
          selectionRepair: null,
          storageError: null,
          setTarget,
          setEngine: () => undefined,
          setLang: () => undefined,
          setCompiled: () => undefined,
          canResetTargetSelections: false,
          resetTargetSelections: () => undefined,
          retryStorage: () => undefined,
        }}>
          <ConfirmContext.Provider value={confirm}>
            <button type="button" onClick={() => setTarget("target-b")}>switch target</button>
            <CorpusView />
          </ConfirmContext.Provider>
        </TargetContext.Provider>
      </ProjectContext.Provider>
    </I18nContext.Provider>
  );
}

async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

function button(container: HTMLElement, text: string): HTMLButtonElement {
  const match = [...container.querySelectorAll("button")].find((candidate) =>
    candidate.textContent?.includes(text),
  );
  if (!(match instanceof HTMLButtonElement)) throw new Error(`button not found: ${text}`);
  return match;
}

describe("CorpusView interactions", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;

  beforeEach(() => {
    mocks.invoke.mockReset();
    mocks.pickFolder.mockReset();
    mocks.desktop = false;
    mocks.listener = undefined;
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
  });

  it("ignores an older target list and keeps rows after a same-scope refresh fails", async () => {
    const oldList = deferred<CorpusEntry[]>();
    let targetBReads = 0;
    mocks.invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list" && args?.target === "target-a") return oldList.promise;
      if (command === "corpus_list" && args?.target === "target-b") {
        targetBReads += 1;
        return targetBReads === 1
          ? Promise.resolve([entry("target-b-row", 7)])
          : Promise.reject(new Error("refresh failed"));
      }
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });

    await act(async () => root.render(<StrictMode><Providers /></StrictMode>));
    await act(async () => button(container, "switch target").click());
    await flush();
    await act(async () => oldList.resolve([entry("target-a-row", 9)]));
    await flush();
    expect(container.textContent).toContain("target-b-row");
    expect(container.textContent).not.toContain("target-a-row");

    await act(async () => mocks.listener?.());
    await flush();
    expect(container.textContent).toContain("target-b-row");
    expect(container.textContent).toContain("refresh failed");
  });

  it("keeps one operation busy and ignores a mutation that finishes after target change", async () => {
    const seed = deferred<unknown>();
    mocks.invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") {
        return Promise.resolve([entry(String(args?.target), 4)]);
      }
      if (command === "corpus_seed") return seed.promise;
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });

    await act(async () => root.render(<StrictMode><Providers /></StrictMode>));
    await flush();
    await act(async () => button(container, "corpus.seed").click());
    expect(button(container, "corpus.import").disabled).toBe(true);
    expect(button(container, "corpus.pruneBytes").disabled).toBe(true);
    await act(async () => button(container, "switch target").click());
    await flush();
    await act(async () => seed.resolve({ seeded: 2 }));
    await flush();

    expect(container.textContent).toContain("target-b");
    expect(container.textContent).not.toContain("corpus.seeded");
    expect(mocks.invoke.mock.calls.filter(([command]) => command === "corpus_seed")).toHaveLength(1);
  });

  it("does not queue duplicate destructive confirms or dispatch one after scope change", async () => {
    const approval = deferred<boolean>();
    const confirm = vi.fn(() => approval.promise);
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return Promise.resolve([entry("retained", 4)]);
      if (command === "corpus_prune") return Promise.resolve({});
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });

    await act(async () => root.render(<StrictMode><Providers confirm={confirm} /></StrictMode>));
    await flush();
    const prune = button(container, "corpus.pruneBytes");
    await act(async () => {
      prune.click();
      prune.click();
    });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(prune.disabled).toBe(true);
    await act(async () => button(container, "switch target").click());
    await act(async () => approval.resolve(true));
    await flush();
    expect(mocks.invoke.mock.calls.some(([command]) => command === "corpus_prune")).toBe(false);
  });

  it("imports a desktop directory with exact accounting and renders unknown survival honestly", async () => {
    mocks.desktop = true;
    mocks.pickFolder.mockResolvedValue("/external/corpus");
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return Promise.resolve([entry("retained", 4)]);
      if (command === "corpus_import") {
        return Promise.resolve({
          inspected: 4,
          eligible: 3,
          duplicates: 1,
          skipped: 1,
          added: 2,
          added_bytes: 11,
          before: { inputs: 1, bytes: 4 },
          after: { inputs: 3, bytes: 15 },
        });
      }
      if (command === "seed_survival") {
        return Promise.resolve({
          total: 3,
          survives: 0,
          dies_at_entry: 0,
          not_measured: 3,
          survival_ratio: null,
        });
      }
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });

    await act(async () => root.render(<StrictMode><Providers /></StrictMode>));
    await flush();
    await act(async () => button(container, "corpus.chooseDirectory").click());
    await flush();
    const source = container.querySelector<HTMLInputElement>('input[name="corpus-import-source"]');
    expect(source?.value).toBe("/external/corpus");
    await act(async () => button(container, "corpus.import").click());
    await flush();
    expect(mocks.invoke).toHaveBeenCalledWith("corpus_import", {
      project: PROJECT,
      target: "target-a",
      source: "/external/corpus",
    });
    expect(container.textContent).toContain("Imported 2 inputs / 11 bytes; 1 duplicates and 1 skipped.");

    await act(async () => button(container, "corpus.measureSurvival").click());
    await flush();
    expect(container.textContent).toContain("corpus.unknown");
    expect(container.textContent).toContain("corpus.notMeasured");
    expect(container.textContent).not.toContain("0%");
  });

  it("confirms each destructive reduction and invokes only accepted operations", async () => {
    const confirm = vi.fn<ConfirmFn>()
      .mockResolvedValueOnce(false)
      .mockResolvedValue(true);
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return Promise.resolve([entry("retained", 4)]);
      if (["corpus_prune", "corpus_prune_coverage", "corpus_minimize"].includes(command)) {
        return Promise.resolve({ before: 2, after: 1, before_bytes: 8, after_bytes: 4 });
      }
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers confirm={confirm} />));
    await flush();

    await act(async () => button(container, "corpus.pruneCoverage").click());
    await flush();
    expect(mocks.invoke.mock.calls.some(([command]) => command === "corpus_prune_coverage")).toBe(false);
    for (const [label, command] of [
      ["corpus.pruneCoverage", "corpus_prune_coverage"],
      ["corpus.minimize", "corpus_minimize"],
      ["corpus.pruneBytes", "corpus_prune"],
    ]) {
      await act(async () => button(container, label).click());
      await flush();
      expect(mocks.invoke.mock.calls.some(([called]) => called === command)).toBe(true);
    }
    expect(confirm).toHaveBeenCalledTimes(4);
  });

  it("shows unavailable engine reasons and clears blocker evidence on target change", async () => {
    mocks.invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "corpus_capabilities") {
        return Promise.resolve({
          seed_survival: { available: false, reason_code: "engine_disabled", reason: "AFL++ is disabled" },
          coverage_prune: { available: false, reason_code: "engine_disabled", reason: "AFL++ is disabled" },
          minimize: { available: false, reason_code: "active_harness_engine_mismatch", reason: "active harness uses AFL++" },
        });
      }
      if (command === "corpus_list") return Promise.resolve([entry(String(args?.target), 4)]);
      if (command === "coverage_blockers") {
        return Promise.resolve({
          schema_version: 1,
          measurement: { status: "available", signature: "coverage" },
          blockers: [{ function: "old-target-only", location: null, unlocked_uncovered: 1, frontier_distance: 1, nearest_covered: "entry", path: ["entry", "old-target-only"] }],
          experiment: { kind: "grow_corpus", target_function: "old-target-only", reason_code: "near_covered_frontier" },
        });
      }
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();

    expect(button(container, "corpus.measureSurvival").disabled).toBe(true);
    expect(button(container, "corpus.minimize").disabled).toBe(true);
    expect(container.textContent).toContain("AFL++ is disabled");
    await act(async () => button(container, "coverageBlockers.explore").click());
    await flush();
    expect(container.textContent).toContain("old-target-only");
    await act(async () => button(container, "switch target").click());
    await flush();
    expect(container.textContent).not.toContain("old-target-only");
  });

  it("labels browser imports as server directories without opening a native picker", async () => {
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return Promise.resolve([]);
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();

    expect(container.textContent).toContain("corpus.importServerHelp");
    expect(container.textContent).toContain("Inventory 0/0");
    expect([...container.querySelectorAll("button")].some((candidate) => candidate.textContent?.includes("corpus.chooseDirectory"))).toBe(false);
    expect(mocks.pickFolder).not.toHaveBeenCalled();
  });

  it("prompts for a target without presenting an unavailable or empty inventory", async () => {
    await act(async () => root.render(<Providers initialTarget="" />));
    await flush();

    expect(container.textContent).toContain("corpus.noTargetSelected");
    expect(container.textContent).toContain("corpus.noTargetHint");
    expect(container.textContent).not.toContain("corpus.inventoryUnavailable");
    expect(container.textContent).not.toContain("Inventory 0/0");
    expect(mocks.invoke).not.toHaveBeenCalledWith("corpus_list", expect.anything());
  });

  it("orders manual and background inventory reads through one generation", async () => {
    const initial = deferred<CorpusEntry[]>();
    let reads = 0;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") {
        reads += 1;
        return reads === 1 ? initial.promise : Promise.resolve([entry("manual-newer", 8)]);
      }
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();
    await act(async () => button(container, "corpus.list").click());
    await flush();
    expect(container.textContent).toContain("manual-newer");
    await act(async () => initial.resolve([entry("initial-older", 4)]));
    await flush();
    expect(container.textContent).toContain("manual-newer");
    expect(container.textContent).not.toContain("initial-older");
  });

  it("retries failed readiness on List and ignores an older readiness result", async () => {
    const olderCapability = deferred<typeof ready>();
    let capabilityReads = 0;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_list") return Promise.resolve([entry("retained", 4)]);
      if (command === "corpus_capabilities") {
        capabilityReads += 1;
        if (capabilityReads === 1) return olderCapability.promise;
        return Promise.resolve(ready);
      }
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();
    await act(async () => button(container, "corpus.list").click());
    await flush();
    expect(button(container, "corpus.measureSurvival").disabled).toBe(false);
    await act(async () => olderCapability.resolve({
      seed_survival: { available: false, reason_code: "old", reason: "obsolete" },
      coverage_prune: { available: false, reason_code: "old", reason: "obsolete" },
      minimize: { available: false, reason_code: "old", reason: "obsolete" },
    }));
    await flush();
    expect(button(container, "corpus.measureSurvival").disabled).toBe(false);
    expect(container.textContent).not.toContain("obsolete");
  });

  it("retries an unavailable readiness query and enables qualified actions", async () => {
    let capabilityReads = 0;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_list") return Promise.resolve([entry("retained", 4)]);
      if (command === "corpus_capabilities") {
        capabilityReads += 1;
        return capabilityReads === 1
          ? Promise.reject(new Error("readiness unavailable"))
          : Promise.resolve(ready);
      }
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();
    expect(container.textContent).toContain("readiness unavailable");
    expect(button(container, "corpus.measureSurvival").disabled).toBe(true);

    await act(async () => button(container, "corpus.list").click());
    await flush();
    expect(container.textContent).not.toContain("readiness unavailable");
    expect(button(container, "corpus.measureSurvival").disabled).toBe(false);
  });

  it("invalidates survival evidence after corpus mutation", async () => {
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return Promise.resolve([entry("retained", 4)]);
      if (command === "seed_survival") return Promise.resolve({ total: 1, survives: 1, dies_at_entry: 0, not_measured: 0, survival_ratio: 1 });
      if (command === "corpus_seed") return Promise.resolve({ seeded: 2 });
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();
    await act(async () => button(container, "corpus.measureSurvival").click());
    await flush();
    expect(container.textContent).toContain("100%");
    await act(async () => button(container, "corpus.seed").click());
    await flush();
    expect(container.textContent).not.toContain("100%");
  });

  it("does not restore a survival result invalidated by a data change", async () => {
    const measurement = deferred<{ total: number; survives: number; dies_at_entry: number; not_measured: number; survival_ratio: number }>();
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return Promise.resolve([entry("retained", 4)]);
      if (command === "seed_survival") return measurement.promise;
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();
    await act(async () => button(container, "corpus.measureSurvival").click());
    expect(button(container, "corpus.list").disabled).toBe(true);
    await act(async () => mocks.listener?.());
    await flush();
    await act(async () => measurement.resolve({ total: 1, survives: 1, dies_at_entry: 0, not_measured: 0, survival_ratio: 1 }));
    await flush();

    expect(container.textContent).not.toContain("100%");
    expect(button(container, "corpus.list").disabled).toBe(false);
  });

  it("distinguishes pending and unavailable inventory from a measured empty corpus", async () => {
    const inventory = deferred<CorpusEntry[]>();
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return inventory.promise;
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();
    expect(container.textContent).toContain("corpus.inventoryLoading");
    expect(container.textContent).not.toContain("Inventory 0/0");
    await act(async () => inventory.reject(new Error("inventory unavailable")));
    await flush();
    expect(container.textContent).toContain("corpus.inventoryUnavailable");
    expect(container.textContent).not.toContain("Inventory 0/0");
  });

  it("surfaces folder picker failure and prevents duplicate picker requests", async () => {
    mocks.desktop = true;
    const selection = deferred<string | null>();
    mocks.pickFolder.mockReturnValue(selection.promise);
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "corpus_capabilities") return Promise.resolve(ready);
      if (command === "corpus_list") return Promise.resolve([]);
      if (command === "run_history") return Promise.resolve([]);
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<Providers />));
    await flush();
    const choose = button(container, "corpus.chooseDirectory");
    await act(async () => {
      choose.click();
      choose.click();
    });
    expect(mocks.pickFolder).toHaveBeenCalledTimes(1);
    expect(mocks.pickFolder).toHaveBeenCalledWith("corpus.chooseDirectory");
    expect(choose.disabled).toBe(true);
    await act(async () => selection.reject(new Error("picker unavailable")));
    await flush();
    expect(container.textContent).toContain("picker unavailable");
  });
});
