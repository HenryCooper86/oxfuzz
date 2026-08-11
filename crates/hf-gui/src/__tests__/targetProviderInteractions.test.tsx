// @vitest-environment jsdom

import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { TargetProvider } from "../providers/TargetContext";
import { useTarget } from "../providers/target";
import { ProjectContext, useProject } from "../providers/project";
import { PipelineContext } from "../providers/pipeline";
import { HarnessView } from "../views/HarnessView";

const transportInvoke = vi.hoisted(() => vi.fn());

vi.mock("../lib", async () => {
  const actual = await vi.importActual<typeof import("../lib")>("../lib");
  return {
    ...actual,
    getTransport: () => ({ invoke: transportInvoke }),
  };
});

const STORAGE_KEY = "hf_target_selection_v1";
const PROJECT = "/workspace/example";
const PROJECT_B = "/workspace/other";
const RETIRED_CANONICAL = ["cluster", "fuzz", "lite"].join("");
const RETIRED_SHORT_ALIAS = ["c", "f", "l"].join("");

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
  configurable: true,
  value: () => undefined,
});

function selection(engine: unknown, target = "parse_input") {
  return { target, engine, lang: "c", compiled: false };
}

function persisted(engine: unknown) {
  return JSON.stringify({ [PROJECT]: selection(engine) });
}

function AppProviders({
  children,
  initialProject = PROJECT,
  recentProjects = [PROJECT],
}: {
  children: React.ReactNode;
  initialProject?: string;
  recentProjects?: string[];
}) {
  const [activeProject, setActiveProject] = useState(initialProject);
  return (
    <I18nContext.Provider value={{
      locale: "en",
      setLocale: () => undefined,
      t: (key, params) => params?.project ? `${key}:${params.project}` : key,
    }}>
      <ProjectContext.Provider value={{
        activeProject,
        recentProjects,
        setActiveProject,
        addRecent: () => undefined,
        removeRecent: () => undefined,
        deleteProjectData: async () => undefined,
      }}>
        <PipelineContext.Provider value={{
          completed: [],
          isDone: () => false,
          currentStage: "discover",
          coreStages: [],
          isSkipped: () => false,
          markDone: () => undefined,
          markSkipped: () => undefined,
          reset: () => undefined,
        }}>
          <TargetProvider>{children}</TargetProvider>
        </PipelineContext.Provider>
      </ProjectContext.Provider>
    </I18nContext.Provider>
  );
}

function TargetProbe({ switchProject }: { switchProject?: string }) {
  const target = useTarget();
  const { setActiveProject } = useProject();
  const blocked = Boolean(target.selectionRepair || target.storageError);
  return (
    <div>
      <output data-repair>{target.selectionRepair?.issue.kind ?? "none"}</output>
      <output data-repair-project>{target.selectionRepair?.projectKey ?? "none"}</output>
      <output data-storage>{target.storageError?.operation ?? "none"}</output>
      <output data-blocked>{String(blocked)}</output>
      <output data-engine>{target.engine}</output>
      <button type="button" onClick={() => target.setEngine("afl++")}>replace engine</button>
      <button type="button" onClick={() => target.setLang("rust")}>change language</button>
      {switchProject && (
        <button type="button" onClick={() => setActiveProject(switchProject)}>switch project</button>
      )}
      <button type="button" onClick={target.retryStorage}>retry storage</button>
    </div>
  );
}

interface MountedView {
  container: HTMLDivElement;
  root: Root;
  unmount: () => Promise<void>;
}

async function mount(
  view: React.ReactNode,
  providerOptions?: Omit<React.ComponentProps<typeof AppProviders>, "children">,
): Promise<MountedView> {
  const container = document.createElement("div");
  document.body.append(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(<AppProviders {...providerOptions}>{view}</AppProviders>);
    await Promise.resolve();
  });
  return {
    container,
    root,
    unmount: async () => {
      await act(async () => root.unmount());
      container.remove();
    },
  };
}

async function flushEffects() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

async function chooseOption(trigger: HTMLButtonElement, optionLabel: string) {
  await act(async () => {
    trigger.click();
  });
  const option = [...document.body.querySelectorAll<HTMLElement>("[role=option]")]
    .find((candidate) => candidate.textContent === optionLabel);
  if (!option) throw new Error(`option ${optionLabel} was not rendered`);
  await act(async () => {
    option.click();
  });
}

function selectionStatus(container: HTMLElement, name: "repair" | "storage" | "blocked") {
  return container.querySelector(`[data-${name}]`)?.textContent;
}

function selectTrigger(container: HTMLElement, labelText: string): HTMLButtonElement {
  const label = [...container.querySelectorAll("label")].find((candidate) => candidate.textContent === labelText);
  const trigger = label?.parentElement?.querySelector<HTMLButtonElement>("[role=combobox]");
  if (!trigger) throw new Error(`Select ${labelText} was not rendered`);
  return trigger;
}

function dispatchStoredSelection(raw: string) {
  window.localStorage.setItem(STORAGE_KEY, raw);
  window.dispatchEvent(new StorageEvent("storage", {
    key: STORAGE_KEY,
    newValue: raw,
    storageArea: window.localStorage,
  }));
}

function invokedMutatingCommands() {
  return transportInvoke.mock.calls
    .map(([command]) => command)
    .filter((command) => [
      "harness_draft",
      "harness_compile",
      "harness_smoke",
      "harness_promote",
      "harness_promote_with_findings",
      "generate_seeds",
    ].includes(command));
}

function configureHarnessTransport() {
  transportInvoke.mockImplementation((command: string) => {
    if (command === "get_fuzzing_settings") {
      return Promise.resolve({
        enabled_engines: ["libfuzzer", "afl++", "honggfuzz", "syzkaller"],
        default_engine: "libfuzzer",
        default_duration_secs: 60,
        sandbox: { max_mem_mb: 2048, max_cpus: 1, max_duration_secs: 7200 },
      });
    }
    if (command === "discover") {
      return Promise.resolve({
        project_root: PROJECT,
        candidates: [{
          id: "candidate-1",
          project_root: PROJECT,
          language: "c",
          symbol: "parse_input",
          kind: "function",
          location: { file: "src/parser.c", line: 1, col: 1 },
          signature: "int parse_input(void)",
          input_surface: "buffer",
          complexity: 1,
          fit_score: 1,
          sanitizers: [],
          rationale: "test fixture",
        }],
      });
    }
    if (command === "harness_review_queue") return Promise.resolve([]);
    if (command === "system_status_cmd") {
      return Promise.resolve({
        docker: true,
        sandbox_image: true,
        libfuzzer: true,
        aflplusplus: true,
        honggfuzz: true,
        syzkaller: true,
        defectdojo: false,
      });
    }
    throw new Error(`unexpected command: ${command}`);
  });
}

let mounted: MountedView[] = [];

beforeEach(() => {
  vi.restoreAllMocks();
  transportInvoke.mockReset();
  window.localStorage.clear();
  mounted = [];
});

afterEach(async () => {
  await Promise.all(mounted.map((view) => view.unmount()));
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe("TargetProvider durable repair boundary", () => {
  it("blocks the default selection when localStorage cannot be read", async () => {
    configureHarnessTransport();
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage unavailable");
    });
    const view = await mount(<><TargetProbe /><HarnessView /></>);
    mounted.push(view);
    await flushEffects();

    expect(selectionStatus(view.container, "storage")).toBe("read");
    expect(selectionStatus(view.container, "blocked")).toBe("true");
    expect(view.container.querySelector("[role=alert]")?.textContent).toBe("targetSelection.storageReadError");
    expect(view.container.querySelector("#target-selection-replacement-engine")).toBeNull();
    expect([...view.container.querySelectorAll("button")].some((button) =>
      button.textContent?.includes("targetSelection.retryStorage"),
    )).toBe(true);
    expect(invokedMutatingCommands()).toEqual([]);
  });

  it("keeps a retired repair blocked until its explicit replacement writes successfully", async () => {
    configureHarnessTransport();
    const raw = persisted(RETIRED_CANONICAL);
    window.localStorage.setItem(STORAGE_KEY, raw);
    const view = await mount(<><TargetProbe /><HarnessView /></>);
    mounted.push(view);
    await flushEffects();
    const originalSetItem = Storage.prototype.setItem;
    const repairAtWrite: string[] = [];
    const failedWrite = vi.spyOn(Storage.prototype, "setItem").mockImplementation((key, value) => {
      if (key === STORAGE_KEY) {
        repairAtWrite.push(selectionStatus(view.container, "repair") ?? "missing");
        throw new Error("quota exceeded");
      }
      return originalSetItem.call(window.localStorage, key, value);
    });

    await act(async () => {
      view.container.querySelector("button")?.click();
    });

    expect(repairAtWrite).toEqual(["retired_engine"]);
    expect(selectionStatus(view.container, "repair")).toBe("retired_engine");
    expect(selectionStatus(view.container, "storage")).toBe("write");
    expect(selectionStatus(view.container, "blocked")).toBe("true");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(raw);
    expect(view.container.querySelector("[role=status]")?.textContent).toBe("targetSelection.storageWriteError");
    expect(invokedMutatingCommands()).toEqual([]);

    failedWrite.mockRestore();
    await act(async () => {
      view.container.querySelector("button")?.click();
    });

    expect(selectionStatus(view.container, "repair")).toBe("none");
    expect(selectionStatus(view.container, "storage")).toBe("none");
    expect(selectionStatus(view.container, "blocked")).toBe("false");
    expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}")[PROJECT].engine).toBe("afl++");
    expect(invokedMutatingCommands()).toEqual([]);
  });

  it("blocks normal selection updates when durable storage rejects the write", async () => {
    const raw = persisted("afl++");
    window.localStorage.setItem(STORAGE_KEY, raw);
    const view = await mount(<TargetProbe />);
    mounted.push(view);
    const originalSetItem = Storage.prototype.setItem;
    const failedWrite = vi.spyOn(Storage.prototype, "setItem").mockImplementation((key, value) => {
      if (key === STORAGE_KEY) throw new Error("quota exceeded");
      return originalSetItem.call(window.localStorage, key, value);
    });

    await act(async () => {
      view.container.querySelectorAll("button")[1]?.click();
    });

    expect(selectionStatus(view.container, "storage")).toBe("write");
    expect(selectionStatus(view.container, "blocked")).toBe("true");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(raw);

    failedWrite.mockRestore();
    await act(async () => {
      view.container.querySelectorAll("button")[0]?.click();
    });

    expect(selectionStatus(view.container, "storage")).toBe("none");
    expect(selectionStatus(view.container, "blocked")).toBe("false");
  });

  it("revalidates only matching storage events before an action can proceed", async () => {
    window.localStorage.setItem(STORAGE_KEY, persisted("afl++"));
    const view = await mount(<TargetProbe />);
    mounted.push(view);

    window.dispatchEvent(new StorageEvent("storage", { key: "unrelated", newValue: persisted(RETIRED_SHORT_ALIAS) }));
    expect(selectionStatus(view.container, "repair")).toBe("none");

    await act(async () => {
      dispatchStoredSelection(persisted(RETIRED_SHORT_ALIAS));
    });

    expect(selectionStatus(view.container, "repair")).toBe("retired_engine");
    expect(selectionStatus(view.container, "blocked")).toBe("true");

    await act(async () => {
      dispatchStoredSelection("{");
    });

    expect(selectionStatus(view.container, "repair")).toBe("invalid_selection");
    expect(selectionStatus(view.container, "blocked")).toBe("true");
  });

  it("ignores same-key sessionStorage and null-area events", async () => {
    window.localStorage.setItem(STORAGE_KEY, persisted("afl++"));
    const view = await mount(<TargetProbe />);
    mounted.push(view);
    const retired = persisted(RETIRED_SHORT_ALIAS);

    window.sessionStorage.setItem(STORAGE_KEY, retired);
    await act(async () => {
      window.dispatchEvent(new StorageEvent("storage", {
        key: STORAGE_KEY,
        newValue: retired,
        storageArea: window.sessionStorage,
      }));
    });
    expect(selectionStatus(view.container, "repair")).toBe("none");

    await act(async () => {
      window.dispatchEvent(new StorageEvent("storage", { key: STORAGE_KEY, newValue: retired }));
    });
    expect(selectionStatus(view.container, "repair")).toBe("none");

    await act(async () => {
      dispatchStoredSelection(retired);
    });
    expect(selectionStatus(view.container, "repair")).toBe("retired_engine");
  });

  it("cleans up the exact-key storage listener on unmount", async () => {
    const removeEventListener = vi.spyOn(window, "removeEventListener");
    const view = await mount(<TargetProbe />);

    await view.unmount();

    expect(removeEventListener).toHaveBeenCalledWith("storage", expect.any(Function));
  });

  it("revalidates a readable multi-project selection before recovering a read failure", async () => {
    const raw = JSON.stringify({
      [PROJECT]: selection("libfuzzer"),
      [PROJECT_B]: selection("honggfuzz", "parse_other"),
    });
    window.localStorage.setItem(STORAGE_KEY, raw);
    const originalGetItem = Storage.prototype.getItem;
    let firstRead = true;
    vi.spyOn(Storage.prototype, "getItem").mockImplementation((key) => {
      if (key === STORAGE_KEY && firstRead) {
        firstRead = false;
        throw new Error("storage unavailable");
      }
      return originalGetItem.call(window.localStorage, key);
    });
    const view = await mount(<TargetProbe />, {
      initialProject: PROJECT,
      recentProjects: [PROJECT, PROJECT_B],
    });
    mounted.push(view);

    await act(async () => {
      [...view.container.querySelectorAll("button")].find((button) => button.textContent === "retry storage")?.click();
    });

    expect(selectionStatus(view.container, "blocked")).toBe("false");
    expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}")).toEqual({
      [PROJECT]: selection("libfuzzer"),
      [PROJECT_B]: selection("honggfuzz", "parse_other"),
    });
  });

  it.each([
    ["retired", selection(RETIRED_SHORT_ALIAS, "parse_other"), "retired_engine"],
    ["malformed", { engine: "afl++" }, "invalid_selection"],
  ])("keeps a re-read %s project repair without deleting it", async (_kind, repairedSelection, expectedRepair) => {
    const raw = JSON.stringify({
      [PROJECT]: selection("libfuzzer"),
      [PROJECT_B]: repairedSelection,
    });
    window.localStorage.setItem(STORAGE_KEY, raw);
    const originalGetItem = Storage.prototype.getItem;
    let firstRead = true;
    vi.spyOn(Storage.prototype, "getItem").mockImplementation((key) => {
      if (key === STORAGE_KEY && firstRead) {
        firstRead = false;
        throw new Error("storage unavailable");
      }
      return originalGetItem.call(window.localStorage, key);
    });
    const view = await mount(<TargetProbe />, {
      initialProject: PROJECT,
      recentProjects: [PROJECT, PROJECT_B],
    });
    mounted.push(view);

    await act(async () => {
      [...view.container.querySelectorAll("button")].find((button) => button.textContent === "retry storage")?.click();
    });

    expect(selectionStatus(view.container, "repair")).toBe(expectedRepair);
    expect(selectionStatus(view.container, "blocked")).toBe("true");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(raw);
  });

  it("keeps the read blocker when explicit recovery cannot re-read storage", async () => {
    window.localStorage.setItem(STORAGE_KEY, persisted("libfuzzer"));
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage unavailable");
    });
    const view = await mount(<TargetProbe />);
    mounted.push(view);

    await act(async () => {
      [...view.container.querySelectorAll("button")].find((button) => button.textContent === "retry storage")?.click();
    });

    expect(selectionStatus(view.container, "storage")).toBe("read");
    expect(selectionStatus(view.container, "blocked")).toBe("true");
  });
});

describe("Harness repair interactions", () => {
  it("does not let a programmatic active-project repair change an inactive repair owner", async () => {
    const raw = JSON.stringify({
      [PROJECT]: selection("honggfuzz"),
      [PROJECT_B]: selection(RETIRED_SHORT_ALIAS, "parse_other"),
    });
    window.localStorage.setItem(STORAGE_KEY, raw);
    const view = await mount(<TargetProbe switchProject={PROJECT_B} />, {
      initialProject: PROJECT,
      recentProjects: [PROJECT, PROJECT_B],
    });
    mounted.push(view);

    expect(view.container.querySelector("[data-repair-project]")?.textContent).toBe(PROJECT_B);

    await act(async () => {
      view.container.querySelectorAll("button")[0]?.click();
    });

    expect(view.container.querySelector("[data-engine]")?.textContent).toBe("honggfuzz");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(raw);

    await act(async () => {
      view.container.querySelectorAll("button")[2]?.click();
    });
    await act(async () => {
      view.container.querySelectorAll("button")[0]?.click();
    });

    expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}")).toEqual({
      [PROJECT]: selection("honggfuzz"),
      [PROJECT_B]: selection("afl++", "parse_other"),
    });
  });

  it("projects the deterministic first repair when another repaired project is active", async () => {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({
      [PROJECT]: selection(RETIRED_CANONICAL),
      [PROJECT_B]: selection(RETIRED_SHORT_ALIAS, "parse_other"),
    }));
    const view = await mount(<TargetProbe />, {
      initialProject: PROJECT_B,
      recentProjects: [PROJECT, PROJECT_B],
    });
    mounted.push(view);

    expect(view.container.querySelector("[data-repair-project]")?.textContent).toBe(PROJECT);
  });

  it("identifies an inactive repair owner and offers a switch instead of a replacement selector", async () => {
    configureHarnessTransport();
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({
      [PROJECT]: selection("honggfuzz"),
      [PROJECT_B]: selection(RETIRED_SHORT_ALIAS, "parse_other"),
    }));
    const view = await mount(<HarnessView />, {
      initialProject: PROJECT,
      recentProjects: [PROJECT, PROJECT_B],
    });
    mounted.push(view);
    await flushEffects();

    expect(view.container.textContent).toContain(PROJECT_B);
    expect(view.container.querySelector("#target-selection-replacement-engine")).toBeNull();
    expect([...view.container.querySelectorAll("button")].some((button) =>
      button.textContent?.includes("targetSelection.switchProject"),
    )).toBe(true);

    await act(async () => {
      [...view.container.querySelectorAll("button")]
        .find((button) => button.textContent?.includes("targetSelection.switchProject"))?.click();
    });
    await chooseOption(selectTrigger(view.container, "targetSelection.replacementEngine"), "AFL++");

    const persistedSelection = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persistedSelection[PROJECT].engine).toBe("honggfuzz");
    expect(persistedSelection[PROJECT_B].engine).toBe("afl++");
  });

  it("offers reset or retry instead of engine replacement for global repairs", async () => {
    configureHarnessTransport();
    window.localStorage.setItem(STORAGE_KEY, "{");
    const view = await mount(<HarnessView />);
    mounted.push(view);
    await flushEffects();

    expect(view.container.querySelector("#target-selection-replacement-engine")).toBeNull();
    expect([...view.container.querySelectorAll("button")].some((button) =>
      button.textContent?.includes("targetSelection.reset"),
    )).toBe(true);
  });

  it("stages two project repairs until the final synchronous write succeeds", async () => {
    const raw = JSON.stringify({
      [PROJECT]: selection(RETIRED_CANONICAL),
      [PROJECT_B]: selection(RETIRED_SHORT_ALIAS, "parse_other"),
    });
    window.localStorage.setItem(STORAGE_KEY, raw);
    const view = await mount(<TargetProbe switchProject={PROJECT_B} />, {
      initialProject: PROJECT,
      recentProjects: [PROJECT, PROJECT_B],
    });
    mounted.push(view);
    await act(async () => {
      view.container.querySelectorAll("button")[0]?.click();
    });
    expect(selectionStatus(view.container, "repair")).toBe("retired_engine");
    expect(selectionStatus(view.container, "blocked")).toBe("true");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(raw);
    expect(invokedMutatingCommands()).toEqual([]);

    await act(async () => {
      view.container.querySelectorAll("button")[2]?.click();
    });

    const originalSetItem = Storage.prototype.setItem;
    const failedWrite = vi.spyOn(Storage.prototype, "setItem").mockImplementation((key, value) => {
      if (key === STORAGE_KEY) throw new Error("quota exceeded");
      return originalSetItem.call(window.localStorage, key, value);
    });
    await act(async () => {
      view.container.querySelectorAll("button")[0]?.click();
    });
    expect(selectionStatus(view.container, "repair")).toBe("retired_engine");
    expect(selectionStatus(view.container, "storage")).toBe("write");
    expect(selectionStatus(view.container, "blocked")).toBe("true");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(raw);
    expect(invokedMutatingCommands()).toEqual([]);

    failedWrite.mockRestore();
    await act(async () => {
      view.container.querySelectorAll("button")[0]?.click();
    });

    expect(selectionStatus(view.container, "repair")).toBe("none");
    expect(selectionStatus(view.container, "storage")).toBe("none");
    expect(selectionStatus(view.container, "blocked")).toBe("false");
    expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}")).toEqual({
      [PROJECT]: selection("afl++"),
      [PROJECT_B]: selection("afl++", "parse_other"),
    });
    expect(invokedMutatingCommands()).toEqual([]);
  });

  it.each([RETIRED_CANONICAL, RETIRED_SHORT_ALIAS, "unknown-engine"])(
    "does not replace %j when the language changes before explicit engine selection",
    async (engine) => {
      configureHarnessTransport();
      window.localStorage.setItem(STORAGE_KEY, persisted("afl++"));
      const view = await mount(<><TargetProbe /><HarnessView /></>);
      mounted.push(view);
      await flushEffects();
      await flushEffects();

      const raw = persisted(engine);
      await act(async () => {
        dispatchStoredSelection(raw);
      });
      const expectedRepair = engine === "unknown-engine" ? "invalid_selection" : "retired_engine";
      expect(selectionStatus(view.container, "repair")).toBe(expectedRepair);

      await chooseOption(selectTrigger(view.container, "harness.language"), "Rust");

      expect(selectionStatus(view.container, "repair")).toBe(expectedRepair);
      expect(window.localStorage.getItem(STORAGE_KEY)).toBe(raw);
      expect(invokedMutatingCommands()).toEqual([]);

      await chooseOption(selectTrigger(view.container, "targetSelection.replacementEngine"), "libFuzzer");

      expect(selectionStatus(view.container, "repair")).toBe("none");
      expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}")[PROJECT].engine).toBe("libfuzzer");
      expect(invokedMutatingCommands()).toEqual([]);
    },
  );
});
