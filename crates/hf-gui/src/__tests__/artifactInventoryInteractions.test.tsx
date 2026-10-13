// @vitest-environment jsdom

import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ArtifactsView } from "../views/ArtifactsView";
import { I18nContext } from "../i18nContext";
import { ProjectContext } from "../providers/project";
import { ConfirmContext } from "../providers/confirm";
import type { CorpusEntry, Crash } from "../types";

const transport = vi.hoisted(() => ({ invoke: vi.fn(), desktop: false }));
vi.mock("../lib", async () => ({
  ...await vi.importActual("../lib"),
  getTransport: () => ({ invoke: transport.invoke }),
  isTauriEnvironment: () => transport.desktop,
}));

const PROJECT_A = "/projects/a";
const PROJECT_B = "/projects/b";
let host: HTMLDivElement;
let root: Root;
let confirm: ReturnType<typeof vi.fn<() => Promise<boolean>>>;

function crash(project: string): Crash {
  return {
    id: `${project}-crash`, run_id: `${project}-run`, target_id: `${project}-target`,
    input_path: `${project}/crash-${project.at(-1)}`, stack_signature: "test-stack",
    kind: "memory", summary: "test crash", minimized: false, bug_report: null,
    casr: null, origin: "target",
  };
}

function seed(project: string): CorpusEntry {
  return {
    target_id: `${project}-target`, path: `${project}/seed-${project.at(-1)}`,
    sha256: project === PROJECT_A ? "a".repeat(64) : "b".repeat(64),
    size: 4, source: "import", coverage_hash: null,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function TestView() {
  const [project, setProject] = useState(PROJECT_A);
  return <I18nContext.Provider value={{ locale: "en", setLocale: () => {}, t: (key) => key }}>
    <ProjectContext.Provider value={{
      activeProject: project, recentProjects: [PROJECT_A, PROJECT_B], setActiveProject: setProject,
      addRecent: () => {}, removeRecent: () => {}, deleteProjectData: async () => {},
    }}>
      <ConfirmContext.Provider value={confirm}>
        <button onClick={() => setProject(PROJECT_B)}>switch project</button>
        <ArtifactsView />
      </ConfirmContext.Provider>
    </ProjectContext.Provider>
  </I18nContext.Provider>;
}

async function mount() {
  await act(async () => root.render(<TestView />));
}

async function click(label: string) {
  const button = [...host.querySelectorAll("button")].find((item) => item.textContent === label || item.getAttribute("aria-label") === label);
  expect(button, `Missing action ${label}`).toBeTruthy();
  expect(button!.disabled, `Disabled action ${label}`).toBe(false);
  await act(async () => button!.click());
}

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  transport.desktop = false;
  transport.invoke.mockReset();
  transport.invoke.mockImplementation(async (command: string, args?: { project: string }) => {
    const project = args?.project ?? PROJECT_A;
    if (command === "all_crashes") return [crash(project)];
    if (command === "all_corpus") return [seed(project)];
    if (["delete_crash", "delete_corpus_entry", "clear_all_artifacts"].includes(command)) return undefined;
    throw new Error(`Unexpected command ${command}`);
  });
  confirm = vi.fn(async () => true);
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.unstubAllGlobals();
});

describe("ArtifactsView inventory ownership", () => {
  it.each(["success", "failure"])("ignores the previous project's delayed scan %s", async (outcome) => {
    const pending = deferred<Crash[]>();
    const baseline = transport.invoke.getMockImplementation()!;
    transport.invoke.mockImplementation((command, args) => command === "all_crashes" && args.project === PROJECT_A
      ? pending.promise : baseline(command, args));
    await mount();
    await click("switch project");
    expect(host.textContent).toContain("crash-b");

    await act(async () => {
      if (outcome === "success") pending.resolve([crash(PROJECT_A)]);
      else pending.reject(new Error("previous project unavailable"));
    });

    expect(host.textContent).toContain("crash-b");
    expect(host.textContent).toContain("seed-b");
    expect(host.textContent).not.toContain("crash-a");
    expect(host.textContent).not.toContain("previous project unavailable");
    await click("artifacts.deleteCrashAria");
    expect(transport.invoke.mock.calls.find(([command]) => command === "delete_crash")?.[1]).toEqual({ crashId: "/projects/b-crash", project: PROJECT_B });
  });

  it("removes the old project's actions while the next inventory loads", async () => {
    const pending = deferred<Crash[]>();
    const baseline = transport.invoke.getMockImplementation()!;
    transport.invoke.mockImplementation((command, args) => command === "all_crashes" && args.project === PROJECT_B
      ? pending.promise : baseline(command, args));
    await mount();
    expect(host.textContent).toContain("crash-a");
    await click("switch project");

    expect(host.textContent).not.toContain("crash-a");
    expect(host.textContent).not.toContain("seed-a");
    expect(host.querySelector('[aria-label="artifacts.deleteCrashAria"]')).toBeNull();
    expect([...host.querySelectorAll("button")].some((button) => button.textContent === "common.clearAll")).toBe(false);
  });

  it.each([
    ["artifacts.deleteCrashAria", "delete_crash"],
    ["artifacts.deleteCorpusAria", "delete_corpus_entry"],
    ["common.clearAll", "clear_all_artifacts"],
  ])("abandons %s confirmation after changing project", async (label, command) => {
    const pending = deferred<boolean>();
    confirm.mockReturnValue(pending.promise);
    await mount();
    await click(label);
    await click("switch project");
    await act(async () => pending.resolve(true));

    expect(transport.invoke.mock.calls.some(([name]) => name === command)).toBe(false);
    expect(host.textContent).toContain("crash-b");
    expect(host.textContent).toContain("seed-b");
  });

  it.each([
    ["artifacts.deleteCrashAria", "crash-a"],
    ["artifacts.deleteCorpusAria", "seed-a"],
    ["common.clearAll", "crash-a"],
  ])("does not restore deleted inventory from a pending refresh after %s", async (label, removed) => {
    await mount();
    const pending = deferred<Crash[]>();
    const baseline = transport.invoke.getMockImplementation()!;
    transport.invoke.mockImplementation((command, args) => command === "all_crashes"
      ? pending.promise : baseline(command, args));
    await click("common.rescan");
    await click(label);
    expect(host.textContent).not.toContain(removed);
    await act(async () => pending.resolve([crash(PROJECT_A)]));

    expect(host.textContent).not.toContain(removed);
    expect(host.textContent).not.toContain("artifacts.scanning");
  });

  it("keeps desktop inventory and clearing global when the selected project changes", async () => {
    transport.desktop = true;
    transport.invoke.mockImplementation(async (command: string) => {
      if (command === "all_crashes") return [crash(PROJECT_A), crash(PROJECT_B)];
      if (command === "all_corpus") return [seed(PROJECT_A), seed(PROJECT_B)];
      if (command === "clear_all_artifacts") return undefined;
      throw new Error(`Unexpected command ${command}`);
    });
    await mount();
    await click("switch project");
    expect(host.textContent).toContain("crash-a");
    expect(host.textContent).toContain("crash-b");
    expect(transport.invoke.mock.calls.filter(([command]) => ["all_crashes", "all_corpus"].includes(command)).every(([, args]) => args === undefined)).toBe(true);
    await click("common.clearAll");
    expect(transport.invoke.mock.calls.find(([command]) => command === "clear_all_artifacts")?.[1]).toBeUndefined();
  });
});
