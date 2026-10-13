// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ProjectContext } from "../providers/project";
import { ChangesView } from "../views/ChangesView";
import type { RevisionComparisonView } from "../types";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke }) }));
let cleanup = async () => {};

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  invoke.mockReset();
});
afterEach(async () => { await cleanup(); vi.unstubAllGlobals(); });

function comparison(base: string, head: string): RevisionComparisonView {
  return {
    schema_version: 1, base_run_id: base, head_run_id: head, comparable: true,
    refusal: null, findings: [], coverage: { status: "stable", delta_pct: 0 },
  };
}

async function mount() {
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  const render = async (project: string) => {
    await act(async () => root.render(
      <ProjectContext.Provider value={{ activeProject: project, recentProjects: [project],
        setActiveProject: () => {}, addRecent: () => {}, removeRecent: () => {}, deleteProjectData: async () => {} }}>
        <I18nProvider><ChangesView /></I18nProvider>
      </ProjectContext.Provider>,
    ));
  };
  await render("/project-a");
  const button = (label: string) => [...host.querySelectorAll("button")].find(item => item.textContent === label);
  const click = async (label: string) => {
    expect(button(label), host.textContent ?? "").toBeTruthy();
    await act(async () => button(label)!.click());
  };
  const input = async (label: string, value: string) => {
    const field = host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(field, value);
      field.dispatchEvent(new Event("input", { bubbles: true }));
    });
  };
  const approve = async () => { await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click()); };
  return { host, render, button, click, input, approve };
}

it("requires a fresh comparison and approval after run IDs change", async () => {
  invoke.mockImplementation(async (command, args) => {
    if (command === "change_compare") return comparison(args.baseRunId, args.headRunId);
    if (command === "change_publish") return { destination: "issue_tracker", observed_only_in_head: 0, coverage_regressed: false, url: null };
    throw new Error(command);
  });
  const view = await mount();
  await view.input("Base run id", "base-a");
  await view.input("Head run id", "head-a");
  await view.click("Compare runs");
  await view.approve();
  expect(view.button("Publish comparison")?.disabled).toBe(false);
  await view.input("Head run id", "head-b");
  expect(view.button("Publish comparison")?.disabled ?? true).toBe(true);
  expect(view.host.querySelector('input[type="checkbox"]')).toBeNull();
  expect(invoke.mock.calls.filter(([command]) => command === "change_publish")).toHaveLength(0);

  await view.click("Compare runs");
  expect(view.button("Publish comparison")?.disabled).toBe(true);
  await view.approve();
  await view.click("Publish comparison");
  expect(invoke.mock.calls.filter(([command]) => command === "change_publish")).toEqual([
    ["change_publish", { baseRunId: "base-a", headRunId: "head-b", regressionThresholdPct: 5, destination: "issue_tracker" }],
  ]);
});

it("ignores a comparison that finishes after its inputs change", async () => {
  let finish!: (value: RevisionComparisonView) => void;
  invoke.mockReturnValue(new Promise<RevisionComparisonView>(resolve => { finish = resolve; }));
  const view = await mount();
  await view.input("Base run id", "base-a");
  await view.input("Head run id", "head-a");
  await view.click("Compare runs");
  await view.input("Head run id", "head-b");
  await act(async () => finish(comparison("base-a", "head-a")));
  expect(view.host.querySelector('input[type="checkbox"]')).toBeNull();
  expect(view.button("Compare runs")?.disabled).toBe(false);
});

it("clears reviewed inputs and ignores late results when the project changes", async () => {
  let finish!: (value: RevisionComparisonView) => void;
  invoke.mockReturnValue(new Promise<RevisionComparisonView>(resolve => { finish = resolve; }));
  const view = await mount();
  await view.input("Base run id", "base-a");
  await view.input("Head run id", "head-a");
  await view.click("Compare runs");
  await view.render("/project-b");
  await act(async () => finish(comparison("base-a", "head-a")));
  expect(view.host.querySelector<HTMLInputElement>('input[aria-label="Base run id"]')!.value).toBe("");
  expect(view.host.querySelector('input[type="checkbox"]')).toBeNull();
});
