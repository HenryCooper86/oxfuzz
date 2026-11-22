// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AutomationView } from "../views/FeatureViews";
import { I18nProvider } from "../i18n";
import { ConfirmContext } from "../providers/confirm";
import { ProjectContext } from "../providers/project";
import { DEFAULT_FUZZING_SETTINGS } from "../lib/fuzzingSettings";

const io = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke: io.invoke }) }));
let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); vi.useFakeTimers(); localStorage.clear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  io.invoke.mockReset();
  io.invoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "get_fuzzing_settings": return DEFAULT_FUZZING_SETTINGS;
      case "schedule_targets": return [{ target: "parse", engine: "honggfuzz", language: "c", fit_score: 1 }];
      case "schedule_list": case "schedule_history": case "schedule_recovery_list": case "allocation_candidates": return [];
      case "allocation_status": return null;
      case "schedule_concurrency_limits": return { active_fuzz_campaign_limit: 2, scheduler_workflow_dispatch_limit: 10, effective_max_concurrent_fuzz_runs: 2 };
      case "schedule_arm": return { armed: false };
      case "schedule_create": return [];
      default: return null;
    }
  });
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.useRealTimers(); vi.unstubAllGlobals(); });
async function mount() {
  await act(async () => root.render(<I18nProvider><ProjectContext.Provider value={{
    activeProject: "/project", recentProjects: [], setActiveProject: () => {}, addRecent: () => {}, removeRecent: () => {}, deleteProjectData: async () => {},
  }}><ConfirmContext.Provider value={async () => true}><AutomationView /></ConfirmContext.Provider></ProjectContext.Provider></I18nProvider>));
}
async function pick(comboboxIndexLabel: string, option: string) {
  const trigger = [...host.querySelectorAll<HTMLElement>('[role="combobox"]')].find(item => item.textContent?.includes(comboboxIndexLabel) || item.getAttribute("aria-label") === comboboxIndexLabel)!;
  expect(trigger, comboboxIndexLabel).toBeTruthy();
  await act(async () => trigger.click());
  const item = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(node => node.textContent === option)!;
  expect(item, option).toBeTruthy();
  await act(async () => item.click());
}
const schedule = () => [...host.querySelectorAll("button")].find(item => item.textContent?.trim() === "Schedule")!;

it("schedules an event trigger with an explicit name", async () => {
  await mount();
  await pick("Interval", "On event");
  await pick("Event", "Run failed");
  const name = host.querySelector<HTMLInputElement>('input[aria-label="Name"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(name, "Alert follow-up");
    name.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => schedule().click());
  expect(io.invoke.mock.calls.find(([c]) => c === "schedule_create")?.[1]).toMatchObject({
    name: "Alert follow-up", triggerKind: "event", triggerValue: "run.failed",
  });
});

it("keeps the generated name when the name field is empty", async () => {
  await mount();
  await act(async () => schedule().click());
  expect((io.invoke.mock.calls.find(([c]) => c === "schedule_create")?.[1] as { name: string }).name).toContain(" / ");
});
