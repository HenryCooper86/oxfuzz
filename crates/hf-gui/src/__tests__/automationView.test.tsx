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
const campaign = {
  id: "schedule-1", name: "Nightly parser", enabled: true, trigger: "interval 3600s",
  project: "/project", target: "parse", engine: "honggfuzz", lang: "c", duration_secs: 60,
  max_runs: null, max_total_secs: null, runs_done: 0, secs_done: 0, last_fire: null,
  durability_status: "ready", preview: { state: "due", timezone: "UTC", timezone_fallback: false,
    next_fires: [], remaining_runs: null, remaining_secs: null },
};
const execution = (id: string, status: string) => ({ execution_id: id, schedule_id: "schedule-1",
  campaign: "Nightly parser", triggered_at: "2026-11-10T01:00:00Z", status, summary: `${id} evidence` });
let host: HTMLDivElement;
let root: Root;
let schedules: typeof campaign[];
let history: ReturnType<typeof execution>[];
let armed: boolean;
let overrides: Record<string, (() => unknown) | undefined>;
const button = (label: string) => [...host.querySelectorAll("button")].find(item => item.textContent?.trim() === label)!;
async function click(label: string) {
  expect(button(label), `button ${label}`).toBeDefined();
  await act(async () => button(label).click());
}
async function edit(input: HTMLInputElement, value: string) {
  expect(input).toBeTruthy();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function mount() {
  await act(async () => root.render(<I18nProvider><ProjectContext.Provider value={{
    activeProject: "/project", recentProjects: [], setActiveProject: () => {}, addRecent: () => {},
    removeRecent: () => {}, deleteProjectData: async () => {},
  }}><ConfirmContext.Provider value={async () => true}><AutomationView /></ConfirmContext.Provider></ProjectContext.Provider></I18nProvider>));
}
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.useFakeTimers(); localStorage.clear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  schedules = [campaign]; history = []; armed = false; overrides = {};
  io.invoke.mockReset();
  io.invoke.mockImplementation(async (command: string, args: Record<string, unknown> = {}) => {
    if (overrides[command]) return overrides[command]!();
    switch (command) {
      case "get_fuzzing_settings": return DEFAULT_FUZZING_SETTINGS;
      case "allocation_candidates": return [];
      case "allocation_status": return null;
      case "schedule_list": return schedules;
      case "schedule_history": return history;
      case "schedule_recovery_list": return [];
      case "schedule_runtime": return { state: "running", armed };
      case "schedule_concurrency_limits": return { active_fuzz_campaign_limit: 2, scheduler_workflow_dispatch_limit: 10, effective_max_concurrent_fuzz_runs: 2 };
      case "schedule_targets": return [{ target: "parse", engine: "honggfuzz", language: "c", fit_score: 1 }];
      case "schedule_set_enabled": schedules = [{ ...campaign, enabled: Boolean(args.enabled) }]; return schedules;
      case "schedule_arm": armed = true; return { armed };
      case "schedule_history_clear": history = history.filter(row => row.status === "running"); return 1;
      case "schedule_create": return schedules;
      default: throw new Error(`Unexpected command: ${command}`);
    }
  });
});
afterEach(async () => {
  await act(async () => root.unmount()); host.remove(); vi.useRealTimers(); vi.unstubAllGlobals();
});

it("shows a failed target lookup as unavailable rather than an empty approved target set", async () => {
  overrides.schedule_targets = () => Promise.reject(new Error("target storage unavailable"));
  await mount();
  expect(host.textContent).toContain("target storage unavailable");
  expect(host.textContent).not.toContain("This project has no approved harness yet");
  expect(button("Schedule").disabled).toBe(true);
});

it("refreshes protected running history after clearing deletable executions", async () => {
  history = [execution("live-once", "running"), execution("finished", "completed")];
  await mount(); await click("Clear");
  expect(host.textContent).toContain("live-once evidence");
  expect(host.textContent).not.toContain("finished evidence");
});

it("does not let a pre-pause poll restore an enabled campaign", async () => {
  await mount();
  let finish!: (value: typeof campaign[]) => void;
  overrides.schedule_list = () => new Promise(resolve => { finish = resolve; });
  await act(async () => vi.advanceTimersByTime(10_000));
  delete overrides.schedule_list;
  await click("Pause");
  await act(async () => finish([campaign]));
  expect(button("Resume")).toBeDefined();
  expect(button("Pause")).toBeUndefined();
});

it("does not let a pre-authorization poll restore disarmed status", async () => {
  await mount();
  let finish!: (value: { state: string; armed: boolean }) => void;
  overrides.schedule_runtime = () => new Promise(resolve => { finish = resolve; });
  await act(async () => vi.advanceTimersByTime(10_000));
  delete overrides.schedule_runtime;
  await click("Authorize scheduled runs");
  await act(async () => finish({ state: "running", armed: false }));
  expect(button("Withdraw authorization")).toBeDefined();
});

it.each(["0", "-1", "1.5"])("rejects invalid run budget %s instead of dispatching a changed allowance", async value => {
  await mount();
  await edit(host.querySelector<HTMLInputElement>('input[placeholder="∞"]')!, value);
  await click("Schedule");
  expect(io.invoke.mock.calls.filter(([command]) => command === "schedule_create")).toHaveLength(0);
  expect(host.querySelector('[role="alert"]')).not.toBeNull();
});

it("rejects a zero time budget instead of silently raising it to one second", async () => {
  await mount();
  await edit(host.querySelectorAll<HTMLInputElement>('input[placeholder="∞"]')[1], "0");
  await click("Schedule");
  expect(io.invoke.mock.calls.filter(([command]) => command === "schedule_create")).toHaveLength(0);
});

it("does not schedule the old duration when the displayed duration is zero", async () => {
  await mount(); await edit(host.querySelector<HTMLInputElement>('input[aria-label="run"]')!, "0");
  await click("Schedule");
  expect(io.invoke.mock.calls.filter(([command]) => command === "schedule_create")).toHaveLength(0);
});

it("sends the exact valid budget and leaves blank allowances unbounded", async () => {
  await mount();
  await edit(host.querySelector<HTMLInputElement>('input[placeholder="∞"]')!, "3");
  await edit(host.querySelectorAll<HTMLInputElement>('input[placeholder="∞"]')[1], "2.5");
  await click("Schedule");
  expect(io.invoke.mock.calls.find(([command]) => command === "schedule_create")?.[1]).toMatchObject({ maxRuns: 3, maxTotalSecs: 150, durationSecs: 60 });
  await edit(host.querySelector<HTMLInputElement>('input[placeholder="∞"]')!, "");
  await edit(host.querySelectorAll<HTMLInputElement>('input[placeholder="∞"]')[1], "");
  await click("Schedule");
  expect(io.invoke.mock.calls.filter(([command]) => command === "schedule_create").at(-1)?.[1]).toMatchObject({ maxRuns: null, maxTotalSecs: null });
});

it("holds the campaign limit control until its pending update is settled", async () => {
  await mount();
  let finish!: (value: number) => void;
  overrides.schedule_concurrency_set = () => new Promise(resolve => { finish = resolve; });
  const input = host.querySelector<HTMLInputElement>('input[aria-label="Active fuzz campaigns"]')!;
  await edit(input, "4");
  expect(input.disabled).toBe(true);
  await act(async () => finish(4));
  expect(input.disabled).toBe(false);
  expect(input.value).toBe("4");
  expect(host.querySelector('[aria-label="How many fuzz runs can happen at once: the lower of the active-campaign limit and the scheduler limit"]')?.textContent).toBe("Runs at once4");
});

it("retries a failed approved-target lookup without changing projects", async () => {
  overrides.schedule_targets = () => Promise.reject(new Error("target storage unavailable"));
  await mount();
  delete overrides.schedule_targets;
  await click("Retry");
  expect(host.textContent).not.toContain("target storage unavailable");
  expect(button("Schedule").disabled).toBe(false);
});
