// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DashboardView } from "../views/DashboardView";
import { I18nContext } from "../i18nContext";
import { ProjectContext } from "../providers/project";
import { ToastContext } from "../components/ui/toastContext";
import type { ReportDraft } from "../types";
import type * as LibModule from "../lib";

const runtime = vi.hoisted(() => ({ invoke: vi.fn(), desktop: false, httpOverride: false, saveDelay: null as Promise<void> | null }));
vi.mock("../lib", async () => ({
  ...(await vi.importActual<typeof LibModule>("../lib")),
  getTransport: () => ({ invoke: runtime.invoke }),
  isTauriEnvironment: () => runtime.desktop,
  usesHttpBackend: () => !runtime.desktop || runtime.httpOverride,
  useDefectDojo: () => ({ configured: false }),
}));

const OWNER = "/projects/saved-owner";
const ACTIVE = "/projects/another-project";
let stored: ReportDraft;
let createdReports: number;
let host: HTMLDivElement;
let root: Root;

beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  runtime.desktop = false;
  runtime.httpOverride = false;
  runtime.saveDelay = null;
  createdReports = 0;
  stored = { id: "saved-report", title: "Original title", project: OWNER, target: "parse", status: "Draft", content: "# Original report", updated_at: "2026-10-01T00:00:00Z" };
  const publicReport = () => ({ ...stored, project: runtime.desktop && !runtime.httpOverride ? stored.project : "<redacted-path>" });
  runtime.invoke.mockReset();
  runtime.invoke.mockImplementation(async (command, args) => {
    if (command === "workbench_dashboard") return {
      active_project: ACTIVE, active_target: null,
      totals: { projects: 1, targets: 0, harnesses: 0, harnesses_needing_review: 0, runs: 0, active_runs: 0, crashes: 0, crashes_needing_triage: 0, corpus_entries: 0 },
      recent_runs: [], top_targets: [], harness_reviews: [], crash_reviews: [],
      readiness: { state: "setup_required", score: 0, headline: "Discover", detail: "No targets", blockers: [], blocker_items: [] },
      next_actions: [], next_action_items: [],
    };
    if (command === "list_report_drafts") return [publicReport()];
    if (command === "system_status_cmd" || command === "effective_auto_revert_policy") return null;
    if (command === "save_report_draft") {
      if (runtime.saveDelay) await runtime.saveDelay;
      const id = typeof args.id === "string" ? args.id : `created-${++createdReports}`;
      stored = { ...stored, ...args, id, project: args.project === undefined ? stored.project : args.project };
      return publicReport();
    }
    throw new Error(`Unexpected operation: ${command}`);
  });
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.unstubAllGlobals();
});

async function mount(activeProject = ACTIVE) {
  await act(async () => root.render(
    <I18nContext.Provider value={{ locale: "en", setLocale: () => {}, t: key => key }}>
      <ProjectContext.Provider value={{ activeProject, recentProjects: [activeProject], setActiveProject: () => {}, addRecent: () => {}, removeRecent: () => {}, deleteProjectData: async () => {} }}>
        <ToastContext.Provider value={{ toast: () => {} }}><DashboardView /></ToastContext.Provider>
      </ProjectContext.Provider>
    </I18nContext.Provider>,
  ));
  await click("dashboard.tabReports");
}

async function click(text: string) {
  const button = [...host.querySelectorAll("button")].find(item => item.textContent?.startsWith(text));
  if (!button) throw new Error(`Missing action ${text}: ${host.textContent}`);
  await act(async () => button.click());
}

async function edit(label: string, value: string) {
  const input = [...host.querySelectorAll("label")].find(item => item.textContent === label)?.querySelector("input");
  if (!input) throw new Error(`Missing field ${label}`);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

it("preserves a redacted report's saved owner across repeated content edits in another project", async () => {
  await mount();
  for (const title of ["First edit", "Second edit"]) {
    await edit("dashboard.labelTitle", title);
    await click("common.saveDraft");
    expect(stored.title).toBe(title);
    expect(stored.project).toBe(OWNER);
  }
});

it("replaces a browser report owner only after an explicit project edit", async () => {
  await mount();
  await edit("dashboard.labelProject", "/projects/replacement");
  await click("common.saveDraft");
  expect(stored.project).toBe("/projects/replacement");
  await edit("dashboard.labelTitle", "Later content edit");
  await click("common.saveDraft");
  expect(stored.project).toBe("/projects/replacement");
});

it("keeps explicit local project editing on desktop", async () => {
  runtime.desktop = true;
  await mount();
  await edit("dashboard.labelProject", "/projects/local-replacement");
  await click("common.saveDraft");
  expect(stored.project).toBe("/projects/local-replacement");
});

it("preserves the saved owner when a desktop host selects the HTTP backend", async () => {
  runtime.desktop = true;
  runtime.httpOverride = true;
  await mount();
  await edit("dashboard.labelTitle", "Desktop HTTP edit");
  await click("common.saveDraft");
  expect(stored.title).toBe("Desktop HTTP edit");
  expect(stored.project).toBe(OWNER);
});

it("keeps report edits made during save and persists them on the next save", async () => {
  await mount();
  await edit("dashboard.labelTitle", "Clicked snapshot");
  let release!: () => void;
  runtime.saveDelay = new Promise<void>(resolve => { release = resolve; });
  await click("common.saveDraft");
  await edit("dashboard.labelTitle", "Newer edit");
  await edit("dashboard.labelProject", "/projects/newer-owner");
  await act(async () => release());
  expect(stored.title).toBe("Clicked snapshot");
  expect(host.querySelector<HTMLInputElement>("label input")?.value).toBe("Newer edit");
  runtime.saveDelay = null;
  await click("common.saveDraft");
  expect(stored.title).toBe("Newer edit");
  expect(stored.project).toBe("/projects/newer-owner");
});

it("does not replace a newly selected blank draft with an earlier save response", async () => {
  await mount();
  let release!: () => void;
  runtime.saveDelay = new Promise<void>(resolve => { release = resolve; });
  await click("common.saveDraft");
  await click("common.new");
  await edit("dashboard.labelTitle", "Different draft");
  await act(async () => release());
  expect(host.querySelector<HTMLInputElement>("label input")?.value).toBe("Different draft");
  expect(host.querySelector("textarea")?.value).toBe("");
});

it("retains the first saved ID for newer edits without creating duplicate drafts", async () => {
  await mount();
  await click("common.new");
  await edit("dashboard.labelTitle", "New report");
  const body = host.querySelector("textarea")!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(body, "# New report");
    body.dispatchEvent(new Event("input", { bubbles: true }));
  });
  let release!: () => void;
  runtime.saveDelay = new Promise<void>(resolve => { release = resolve; });
  await click("common.saveDraft");
  await click("common.saveDraft");
  await edit("dashboard.labelTitle", "New report edited while saving");
  await act(async () => release());
  const firstId = stored.id;
  runtime.saveDelay = null;
  await click("common.saveDraft");
  expect(stored.title).toBe("New report edited while saving");
  expect(stored.id).toBe(firstId);
  expect(createdReports).toBe(1);
});

it("does not assign an earlier save ID to an automatically selected report", async () => {
  await mount();
  let release!: () => void;
  runtime.saveDelay = new Promise<void>(resolve => { release = resolve; });
  await click("common.saveDraft");
  const body = host.querySelector("textarea")!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(body, "");
    body.dispatchEvent(new Event("input", { bubbles: true }));
  });
  const other = { ...stored, id: "other-report", title: "Other report", content: "# Other report", project: "<redacted-path>" };
  const originalInvoke = runtime.invoke.getMockImplementation()!;
  runtime.invoke.mockImplementation((command, args) => command === "list_report_drafts" ? Promise.resolve([other]) : originalInvoke(command, args));
  await mount("/projects/newly-selected-project");
  expect(host.querySelector<HTMLInputElement>("label input")?.value).toBe("Other report");
  await act(async () => release());
  runtime.saveDelay = null;
  await click("common.saveDraft");
  expect(stored.id).toBe(other.id);
  expect(stored.content).toBe(other.content);
});
