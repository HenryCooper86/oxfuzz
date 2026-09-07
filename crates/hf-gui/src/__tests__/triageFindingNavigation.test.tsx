// @vitest-environment jsdom

import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { FindingSelectionProvider, FINDING_SELECTION_STORAGE_KEY } from "../providers/FindingSelectionContext";
import { PipelineContext } from "../providers/pipeline";
import { ProjectContext } from "../providers/project";
import { RunOutputContext, EMPTY_RUN_STATS } from "../providers/runOutput";
import { TargetContext } from "../providers/target";
import { ConfirmContext } from "../providers/confirm";
import { ToastContext } from "../components/ui/toastContext";
import { TriageView } from "../views/TriageView";
import { DashboardView } from "../views/DashboardView";
import type { FindingReviewItem } from "../types";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({
  ...(await vi.importActual<typeof import("../lib")>("../lib")),
  getTransport: () => ({ invoke }),
  isTauriEnvironment: () => false,
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
Object.defineProperty(HTMLElement.prototype, "scrollIntoView", { configurable: true, value: () => undefined });

const PROJECT_A = "/workspace/a";
const PROJECT_B = "/workspace/b";

function finding(id: string, runId: string, project: string, input: string): FindingReviewItem {
  const claim = {
    determination: "not_verified" as const,
    status: "not_verified" as const,
    detail_code: "fixture",
    detail: "fixture",
    evidence: [],
  };
  return {
    crash: {
      id,
      run_id: runId,
      target_id: `${project}-target`,
      input_path: input,
      stack_signature: `${id}-signature`,
      kind: "Asan",
      summary: `${id} summary`,
      minimized: true,
      bug_report: null,
      casr: null,
      origin: "target",
    },
    project_root: project,
    target_id: `${project}-target`,
    target_symbol: "parse_packet",
    target_language: "C",
    engine: "LibFuzzer",
    proof: {
      schema_version: 1,
      fault_origin: { ...claim, determination: "target", status: "supported" },
      deterministic_reproduction: claim,
      casr_exploitability: { ...claim, determination: "unavailable", status: "unavailable" },
      external_reachability: claim,
      fix_verification: claim,
    } as FindingReviewItem["proof"],
    disposition: {
      schema_version: 1,
      disposition: "reachability_unproven",
      action: "demonstrate_reachability",
      action_detail: "show reachability",
      claim_ceiling: "target_fault_minimized",
      claim_limit: "not shown exploitable",
      evidence: [],
    },
    latest_scoped_actions_allowed: false,
    latest_scoped_action_reason: "This finding belongs to a historical run.",
  };
}

const older = finding("older-crash", "older-run", PROJECT_A, "/evidence/older/crash-input");
older.crash.casr = {
  severity: "Exploitable",
  severity_short: "write outside allocation",
  crashline: "historical/parser.c:73",
  stack: ["parse_legacy_frame", "dispatch_historical_input"],
  cluster: 17,
};
const newer = finding("newer-crash", "newer-run", PROJECT_A, "/evidence/newer/crash-input");
const projectB = finding("project-b-crash", "project-b-run", PROJECT_B, "/evidence/b/crash-input");
const resolved = {
  ...finding("resolved-crash", "older-run", PROJECT_A, "/evidence/resolved/crash-input"),
  disposition: { ...older.disposition, disposition: "resolved", action: "no_action", claim_ceiling: "remediation_verified" },
} as FindingReviewItem;

function Providers({ children, locale = "en", translate = (key) => key }: {
  children: React.ReactNode;
  locale?: "en" | "zh";
  translate?: (key: string, params?: Record<string, string | number>) => string;
}) {
  const [activeProject, setActiveProject] = useState(PROJECT_A);
  return (
    <I18nContext.Provider value={{ locale, setLocale: () => undefined, t: translate }}>
      <ProjectContext.Provider value={{
        activeProject,
        recentProjects: [PROJECT_A, PROJECT_B],
        setActiveProject,
        addRecent: () => undefined,
        removeRecent: () => undefined,
        deleteProjectData: async () => undefined,
      }}>
        <PipelineContext.Provider value={{ completed: [], isDone: () => false, currentStage: "triage", coreStages: [], isSkipped: () => false, markDone: () => undefined, markSkipped: () => undefined, reset: () => undefined }}>
          <TargetContext.Provider value={{ target: "", engine: "libfuzzer", lang: "c", compiled: false, selectionRepair: null, storageError: null, setTarget: () => undefined, setEngine: () => undefined, setLang: () => undefined, setCompiled: () => undefined, canResetTargetSelections: false, resetTargetSelections: () => undefined, retryStorage: () => undefined }}>
            <RunOutputContext.Provider value={{ log: [], stats: EMPTY_RUN_STATS, summary: { edges: 12, crashes: 1, execs: 40 }, running: false, cancelling: false, lastTarget: "latest_target", lastEngine: "libfuzzer", runFuzzer: async () => 0, runSyzkaller: async () => 0, cancelRun: async () => undefined, clear: () => undefined }}>
              <ToastContext.Provider value={{ toast: () => undefined }}>
                <ConfirmContext.Provider value={async () => true}>
                  <FindingSelectionProvider>
                    <button type="button" onClick={() => setActiveProject(PROJECT_B)}>switch project</button>
                    {children}
                  </FindingSelectionProvider>
                </ConfirmContext.Provider>
              </ToastContext.Provider>
            </RunOutputContext.Provider>
          </TargetContext.Provider>
        </PipelineContext.Provider>
      </ProjectContext.Provider>
    </I18nContext.Provider>
  );
}

function NavigationHost() {
  const [view, setView] = useState<"dashboard" | "triage">("dashboard");
  return view === "dashboard"
    ? <DashboardView onNavigate={(next) => setView(next === "triage" ? "triage" : "dashboard")} />
    : <TriageView />;
}

async function flush() {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}

describe("retained finding navigation", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;

  beforeEach(() => {
    invoke.mockReset();
    localStorage.clear();
    localStorage.setItem(FINDING_SELECTION_STORAGE_KEY, JSON.stringify({
      [PROJECT_A]: { findingId: older.crash.id, runId: older.crash.run_id },
      [PROJECT_B]: { findingId: projectB.crash.id, runId: projectB.crash.run_id },
    }));
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "finding_review_queue") return Promise.resolve(args?.project === PROJECT_B ? [projectB] : [newer, older]);
      if (command === "finding_review") {
        return Promise.resolve(args?.findingId === older.crash.id ? older : projectB);
      }
      throw new Error(`unexpected command ${command}`);
    });
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
  });

  it("restores exact historical evidence per project without starting work", async () => {
    await act(async () => root.render(<Providers><TriageView /></Providers>));
    await flush();
    expect(container.textContent).toContain("crash-input");
    expect(container.querySelector('[title="/evidence/older/crash-input"]')).not.toBeNull();
    expect(container.textContent).toContain("historical/parser.c:73");
    expect(container.textContent).toContain("parse_legacy_frame");

    const switchButton = [...container.querySelectorAll("button")].find((button) => button.textContent === "switch project");
    await act(async () => switchButton?.click());
    await flush();
    expect(container.querySelector('[title="/evidence/b/crash-input"]')).not.toBeNull();

    const commands = invoke.mock.calls.map(([command]) => command);
    expect(commands).toContain("finding_review_queue");
    expect(commands).toContain("finding_review");
    expect(commands).not.toContain("triage");
    expect(commands).not.toContain("generate_report");
    expect(commands).not.toContain("export_repro");
    expect(commands).not.toContain("push_to_defectdojo");
  });

  it("opens the exact dashboard finding in Triage", async () => {
    localStorage.removeItem(FINDING_SELECTION_STORAGE_KEY);
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "workbench_dashboard") return Promise.resolve({
        active_project: PROJECT_A,
        active_target: null,
        totals: { projects: 1, targets: 1, harnesses: 1, harnesses_needing_review: 0, runs: 2, active_runs: 0, crashes: 1, crashes_needing_triage: 1, corpus_entries: 0 },
        recent_runs: [], top_targets: [], harness_reviews: [],
        crash_reviews: [{ crash_id: older.crash.id, run_id: older.crash.run_id, target_id: older.target_id, target_symbol: older.target_symbol, kind: older.crash.kind, summary: older.crash.summary, severity: "Unclassified", minimized: true, has_bug_report: false, proof: older.proof, disposition: older.disposition }],
        readiness: { state: "active", score: 90, headline: "active", detail: "active", blockers: [], blocker_items: [] },
        next_actions: [], next_action_items: [],
      });
      if (command === "list_report_drafts") return Promise.resolve([]);
      if (command === "system_status_cmd") return Promise.resolve(null);
      if (command === "effective_auto_revert_policy") return Promise.reject(new Error("unconfigured"));
      if (command === "finding_review_queue") return Promise.resolve([newer, older]);
      if (command === "finding_review") return Promise.resolve(args?.findingId === older.crash.id ? older : newer);
      throw new Error(`unexpected command ${command}`);
    });

    await act(async () => root.render(<Providers><NavigationHost /></Providers>));
    await flush();
    const open = [...container.querySelectorAll("button")].find((button) => button.textContent?.includes("dashboard.openFinding"));
    expect(open).toBeDefined();
    await act(async () => open?.click());
    await flush();

    expect(container.querySelector('[title="/evidence/older/crash-input"]')).not.toBeNull();
    const detailCall = invoke.mock.calls.find(([command]) => command === "finding_review");
    expect(detailCall?.[1]).toMatchObject({ project: PROJECT_A, findingId: older.crash.id });
    expect(invoke.mock.calls.map(([command]) => command)).not.toContain("triage");
  });

  it("ignores late queue and detail responses from the previous project", async () => {
    let resolveQueueA: (items: FindingReviewItem[]) => void = () => undefined;
    let resolveDetailA: (item: FindingReviewItem) => void = () => undefined;
    const queueA = new Promise<FindingReviewItem[]>((resolve) => { resolveQueueA = resolve; });
    const detailA = new Promise<FindingReviewItem>((resolve) => { resolveDetailA = resolve; });
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "finding_review_queue") return args?.project === PROJECT_A ? queueA : Promise.resolve([projectB]);
      if (command === "finding_review") return args?.project === PROJECT_A ? detailA : Promise.resolve(projectB);
      throw new Error(`unexpected command ${command}`);
    });

    await act(async () => root.render(<Providers><TriageView /></Providers>));
    const switchButton = [...container.querySelectorAll("button")].find((button) => button.textContent === "switch project");
    await act(async () => switchButton?.click());
    await flush();
    expect(container.querySelector('[title="/evidence/b/crash-input"]')).not.toBeNull();

    await act(async () => {
      resolveQueueA([older]);
      resolveDetailA(older);
      await Promise.resolve();
    });
    expect(container.querySelector('[title="/evidence/b/crash-input"]')).not.toBeNull();
    expect(container.querySelector('[title="/evidence/older/crash-input"]')).toBeNull();
  });

  it("requests resolved history only after the explicit filter change", async () => {
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "finding_review_queue") {
        const filter = args?.filter as { disposition?: { mode?: string; value?: string } };
        return Promise.resolve(filter.disposition?.value === "resolved" ? [resolved] : [older]);
      }
      if (command === "finding_review") return Promise.resolve(args?.findingId === resolved.crash.id ? resolved : older);
      throw new Error(`unexpected command ${command}`);
    });
    await act(async () => root.render(<Providers><TriageView /></Providers>));
    await flush();
    const disposition = container.querySelector<HTMLSelectElement>('[aria-label="triage.filterDisposition"]');
    expect(disposition).not.toBeNull();
    await act(async () => {
      if (disposition) {
        disposition.value = "only:resolved";
        disposition.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    await flush();
    expect(container.textContent).toContain("resolved");
    expect(invoke.mock.calls.some(([command, args]) => command === "finding_review_queue" && args.filter.disposition.value === "resolved")).toBe(true);

    const resolvedRow = [...container.querySelectorAll("button")]
      .find((button) => button.textContent?.includes("resolved-crash summary"));
    await act(async () => resolvedRow?.click());
    await flush();
    expect(disposition?.value).toBe("only:resolved");
    expect(container.textContent).toContain("resolved-crash summary");
    expect(container.querySelector('[title="/evidence/resolved/crash-input"]')).not.toBeNull();
  });

  it("renders verification confidence, reproduction, and retained reasons", async () => {
    const verifiable = {
      ...newer,
      latest_scoped_actions_allowed: true,
      latest_scoped_action_reason: null,
    };
    localStorage.setItem(FINDING_SELECTION_STORAGE_KEY, JSON.stringify({
      [PROJECT_A]: { findingId: verifiable.crash.id, runId: verifiable.crash.run_id },
    }));
    invoke.mockImplementation((command: string) => {
      if (command === "finding_review_queue") return Promise.resolve([verifiable]);
      if (command === "finding_review") return Promise.resolve(verifiable);
      if (command === "verify_crash") return Promise.resolve({
        likely_target_bug: true,
        reproduces_deterministically: true,
        confidence: "high",
        reasons: ["distinctive retained verdict reason"],
      });
      throw new Error(`unexpected command ${command}`);
    });

    await act(async () => root.render(<Providers><TriageView /></Providers>));
    await flush();
    const verify = [...container.querySelectorAll("button")]
      .find((button) => button.textContent?.includes("triage.verifyCrash"));
    await act(async () => verify?.click());
    await flush();
    expect(container.textContent).toContain("distinctive retained verdict reason");
    expect(container.textContent).toContain("triage.confidence");
    expect(container.textContent).toContain("triage.reproduces");
  });

  it("keeps an exact selected finding visible outside the active queue filter", async () => {
    localStorage.setItem(FINDING_SELECTION_STORAGE_KEY, JSON.stringify({
      [PROJECT_A]: { findingId: resolved.crash.id, runId: resolved.crash.run_id },
    }));
    invoke.mockImplementation((command: string) => {
      if (command === "finding_review_queue") return Promise.resolve([]);
      if (command === "finding_review") return Promise.resolve(resolved);
      throw new Error(`unexpected command ${command}`);
    });

    await act(async () => root.render(<Providers><TriageView /></Providers>));
    await flush();

    expect(container.querySelector('[title="/evidence/resolved/crash-input"]')).not.toBeNull();
    expect(container.textContent).toContain("triage.noMatchingFindings");
  });

  it("does not expose latest-target actions while exact detail is pending or missing", async () => {
    let rejectDetail: (error: Error) => void = () => undefined;
    const pendingDetail = new Promise<FindingReviewItem>((_resolve, reject) => { rejectDetail = reject; });
    invoke.mockImplementation((command: string) => {
      if (command === "finding_review_queue") return Promise.resolve([]);
      if (command === "finding_review") return pendingDetail;
      throw new Error(`unexpected command ${command}`);
    });

    await act(async () => root.render(<Providers><TriageView /></Providers>));
    await flush();
    const reportButton = [...container.querySelectorAll("button")]
      .find((button) => button.textContent?.includes("triage.composeReport"));
    expect(reportButton?.disabled).toBe(true);

    await act(async () => {
      rejectDetail(new Error("deleted"));
      await Promise.resolve();
    });
    await flush();
    expect(reportButton?.disabled).toBe(true);
    expect(container.textContent).toContain("triage.findingUnavailable");
    expect(invoke.mock.calls.map(([command]) => command)).not.toContain("generate_report");
  });

  it("keeps a newer row selection while an earlier scan is pending", async () => {
    let resolveScan: (crashes: FindingReviewItem["crash"][]) => void = () => undefined;
    const pendingScan = new Promise<FindingReviewItem["crash"][]>((resolve) => { resolveScan = resolve; });
    invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "finding_review_queue") return Promise.resolve([older, newer]);
      if (command === "finding_review") return Promise.resolve(args?.findingId === newer.crash.id ? newer : older);
      if (command === "triage") return pendingScan;
      throw new Error(`unexpected command ${command}`);
    });

    await act(async () => root.render(<Providers><TriageView /></Providers>));
    await flush();
    const scan = [...container.querySelectorAll("button")]
      .find((button) => button.textContent?.includes("triage.scanForCrashes"));
    await act(async () => scan?.click());
    const newerRow = [...container.querySelectorAll("button")]
      .find((button) => button.textContent?.includes("newer-crash summary"));
    await act(async () => newerRow?.click());
    await flush();

    expect(container.querySelector('[title="/evidence/newer/crash-input"]')).not.toBeNull();
    expect(scan?.disabled).toBe(true);
    await act(async () => scan?.click());
    expect(invoke.mock.calls.filter(([command]) => command === "triage")).toHaveLength(1);

    await act(async () => {
      resolveScan([older.crash]);
      await Promise.resolve();
    });
    await flush();
    expect(container.querySelector('[title="/evidence/newer/crash-input"]')).not.toBeNull();
  });

  it("composes and saves a selected latest finding in the interface language", async () => {
    const selected = {
      ...newer,
      target_symbol: "selected_target",
      latest_scoped_actions_allowed: true,
      latest_scoped_action_reason: null,
    };
    localStorage.setItem(FINDING_SELECTION_STORAGE_KEY, JSON.stringify({
      [PROJECT_A]: { findingId: selected.crash.id, runId: selected.crash.run_id },
    }));
    invoke.mockImplementation((command: string) => {
      if (command === "finding_review_queue") return Promise.resolve([selected]);
      if (command === "finding_review") return Promise.resolve(selected);
      if (command === "generate_report") return Promise.resolve("# 中文分类报告");
      if (command === "save_report_draft") return Promise.resolve({ id: "draft-id" });
      throw new Error(`unexpected command ${command}`);
    });
    const translate = (key: string, params?: Record<string, string | number>) => (
      key === "reports.triageDraftTitle"
        ? `分类定级报告 — ${params?.target}`
        : key
    );

    await act(async () => root.render(<Providers locale="zh" translate={translate}><TriageView /></Providers>));
    await flush();
    const compose = [...container.querySelectorAll("button")]
      .find((button) => button.textContent?.includes("triage.composeReport"));
    await act(async () => compose?.click());
    await flush();

    expect(invoke.mock.calls.find(([command]) => command === "generate_report")?.[1]).toEqual({
      project: PROJECT_A,
      target: "selected_target",
      language: "zh",
      expectedRunId: "newer-run",
    });
    expect(invoke.mock.calls.find(([command]) => command === "save_report_draft")?.[1]).toMatchObject({
      title: "分类定级报告 — selected_target",
      project: PROJECT_A,
      target: "selected_target",
      status: "Draft",
      content: "# 中文分类报告",
    });
  });
});
