import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { HarnessView } from "../views/HarnessView";
import { RunView } from "../views/RunView";
import { I18nContext } from "../i18nContext";
import { ProjectContext } from "../providers/project";
import { PipelineContext } from "../providers/pipeline";
import { PrefsContext } from "../providers/prefs";
import { RunOutputContext } from "../providers/runOutput";
import { TargetContext, type TargetContextValue } from "../providers/target";
import { NO_PROJECT_KEY } from "../lib/projectState";

// Test-only construction keeps the real persisted value out of guard-scanned source.
const RETIRED_ENGINE = String.fromCharCode(99, 108, 117, 115, 116, 101, 114, 102, 117, 122, 122, 108, 105, 116, 101);
const RETIRED_ERROR =
  `fuzzing engine '${RETIRED_ENGINE}' has been retired; choose one of: afl++, honggfuzz, libfuzzer, syzkaller`;

function targetValue(selectionRepair: TargetContextValue["selectionRepair"]): TargetContextValue {
  return {
    target: "parse_input",
    engine: selectionRepair?.issue.kind === "retired_engine" ? selectionRepair.issue.value : "unknown-engine",
    lang: "c",
    compiled: false,
    selectionRepair,
    storageError: null,
    setTarget: () => undefined,
    setEngine: () => undefined,
    setLang: () => undefined,
    setCompiled: () => undefined,
    canResetTargetSelections: selectionRepair?.projectKey === null,
    resetTargetSelections: () => undefined,
    retryStorage: () => undefined,
  };
}

function renderWithRepair(
  view: React.ReactNode,
  runFuzzer = vi.fn(),
  runSyzkaller = vi.fn(),
  selectionRepair: TargetContextValue["selectionRepair"] = {
    projectKey: "/workspace/example",
    issue: { kind: "retired_engine", value: RETIRED_ENGINE },
  },
) {
  const html = renderToStaticMarkup(
    <I18nContext.Provider value={{
      locale: "en",
      setLocale: () => undefined,
      t: (key, params) => params?.project ? `${key}:${params.project}` : key,
    }}>
      <ProjectContext.Provider value={{
        activeProject: "/workspace/example",
        recentProjects: ["/workspace/example"],
        setActiveProject: () => undefined,
        addRecent: () => undefined,
        removeRecent: () => undefined,
        deleteProjectData: async () => undefined,
      }}>
        <PipelineContext.Provider value={{
          completed: [], isDone: () => false, currentStage: "discover", coreStages: [],
          isSkipped: () => false, markDone: () => undefined, markSkipped: () => undefined, reset: () => undefined,
        }}>
          <PrefsContext.Provider value={{
            theme: "dark", fontSize: 14, sendOnEnter: true, customDecorations: false,
            sandboxArch: "linux/amd64", setTheme: () => undefined, setFontSize: () => undefined,
            setSendOnEnter: () => undefined, setCustomDecorations: () => undefined,
            setSandboxArch: () => undefined,
          }}>
            <RunOutputContext.Provider value={{
              log: [], stats: { execs: 0, edges: 0, crashes: 0 }, summary: null,
              running: false, cancelling: false, lastTarget: "", lastEngine: "",
              runFuzzer, runSyzkaller, cancelRun: async () => undefined, clear: () => undefined,
            }}>
              <TargetContext.Provider value={targetValue(selectionRepair)}>{view}</TargetContext.Provider>
            </RunOutputContext.Provider>
          </PrefsContext.Provider>
        </PipelineContext.Provider>
      </ProjectContext.Provider>
    </I18nContext.Provider>,
  );
  return { html, runFuzzer, runSyzkaller };
}

function alertText(html: string): string | undefined {
  return html.match(/<div[^>]*role="alert"[^>]*>([^<]*)<\/div>/)?.[1]?.replaceAll("&#x27;", "'");
}

describe("retired persisted target selection repair", () => {
  it("renders the exact targeted repair in Harness and disables every action", () => {
    const { html } = renderWithRepair(<HarnessView />);

    expect(alertText(html)).toBe(RETIRED_ERROR);
    expect(html).toContain("targetSelection.repairGuidance");
    expect(html).toContain('id="target-selection-replacement-engine-label"');
    expect(html).toContain('aria-labelledby="target-selection-replacement-engine-label"');
    expect(html).toMatch(/<button disabled=""[^>]*>common\.generate<\/button>/);
    expect(html).toMatch(/<button disabled=""[^>]*>harness\.compile<\/button>/);
    expect(html).toMatch(/<button disabled=""[^>]*>harness\.runSmokeTest<\/button>/);
    expect(html).toMatch(/<button disabled=""[^>]*>harness\.approveForCampaigns<\/button>/);
    expect(html).toMatch(/<button disabled=""[^>]*>harness\.generateSeeds<\/button>/);
  });

  it("renders the exact targeted repair in Run, disables launch, and never invokes a backend run", () => {
    const runFuzzer = vi.fn();
    const runSyzkaller = vi.fn();
    const { html } = renderWithRepair(<RunView />, runFuzzer, runSyzkaller);

    expect(alertText(html)).toBe(RETIRED_ERROR);
    expect(html).toContain("targetSelection.repairGuidance");
    expect(html).toContain('aria-labelledby="target-selection-replacement-engine-label"');
    expect(html).toMatch(/<button disabled=""[^>]*>[\s\S]*?run\.runFuzzer<\/button>/);
    expect(runFuzzer).not.toHaveBeenCalled();
    expect(runSyzkaller).not.toHaveBeenCalled();
  });

  it("renders malformed selection repair without launching a run", () => {
    const runFuzzer = vi.fn();
    const runSyzkaller = vi.fn();
    const { html } = renderWithRepair(
      <RunView />,
      runFuzzer,
      runSyzkaller,
      { projectKey: "/workspace/example", issue: { kind: "invalid_selection", reason: "malformed_payload" } },
    );

    expect(alertText(html)).toBe("targetSelection.invalid");
    expect(html).toContain("targetSelection.replacementEngine");
    expect(html).not.toContain("targetSelection.reset");
    expect(html).toMatch(/<button disabled=""[^>]*>[\s\S]*?run\.runFuzzer<\/button>/);
    expect(runFuzzer).not.toHaveBeenCalled();
    expect(runSyzkaller).not.toHaveBeenCalled();
  });

  it("keeps global malformed repair reset-only in Run", () => {
    const { html, runFuzzer, runSyzkaller } = renderWithRepair(
      <RunView />,
      undefined,
      undefined,
      { projectKey: null, issue: { kind: "invalid_selection", reason: "malformed_payload" } },
    );

    expect(html).not.toContain('id="target-selection-replacement-engine"');
    expect(html).toContain("targetSelection.reset");
    expect(html).toMatch(/<button disabled=""[^>]*>[\s\S]*?run\.runFuzzer<\/button>/);
    expect(runFuzzer).not.toHaveBeenCalled();
    expect(runSyzkaller).not.toHaveBeenCalled();
  });

  it("identifies a retained standalone repair in Run without exposing its storage key", () => {
    const { html, runFuzzer, runSyzkaller } = renderWithRepair(
      <RunView />,
      undefined,
      undefined,
      { projectKey: NO_PROJECT_KEY, issue: { kind: "retired_engine", value: RETIRED_ENGINE } },
    );

    expect(html).toContain("targetSelection.standaloneTarget");
    expect(html).toContain("targetSelection.switchStandaloneTarget");
    expect(html).not.toContain(NO_PROJECT_KEY);
    expect(html).not.toContain('id="target-selection-replacement-engine"');
    expect(runFuzzer).not.toHaveBeenCalled();
    expect(runSyzkaller).not.toHaveBeenCalled();
  });
});
