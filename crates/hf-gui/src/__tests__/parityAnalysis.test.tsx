// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { BisectPanel } from "../components/BisectPanel";
import { CoverageSummaryPanel } from "../components/CoverageSummaryPanel";
import { RunComparison } from "../components/RunComparison";
import { SurfacePanels } from "../components/SurfacePanels";
import { TriageParityPanel } from "../components/TriageParityPanel";
import { TrustReportPanel } from "../components/TrustReportPanel";
import { enParityAnalysis, zhParityAnalysis } from "../i18n.parityAnalysis";
import type * as LibModule from "../lib";

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", async (importOriginal) => ({
  ...(await importOriginal<typeof LibModule>()),
  getTransport: () => ({ invoke: mocks.invoke }),
}));

let host: HTMLDivElement;
let root: Root;
const flush = async () => act(async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); });
async function mount(node: React.ReactNode) {
  await act(async () => root.render(<I18nProvider>{node}</I18nProvider>));
  await flush();
}
function button(label: string): HTMLButtonElement {
  const found = [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === label);
  if (!found) throw new Error(`no button ${label}: ${host.textContent}`);
  return found;
}
async function click(label: string) { await act(async () => button(label).click()); await flush(); }
async function type(input: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  mocks.invoke.mockReset();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

it("has a Chinese string for every English analysis string", () => {
  expect(Object.keys(zhParityAnalysis).sort()).toEqual(Object.keys(enParityAnalysis).sort());
  for (const value of Object.values(zhParityAnalysis)) expect(value.trim()).not.toBe("");
});

it("bisects a crash with HEAD as the default bad revision and renders steps and the first bad commit", async () => {
  mocks.invoke.mockResolvedValue({
    good: "a".repeat(40), bad: "b".repeat(40), candidates: 3,
    result: { kind: "first_bad", commit: "c".repeat(40), subject: "parser: drop bounds check" },
    steps: [{ commit: "d".repeat(40), verdict: "good", note: "" }, { commit: "c".repeat(40), verdict: "bad", note: "" }, { commit: "e".repeat(40), verdict: "skip", note: "build failed" }],
  });
  await mount(<BisectPanel project="/p" target="decode" crashId="crash-1" />);
  expect(button("Bisect").disabled).toBe(true);
  await type(host.querySelector('input[aria-label="Known-good revision"]')!, " v1.0 ");
  await click("Bisect");
  expect(mocks.invoke).toHaveBeenCalledWith("bisect_crash", { project: "/p", target: "decode", crashId: "crash-1", good: "v1.0", bad: "HEAD" });
  const report = host.querySelector('[data-testid="bisect-report"]')!.textContent!;
  expect(report).toContain("Bisected 3 commit(s)");
  expect(report).toContain("skip eeeeeeeeeeee  build failed");
  expect(report).toContain(`First commit at which the input crashes: ${"c".repeat(40)}`);
  expect(report).toContain("parser: drop bounds check");
});

it("shows an undecided bisection and a failed one", async () => {
  mocks.invoke.mockResolvedValueOnce({ good: "a", bad: "b", candidates: 2, steps: [], result: { kind: "undecided", commits: ["x1", "x2"] } });
  await mount(<BisectPanel project="/p" target="decode" crashId="crash-1" />);
  await type(host.querySelector('input[aria-label="Known-good revision"]')!, "v1");
  await type(host.querySelector('input[aria-label="Bad revision (default HEAD)"]')!, "v2");
  await click("Bisect");
  expect(mocks.invoke).toHaveBeenCalledWith("bisect_crash", expect.objectContaining({ bad: "v2" }));
  expect(host.textContent).toContain("Undecided: the first crashing commit is one of these 2");
  mocks.invoke.mockRejectedValueOnce("not a git repository");
  await click("Bisect");
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("not a git repository");
});

it("runs AI triage with the chosen model policy and reloads the queue", async () => {
  mocks.invoke.mockResolvedValue([{ id: "c1" }, { id: "c2" }]);
  const reload = vi.fn();
  await mount(<TriageParityPanel project="/p" target="decode" disabled={false} onTriaged={reload} />);
  const select = host.querySelector("select")!;
  await act(async () => { select.value = "require"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  await click("AI triage");
  expect(mocks.invoke).toHaveBeenCalledWith("triage", { project: "/p", target: "decode", ai: "require" });
  expect(host.textContent).toContain("AI triage finished: 2 finding(s).");
  expect(reload).toHaveBeenCalledTimes(1);
});

it("renders each stored-crash replay result with the CLI's counts", async () => {
  mocks.invoke.mockResolvedValue([
    { crash_id: "aaaaaaaa1111", input: "crash-1", still_crashes: true, verified: true, summary: "SEGV" },
    { crash_id: "bbbbbbbb2222", input: "crash-2", still_crashes: false, verified: true, summary: "clean exit" },
    { crash_id: "", input: "crash-3", still_crashes: false, verified: false, summary: "sandbox down" },
  ]);
  await mount(<TriageParityPanel project="/p" target="decode" disabled={false} onTriaged={() => {}} />);
  await click("Replay stored crashes (regression check)");
  expect(mocks.invoke).toHaveBeenCalledWith("verify_regressions", { project: "/p", target: "decode" });
  const text = host.querySelector('[data-testid="regression-results"]')!.textContent!;
  expect(text).toContain("Replayed 3 crash(es): 1 still crashing, 1 no longer crashing, 1 inconclusive.");
  expect(text).toContain("[STILL CRASHES] aaaaaaaa crash-1 -- SEGV");
  expect(text).toContain("[NO CRASH ON REPLAY] bbbbbbbb crash-2 -- clean exit");
  expect(text).toContain("[INCONCLUSIVE]  crash-3 -- sandbox down");
});

it("says so when there are no stored crashes and keeps the buttons off without a target", async () => {
  mocks.invoke.mockResolvedValue([]);
  await mount(<TriageParityPanel project="/p" target="decode" disabled={false} onTriaged={() => {}} />);
  await click("Replay stored crashes (regression check)");
  expect(host.textContent).toContain("No stored crashes to replay.");
  await mount(<TriageParityPanel project="/p" target="" disabled={false} onTriaged={() => {}} />);
  expect(button("AI triage").disabled).toBe(true);
});

it("shows coverage percentages and saves both line report formats", async () => {
  mocks.invoke.mockImplementation(async (command: string, args: { format?: string }) => {
    if (command === "coverage_summary") return { lines_covered: 50, lines_total: 200, line_percent: 25, functions_covered: 3, functions_total: 4, function_percent: 75, regions_covered: 0, regions_total: 0, region_percent: 0 };
    if (command === "export_coverage_line_report") return { path: args.format === "lcov" ? "/out/t.lcov.info" : null, lines_hit: 50, lines_total: 200, files: 2, skipped_files: 0 };
    return null;
  });
  await mount(<CoverageSummaryPanel project="/p" target="decode" />);
  expect(host.textContent).toContain("50 / 200 (25.0%)");
  expect(host.textContent).toContain("3 / 4 (75.0%)");
  await click("Save lcov");
  expect(mocks.invoke).toHaveBeenCalledWith("export_coverage_line_report", { project: "/p", target: "decode", format: "lcov" });
  expect(host.textContent).toContain("Saved /out/t.lcov.info: 50/200 lines hit across 2 file(s).");
  await click("Save HTML report");
  expect(mocks.invoke).toHaveBeenCalledWith("export_coverage_line_report", { project: "/p", target: "decode", format: "html" });
  expect(host.textContent).toContain("Save cancelled.");
});

it("explains an unmeasured target instead of showing zeros", async () => {
  mocks.invoke.mockResolvedValue(null);
  await mount(<CoverageSummaryPanel project="/p" target="decode" />);
  expect(host.textContent).toContain("No coverage can be measured yet");
  expect(host.textContent).not.toContain("0.0%");
});

it("lists unreached entry points and attribution from cached measurements, stating nothing is run", async () => {
  mocks.invoke.mockImplementation(async (command: string) => command === "unreached_surface"
    ? { measurement: { state: "retained", measurements: 2 }, candidates: [{ symbol: "parse_hdr", discovery_score: 0.9, attempt: { state: "attempted_smoke_failed", attempts: 1 } }] }
    : { measurement: { state: "retained", measurements: 2 }, candidates: [{ symbol: "parse_hdr", discovery_score: 0.9, covered_share: 0.5, tier: { tier: "partial", covered: 1, total: 2 } }, { symbol: "init", discovery_score: 0.1, covered_share: 0, tier: { tier: "untouched" } }] });
  await mount(<SurfacePanels project="/p" lang="rust" />);
  expect(mocks.invoke).toHaveBeenCalledWith("unreached_surface", { project: "/p", lang: "rust" });
  expect(mocks.invoke).toHaveBeenCalledWith("coverage_attribution", { project: "/p", lang: "rust" });
  const text = host.textContent!;
  expect(text).toContain("Unreached entry points");
  expect(text).toContain("Coverage attribution");
  expect(text).toContain("Reads cached coverage measurements only");
  expect(text).toContain("smoke failed");
  expect(text).toContain("partial 1/2");
  expect(text).toContain("untouched");
});

it("reports a missing measurement and tolerates a failing command", async () => {
  mocks.invoke.mockImplementation(async (command: string) => {
    if (command === "unreached_surface") return { measurement: { state: "unavailable", reason: "no_completed_coverage_measurement" }, candidates: [] };
    throw new Error("unknown command");
  });
  await mount(<SurfacePanels project="/p" lang="c" />);
  expect(host.textContent).toContain("No coverage measurement is retained for this project (no_completed_coverage_measurement)");
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("unknown command");
});

it("shows the trust determination, each gate and the claims not licensed", async () => {
  mocks.invoke.mockResolvedValue({
    run_id: "r1", determination: "qualified", unlicensed_claims: ["findings_worth_reporting"],
    gates: [{ claim: "fuzzer_ran", verdict: "supported", detail: "run ended cleanly" }, { claim: "findings_worth_reporting", verdict: "unsupported", detail: "no triaged finding" }],
  });
  await mount(<TrustReportPanel runId="r1" />);
  await click("Show trust report");
  expect(mocks.invoke).toHaveBeenCalledWith("campaign_trust_report", { runId: "r1" });
  const text = host.querySelector('[data-testid="trust-report"]')!.textContent!;
  expect(text).toContain("Qualified");
  expect(text).toContain("Fuzzer ran: supported -- run ended cleanly");
  expect(text).toContain("Findings worth reporting: not established -- no triaged finding");
  expect(text).toContain("Claims not licensed: Findings worth reporting");
});

it("captures a run's edge set and says when it was already retained", async () => {
  mocks.invoke.mockResolvedValue({ run_id: "r1", binary_sha256: "s", inputs: 12, edges: 340, collected_at: "now", already_retained: false });
  await mount(<TrustReportPanel runId="r1" />);
  await click("Capture edge set");
  expect(mocks.invoke).toHaveBeenCalledWith("capture_run_edges", { runId: "r1" });
  expect(host.textContent).toContain("Captured 340 edge(s) from 12 input(s).");
  mocks.invoke.mockResolvedValue({ run_id: "r1", binary_sha256: "s", inputs: 12, edges: 340, collected_at: "now", already_retained: true });
  await click("Capture edge set");
  expect(host.textContent).toContain("nothing was re-measured");
});

const assessment = { baseline_id: "a", result_id: "b", comparable: true, reason: "comparable", setup_matches: true, harness_changed: false, binary_changed: false, edge_delta: "5" };
it("compares edge sets of two runs and renders counts and capped samples", async () => {
  mocks.invoke.mockImplementation(async (command: string) => command === "run_comparison" ? assessment
    : { run_a: "a", run_b: "b", same_binary: true, edges_a: 10, edges_b: 15, only_a: 1, only_b: 6, common: 9, union: 16, only_a_sample: [4], only_b_sample: [11, 12], sample_cap: 64 });
  await mount(<RunComparison baselineId="a" resultId="b" />);
  await click("Compare edge sets");
  expect(mocks.invoke).toHaveBeenCalledWith("run_edge_diff", { baselineId: "a", resultId: "b" });
  const text = host.querySelector('[data-testid="edge-set-diff"]')!.textContent!;
  expect(text).toContain("Lost 1, gained 6, shared 9, union 16.");
  expect(text).toContain("Lost (first 64): 4");
  expect(text).toContain("Gained (first 64): 11, 12");
});

it("shows the service's explanation when a run has no captured edge set", async () => {
  mocks.invoke.mockImplementation(async (command: string) => {
    if (command === "run_comparison") return assessment;
    throw new Error("run 'b' has no captured edge set; capture one first");
  });
  await mount(<RunComparison baselineId="a" resultId="b" />);
  await click("Compare edge sets");
  expect(host.querySelector('[data-testid="edge-set-diff"] [role="alert"]')?.textContent).toContain("has no captured edge set");
});
