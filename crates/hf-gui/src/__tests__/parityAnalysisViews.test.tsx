// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ConfirmContext } from "../providers/confirm";
import { CorpusView } from "../views/CorpusView";
import type * as LibModule from "../lib";

const mocks = vi.hoisted(() => ({ invoke: vi.fn(), concolic: { state: "available" } as unknown }));
vi.mock("../lib", async (importOriginal) => ({
  ...(await importOriginal<typeof LibModule>()),
  getTransport: () => ({ invoke: mocks.invoke }),
  isTauriEnvironment: () => false,
  onDataChanged: () => () => {},
}));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/proj" }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ target: "decode", lang: "rust", engine: "afl++" }) }));

let host: HTMLDivElement; let root: Root;
const flush = async () => act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
const button = (label: string) => {
  const found = [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === label);
  if (!found) throw new Error(`no button ${label}`);
  return found;
};
async function mount() {
  await act(async () => root.render(<I18nProvider><ConfirmContext.Provider value={async () => true}><CorpusView /></ConfirmContext.Provider></I18nProvider>));
  await flush(); await flush();
}
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  mocks.concolic = { state: "available" };
  mocks.invoke.mockReset();
  mocks.invoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "corpus_list": return [];
      case "corpus_capabilities": return { seed_survival: { available: true }, coverage_prune: { available: true }, minimize: { available: true } };
      case "concolic_availability": return mocks.concolic;
      case "coverage_summary": return null;
      case "corpus_afl_cmin": return { before: 9, after: 4, before_bytes: 90, after_bytes: 40 };
      case "corpus_regenerate_dead_seeds": return { removed_dead: 2, replacements_requested: 2, replacements_added: 2, replacement_survives: 1, replacement_dies_at_entry: 1, replacement_not_measured: 0 };
      case "corpus_absorb_crashes": return 3;
      case "corpus_concolic": return { inputs_explored: 5, inputs_skipped: 0, inputs_solved: 4, inputs_novel: 2, stop_reason: "Exhausted", corpus_size_before: 10, corpus_size_after: 12 };
      default: return null;
    }
  });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

it("runs afl-cmin, dead-seed regeneration, crash absorption and concolic enrichment from the corpus view", async () => {
  await mount();
  await act(async () => button("Minimize with afl-cmin").click()); await flush();
  expect(mocks.invoke).toHaveBeenCalledWith("corpus_afl_cmin", { project: "/proj", target: "decode" });
  expect(host.textContent).toContain("afl-cmin distilled 9 -> 4 entries (90 -> 40 bytes).");
  await act(async () => button("Regenerate dead seeds").click()); await flush();
  expect(mocks.invoke).toHaveBeenCalledWith("corpus_regenerate_dead_seeds", { project: "/proj", target: "decode", lang: "rust" });
  expect(host.textContent).toContain("Regenerated 2/2 dying seed(s); 2 replacement(s) written: 1 survive, 1 die at entry, 0 not measured.");
  await act(async () => button("Absorb crash inputs").click()); await flush();
  expect(mocks.invoke).toHaveBeenCalledWith("corpus_absorb_crashes", { project: "/proj", target: "decode" });
  expect(host.textContent).toContain("Absorbed 3 crash reproducer(s) into the corpus.");
  await act(async () => button("Concolic enrichment").click()); await flush();
  expect(mocks.invoke).toHaveBeenCalledWith("corpus_concolic", { project: "/proj", target: "decode" });
  expect(host.textContent).toContain("solver produced 4, 2 novel; corpus 10 -> 12 entries");
});

it("disables concolic enrichment with the service's reason when it is unavailable", async () => {
  mocks.concolic = { state: "unavailable", reason: "symcc_not_in_image" };
  await mount();
  expect(button("Concolic enrichment").disabled).toBe(true);
  expect(host.textContent).toContain("Concolic enrichment is unavailable: symcc_not_in_image");
});

it("keeps the corpus view usable when the optional commands are unknown", async () => {
  mocks.invoke.mockImplementation(async (command: string) => {
    if (command === "corpus_list") return [];
    if (command === "corpus_capabilities") return { seed_survival: { available: true }, coverage_prune: { available: true }, minimize: { available: true } };
    throw new Error(`unknown command ${command}`);
  });
  await mount();
  expect(host.textContent).toContain("Coverage");
  expect(button("Concolic enrichment").disabled).toBe(true);
});

it("wires the analysis surfaces into the views that own them", () => {
  const triage = readFileSync("src/views/TriageView.tsx", "utf8");
  expect(triage).toContain("<TriageParityPanel");
  expect(triage).toContain("<BisectPanel");
  const discover = readFileSync("src/views/DiscoverView.tsx", "utf8");
  expect(discover).toContain('{ value: "rust", label: "Rust" }');
  expect(discover).toContain("<SurfacePanels");
  expect(readFileSync("src/views/RunsView.tsx", "utf8")).toContain("<TrustReportPanel");
  const dashboard = readFileSync("src/views/DashboardView.tsx", "utf8");
  expect(dashboard).not.toContain("oxfuzz regress");
  expect(dashboard).toContain("parity.analysis.dashboard.openTriage");
});
