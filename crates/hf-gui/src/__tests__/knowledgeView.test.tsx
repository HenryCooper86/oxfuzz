// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { KnowledgeView } from "../views/FeatureViews";
import { I18nProvider } from "../i18n";
import { ProjectContext } from "../providers/project";

const io = vi.hoisted(() => ({ invoke: vi.fn(), pick: vi.fn() }));
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke: io.invoke }), pickFile: io.pick }));
vi.mock("../lib/transport", async () => ({ ...await vi.importActual("../lib/transport"), isTauriEnvironment: () => true }));
const config = { retrieval_strategy: "keyword", chunk_max_tokens: 450, embedding_model: null, embedding_dimensions: null };
const status = { indexed: true, files: 3, chunks: 6, documents: 0, legacy_documents_preserved: false,
  indexed_at: "2026-11-10T01:00:00Z", configured: config, effective: config as typeof config | null, stale: false, warnings: [] };
const hit = { file: "parser.c", score: 1, snippet: "old_project_symbol" };
const summary = { db_configured: true, targets: [], runs: [], crashes: [] };
let host: HTMLDivElement;
let root: Root;
let overrides: Record<string, (() => unknown) | undefined>;
const button = (label: string) => [...host.querySelectorAll("button")].find(item => item.textContent?.trim() === label)!;
async function click(label: string) { expect(button(label)).toBeDefined(); await act(async () => button(label).click()); }
async function query(value: string) {
  const input = host.querySelector<HTMLInputElement>('input')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function render(project = "/first") {
  await act(async () => root.render(<I18nProvider><ProjectContext.Provider value={{
    activeProject: project, recentProjects: [], setActiveProject: () => {}, addRecent: () => {}, removeRecent: () => {}, deleteProjectData: async () => {},
  }}><KnowledgeView /></ProjectContext.Provider></I18nProvider>));
}
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.clear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  overrides = {}; io.invoke.mockReset(); io.pick.mockReset();
  io.invoke.mockImplementation(async (command: string) => {
    if (overrides[command]) return overrides[command]!();
    if (command === "knowledge_summary") return summary;
    if (command === "knowledge_stats") return status;
    if (command === "knowledge_search") return [hit];
    if (command === "knowledge_index" || command === "knowledge_ingest") return { files: 3, chunks: 6, updated_entries: 1, reused_entries: 2, removed_entries: 0 };
    throw new Error(command);
  });
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

it("removes old project search results immediately when the active project changes", async () => {
  await render(); await query("parser"); await click("Search");
  expect(host.textContent).toContain(hit.snippet);
  await render("/second");
  expect(host.textContent).not.toContain(hit.snippet);
});
it("discards a search response from a project that is no longer selected", async () => {
  let finish!: (value: typeof hit[]) => void;
  overrides.knowledge_search = () => new Promise(resolve => { finish = resolve; });
  await render(); await query("parser"); await click("Search");
  await render("/second"); await act(async () => finish([hit]));
  expect(host.textContent).not.toContain(hit.snippet);
});
it("clears results when the query is edited", async () => {
  await render(); await query("parser"); await click("Search"); await query("other");
  expect(host.textContent).not.toContain(hit.snippet);
});
it("discards a late result for a superseded query", async () => {
  let finish!: (value: typeof hit[]) => void;
  overrides.knowledge_search = () => new Promise(resolve => { finish = resolve; });
  await render(); await query("parser"); await click("Search"); await query("other");
  await act(async () => finish([hit]));
  expect(host.textContent).not.toContain(hit.snippet);
  expect(button("Search").disabled).toBe(false);
});
it("shows an initial index status failure and lets a status check recover", async () => {
  overrides.knowledge_stats = () => Promise.reject(new Error("index service unavailable"));
  await render();
  expect(host.textContent).toContain("index service unavailable");
  delete overrides.knowledge_stats; await click("Check index status");
  expect(host.textContent).not.toContain("index service unavailable");
  expect(host.querySelector<HTMLInputElement>("input")?.disabled).toBe(false);
});
it("does not retain a fresh-index claim after its status check fails", async () => {
  await render();
  overrides.knowledge_stats = () => Promise.reject(new Error("status connection lost"));
  await click("Check index status");
  expect(host.textContent).toContain("status connection lost");
  expect(host.textContent).not.toContain("Index matches current sources");
});
it("ignores an initial status response after a newer status check", async () => {
  let finish!: (value: typeof status) => void;
  overrides.knowledge_stats = () => new Promise(resolve => { finish = resolve; });
  await render(); delete overrides.knowledge_stats;
  await click("Check index status");
  await act(async () => finish({ ...status, indexed: false, effective: null }));
  expect(host.querySelector<HTMLInputElement>("input")?.disabled).toBe(false);
});
it("discards index failures from a previously selected project", async () => {
  let fail!: (error: Error) => void;
  overrides.knowledge_index = () => new Promise((_, reject) => { fail = reject; });
  await render(); await click("Index project"); await render("/second");
  await act(async () => fail(new Error("old project failed")));
  expect(host.textContent).not.toContain("old project failed");
});
it("does not ingest a picked document after its project has changed", async () => {
  let finish!: (file: string) => void;
  io.pick.mockReturnValue(new Promise(resolve => { finish = resolve; }));
  await render(); await click("Add document"); await render("/second");
  await act(async () => finish("/documents/spec.pdf"));
  expect(io.invoke.mock.calls.filter(([command]) => command === "knowledge_ingest")).toHaveLength(0);
});
it("handles file picker errors without leaving an unhandled rejection", async () => {
  io.pick.mockRejectedValue(new Error("picker unavailable"));
  await render(); await click("Add document");
  expect(host.textContent).toContain("picker unavailable");
});
it("prevents old summary reads from replacing a newer refresh", async () => {
  let finish!: (value: typeof summary) => void;
  overrides.knowledge_summary = () => new Promise(resolve => { finish = resolve; });
  await render();
  overrides.knowledge_summary = () => ({ ...summary, runs: [{ id: "run", project: "/first", engine: "retained-new-run", status: "Done", started_at: "2026-11-10T01:00:00Z" }] });
  await click("Refresh"); await act(async () => finish(summary));
  expect(host.textContent).toContain("retained-new-run");
});

it("discloses the database summary display limit instead of implying every row is visible", async () => {
  overrides.knowledge_summary = () => ({ ...summary, runs: Array.from({ length: 41 }, (_, index) => ({
    id: String(index), project: "/first", engine: `engine-${index}`, status: "Done", started_at: "2026-11-10T01:00:00Z",
  })) });
  await render();
  expect(host.textContent).toContain("Showing 40 of 41");
  expect(host.textContent).not.toContain("engine-40");
});
