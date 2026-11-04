// @vitest-environment jsdom
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AgentsView, SkillsView, KnowledgeView } from "../views/FeatureViews";
import { I18nProvider } from "../i18n";

// A list that failed to load must not look like an empty list: the user would
// conclude there is nothing there and act on that.
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", () => ({ getTransport: () => ({ invoke }), pickFile: vi.fn(), pickFolder: vi.fn(), emitDataChanged: vi.fn() }));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/sample", recentProjects: ["/sample"] }) }));

let host: HTMLDivElement; let root: Root; let failing: boolean;
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  failing = true;
  invoke.mockReset();
  invoke.mockImplementation(async (command: string) => {
    if (["list_agents", "list_skills", "knowledge_summary"].includes(command) && failing) throw new Error("service unreachable");
    if (command === "list_agents") return [{ id: "a1", name: "Triage Analyst", description: "d", role: "triage", icon: null, system_prompt: "", allowed_tools: [], model_tags: [], temperature: null, max_iterations: 8, autonomy: "assist", capabilities: [], user_callable: true, skills: [], trust_tier: "user-defined" }];
    if (command === "list_skills") return [{ name: "corpus-curation", version: "1", description: "Curates corpora", domain: [], body: "", max_input_tokens: 2000, trust_tier: "user-defined" }];
    if (command === "knowledge_summary") return { db_configured: true, targets: [{ symbol: "parse_value", kind: "Function", fit_score: 0.8, project: "/sample", location: "a.c:1" }], runs: [], crashes: [] };
    if (command === "knowledge_stats") return { indexed: false, files: 0, chunks: 0, documents: 0, legacy_documents_preserved: false, indexed_at: null, effective: { retrieval_strategy: "keyword", chunk_max_tokens: 512, embedding_model: null, embedding_dimensions: null }, configured: { retrieval_strategy: "keyword", chunk_max_tokens: 512, embedding_model: null, embedding_dimensions: null }, stale: false, warnings: [] };
    if (command === "agent_tools") return [];
    return null;
  });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); Reflect.deleteProperty(window, "__TAURI_INTERNALS__"); });

async function render(view: ReactNode) {
  await act(async () => root.render(<I18nProvider>{view}</I18nProvider>));
  await act(async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); });
}
async function retry() {
  failing = false;
  await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent === "Retry")!.click());
  await act(async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); });
}

it.each([
  ["agents", <AgentsView key="a" />, "Could not load agents", "No agents found", "Triage Analyst"],
  ["skills", <SkillsView key="s" />, "Could not load skills", "No skills yet", "corpus-curation"],
])("shows a %s load failure with Retry instead of an empty list", async (_name, view, failure, empty, loaded) => {
  await render(view);
  expect(host.textContent).toContain(failure);
  expect(host.textContent).toContain("service unreachable");
  expect(host.textContent).not.toContain(empty);
  await retry();
  expect(host.textContent).toContain(loaded);
  expect(host.textContent).not.toContain(failure);
});

it("shows a desktop knowledge summary failure with Retry", async () => {
  Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });
  await render(<KnowledgeView />);
  expect(host.textContent).toContain("Could not load what oxfuzz has learned");
  await retry();
  expect(host.textContent).toContain("parse_value");
});
