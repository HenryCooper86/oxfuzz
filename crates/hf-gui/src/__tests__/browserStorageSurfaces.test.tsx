// @vitest-environment jsdom

import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KnowledgeView } from "../views/FeatureViews";
import { StorageTab } from "../components/settings/StorageTab";
import { I18nProvider } from "../i18n";
import { ProjectContext } from "../providers/project";
import { ConfirmContext } from "../providers/confirm";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", () => ({ getTransport: () => ({ invoke }), pickFile: vi.fn(), pickFolder: vi.fn(), emitDataChanged: vi.fn() }));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let indexed: boolean;
let cleared: boolean;
let workspaceCleared: boolean;
let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  localStorage.clear();
  Reflect.deleteProperty(window, "__TAURI_INTERNALS__");
  indexed = false;
  cleared = false;
  workspaceCleared = false;
  invoke.mockReset();
  invoke.mockImplementation(async (command, args) => {
    if (command === "knowledge_stats") return {
      indexed, files: indexed ? 3 : 0, chunks: indexed ? 8 : 0, documents: 0,
      legacy_documents_preserved: false, indexed_at: null,
      effective: { retrieval_strategy: "keyword", chunk_max_tokens: 512, embedding_model: null, embedding_dimensions: null },
      configured: { retrieval_strategy: "keyword", chunk_max_tokens: 512, embedding_model: null, embedding_dimensions: null },
      stale: false, warnings: [],
    };
    if (command === "knowledge_index") {
      if (args.project !== "/sample") throw new Error("wrong project");
      indexed = true;
      return { files: 3, chunks: 8 };
    }
    if (command === "knowledge_search") {
      if (args.project !== "/sample" || args.query !== "parser") throw new Error("wrong search");
      return [{ file: "src/parser.c", score: 0.75, snippet: "parse_header consumes the supplied bytes" }];
    }
    if (command === "knowledge_summary") return {
      db_configured: true, targets: cleared ? [] : [{ symbol: "retained_parser", kind: "Function", fit_score: 0.8, project: "/sample", location: "parser.c:1" }], runs: [], crashes: [],
    };
    if (command === "clear_knowledge") { cleared = true; return null; }
    if (command === "app_paths") return { config_dir: "/config", data_dir: "/data", workspace_dir: "/workspace" };
    if (command === "clear_workspace") { workspaceCleared = true; return null; }
    throw new Error(`Unexpected command: ${command}`);
  });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  localStorage.clear();
  Reflect.deleteProperty(window, "__TAURI_INTERNALS__");
});

async function mount(view: ReactNode, locale = "en") {
  localStorage.setItem("hf_locale", locale);
  await act(async () => root.render(<I18nProvider>
    <ProjectContext.Provider value={{ activeProject: "/sample", recentProjects: ["/sample"], setActiveProject: () => undefined, addRecent: () => undefined, removeRecent: () => undefined, deleteProjectData: async () => undefined }}>
      <ConfirmContext.Provider value={async () => true}>{view}</ConfirmContext.Provider>
    </ProjectContext.Provider>
  </I18nProvider>));
}

async function click(label: string) {
  const button = [...container.querySelectorAll("button")].find(item => item.textContent === label);
  if (!button) throw new Error(`Missing action: ${label}`);
  await act(async () => button.click());
}

describe("browser storage capabilities", () => {
  it.each(["en", "zh"])("explains desktop-only global knowledge controls in %s while preserving project indexing", async locale => {
    await mount(<KnowledgeView />, locale);

    expect(container.querySelector('[role="note"]')?.textContent).toContain(locale === "en" ? "desktop app" : "桌面应用");
    expect([...container.querySelectorAll("button")].some(button => button.textContent === (locale === "en" ? "Clear" : "清空"))).toBe(false);
    expect(invoke.mock.calls.some(([command]) => command === "knowledge_summary")).toBe(false);
    await click(locale === "en" ? "Index project" : "索引项目");
    expect(container.textContent).toContain(locale === "en" ? "indexed 3 files" : "已索引 3 个文件");
  });

  it("keeps project knowledge search usable in the browser", async () => {
    indexed = true;
    await mount(<KnowledgeView />);
    const input = container.querySelector("input")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "parser");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("Search");

    expect(container.textContent).toContain("src/parser.c");
    expect(container.textContent).toContain("parse_header consumes the supplied bytes");
  });

  it.each(["en", "zh"])("explains server-managed workspace storage in %s without a nonfunctional cleanup control", async locale => {
    await mount(<StorageTab />, locale);

    expect(container.querySelector('[role="note"]')?.textContent).toContain(locale === "en" ? "desktop app" : "桌面应用");
    expect(container.querySelector("input")).toBeNull();
    expect(container.querySelector("button")).toBeNull();
    expect(invoke.mock.calls.some(([command]) => command === "app_paths" || command === "clear_workspace")).toBe(false);
  });

  it("preserves desktop summary and explicitly confirmed global knowledge cleanup", async () => {
    Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });
    await mount(<KnowledgeView />);
    expect(container.textContent).toContain("retained_parser");
    await click("Clear");
    expect(container.textContent).not.toContain("retained_parser");
    expect(container.textContent).toContain("Nothing learned yet");
  });

  it("preserves desktop workspace location and two-step cleanup", async () => {
    Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });
    await mount(<StorageTab />);
    expect(container.querySelector("input")?.value).toBe("/workspace");
    await click("Clear Workspace");
    expect(workspaceCleared).toBe(false);
    await click("Click again to confirm");
    expect(workspaceCleared).toBe(true);
  });
});
