// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ProjectContext } from "../providers/project";
import { NotificationsTab } from "../components/settings/NotificationsTab";
import { ObservabilityPanel } from "../components/observation/ObservabilityPanel";
import { IssueDraft } from "../components/IssueDraft";
import { AuditView } from "../views/AuditView";
import { KnowledgeView } from "../views/FeatureViews";

const io = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke: io.invoke }), openExternal: vi.fn() }));
vi.mock("../lib/transport", async () => ({ ...await vi.importActual("../lib/transport"), isTauriEnvironment: () => true }));

let host: HTMLDivElement;
let root: Root;
const button = (label: string) => [...host.querySelectorAll("button")].find(item => item.textContent?.trim() === label);
async function click(label: string) { expect(button(label), `button ${label}`).toBeDefined(); await act(async () => button(label)!.click()); }
async function edit(input: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function render(node: React.ReactNode, project = "/proj") {
  await act(async () => root.render(<I18nProvider><ProjectContext.Provider value={{
    activeProject: project, recentProjects: [], setActiveProject: () => {}, addRecent: () => {}, removeRecent: () => {}, deleteProjectData: async () => {},
  }}>{node}</ProjectContext.Provider></I18nProvider>));
}
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.clear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  io.invoke.mockReset();
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

function notificationsMock(extra: Record<string, () => unknown> = {}) {
  io.invoke.mockImplementation(async (command: string) => {
    if (extra[command]) return extra[command]();
    switch (command) {
      case "read_config": return "webhook_url = \"https://hooks.example.test/a\"\nbearer_token = \"s3cret-token\"\n";
      case "config_toml_to_value": return { webhook_url: "https://hooks.example.test/a", bearer_token: "s3cret-token", format: "json", verify_tls: true };
      case "config_value_to_toml": return "toml-out";
      case "write_config": return null;
      case "schedule_targets": return [{ target: "parse", engine: "afl++", language: "c", fit_score: 1 }];
      default: throw new Error(command);
    }
  });
}

it("loads the notifications section without echoing the token and saves a kept token unchanged", async () => {
  notificationsMock();
  await render(<NotificationsTab />);
  expect(host.textContent).not.toContain("s3cret-token");
  expect(host.textContent).toContain("Configured");
  await edit(host.querySelector<HTMLInputElement>('input[aria-label="Webhook URL"]')!, "https://hooks.example.test/b");
  await click("Save");
  const toml = io.invoke.mock.calls.find(([c]) => c === "config_value_to_toml")![1] as { value: Record<string, unknown> };
  expect(toml.value).toMatchObject({ webhook_url: "https://hooks.example.test/b", bearer_token: "s3cret-token", format: "json", verify_tls: true });
  expect(io.invoke).toHaveBeenCalledWith("read_config", { name: "notifications" });
  expect(io.invoke).toHaveBeenCalledWith("write_config", { name: "notifications", content: "toml-out" });
});

it("sends a test message and reports a failure inline", async () => {
  notificationsMock({ notifications_test: () => Promise.reject(new Error("webhook refused")) });
  await render(<NotificationsTab />);
  await click("Send test message");
  expect(io.invoke).toHaveBeenCalledWith("notifications_test");
  expect(host.textContent).toContain("webhook refused");
});

it("sends an alert for a target's latest run and reports how many crashes were sent", async () => {
  notificationsMock({ notify_latest_run: () => 2 });
  await render(<NotificationsTab />);
  await edit(host.querySelector<HTMLInputElement>('input[aria-label="Target"]')!, "parse");
  await click("Send alert");
  expect(io.invoke).toHaveBeenCalledWith("notify_latest_run", { project: "/proj", target: "parse" });
  expect(host.textContent).toContain("2 crashes");
});

it("thaws a frozen provider and refreshes the snapshot", async () => {
  const provider = (frozen: boolean) => ({ id: "p1", model: "m", tags: [], is_frozen: frozen, active_requests: 0, max_concurrency: 1, total_requests: 0, total_errors: 0, error_rate: 0, total_input_tokens: 0, total_output_tokens: 0, estimated_cost_usd: 0 });
  let frozen = true;
  io.invoke.mockImplementation(async (command: string) => {
    if (command === "system_snapshot") return { providers: [provider(frozen)], agents: { active_instances: 0, registered_definitions: 0, total_instances: 0, instances: [] }, memory: { pending_runs: 0, interrupted_runs: 0, llm_calls: 0, targets: 0, crashes: 0 } };
    if (command === "thaw_provider") { frozen = false; return null; }
    throw new Error(command);
  });
  await render(<ObservabilityPanel />);
  await click("Thaw");
  expect(io.invoke).toHaveBeenCalledWith("thaw_provider", { providerId: "p1" });
  expect(button("Thaw")).toBeUndefined();
});

it("shows the thaw health-check error inline", async () => {
  io.invoke.mockImplementation(async (command: string) => {
    if (command === "system_snapshot") return { providers: [{ id: "p1", model: "m", tags: [], is_frozen: true, active_requests: 0, max_concurrency: 1, total_requests: 0, total_errors: 0, error_rate: 0, total_input_tokens: 0, total_output_tokens: 0, estimated_cost_usd: 0 }], agents: { active_instances: 0, registered_definitions: 0, total_instances: 0, instances: [] }, memory: { pending_runs: 0, interrupted_runs: 0, llm_calls: 0, targets: 0, crashes: 0 } };
    throw new Error("health check failed");
  });
  await render(<ObservabilityPanel />);
  await click("Thaw");
  expect(host.textContent).toContain("health check failed");
});

it("labels a Jira draft Jira", async () => {
  await render(<IssueDraft project="/p" draft={{ crash_id: "c", title: "t", description: "d", labels: [], provider: "jira", project_web_url: "https://jira.example.test", issue_url: null, can_file: true }} />);
  expect(host.textContent).toContain("Jira");
  expect(host.textContent).toContain("Jira issue");
});

it("loads the audit trail with the chosen limit", async () => {
  io.invoke.mockImplementation(async () => []);
  await render(<AuditView />);
  expect(io.invoke).toHaveBeenCalledWith("policy_decisions", { limit: 200 });
  const select = host.querySelector<HTMLElement>('[role="combobox"][aria-label="Decision limit"]')!;
  await act(async () => select.click());
  const option = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(item => item.textContent === "1000")!;
  await act(async () => option.click());
  expect(io.invoke).toHaveBeenCalledWith("policy_decisions", { limit: 1000 });
});

it("searches the knowledge base with the chosen result limit", async () => {
  io.invoke.mockImplementation(async (command: string) => {
    if (command === "knowledge_stats") return { indexed: true, files: 1, chunks: 1, documents: 0, legacy_documents_preserved: false, indexed_at: null, configured: { retrieval_strategy: "keyword", chunk_max_tokens: 450, embedding_model: null, embedding_dimensions: null }, effective: null, stale: false, warnings: [] };
    if (command === "knowledge_summary") return { db_configured: true, targets: [], runs: [], crashes: [] };
    if (command === "knowledge_search") return [];
    throw new Error(command);
  });
  await render(<KnowledgeView />);
  await edit(host.querySelector<HTMLInputElement>("input")!, "parser");
  await edit(host.querySelector<HTMLInputElement>('input[aria-label="Result limit"]')!, "25");
  await click("Search");
  expect(io.invoke).toHaveBeenCalledWith("knowledge_search", { project: "/proj", query: "parser", limit: 25 });
});
