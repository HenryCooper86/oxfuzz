// @vitest-environment jsdom
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AgentsView, SkillsView } from "../views/FeatureViews";
import { I18nProvider } from "../i18n";

const io = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke: io.invoke }) }));
const agent = { id: "custom-agent", name: "Custom Agent", description: "A fixture agent", role: "triage", icon: null, system_prompt: "Review evidence", allowed_tools: ["triage"], model_tags: [], temperature: 0.4, max_iterations: 12, autonomy: "assist", capabilities: [], user_callable: true, skills: [], trust_tier: "user-defined", builtin_available: false, completion_requirement: { tool: "triage", reminder: "Inspect evidence first" } };
const skill = { name: "custom-skill", version: "1.0.0", description: "A fixture playbook", domain: ["fuzzing"], body: "Review each finding", trust_tier: "user-defined", builtin_available: false };
let host: HTMLDivElement; let root: Root;
let overrides: Record<string, ((args?: Record<string, unknown>) => unknown) | undefined>;
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { resolve, promise }; }
const button = (name: string) => [...host.querySelectorAll("button")].find(b => b.textContent?.trim() === name || b.getAttribute("aria-label") === name)!;
async function click(name: string) { expect(button(name)).toBeDefined(); await act(async () => button(name).click()); }
async function field(label: string, value: string) {
  const node = [...host.querySelectorAll("label")].find(n => n.textContent?.startsWith(label))!.querySelector<HTMLInputElement | HTMLTextAreaElement>("input,textarea")!;
  await act(async () => {
    const prototype = node instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(node, value);
    node.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function render(view: ReactNode) { await act(async () => root.render(<I18nProvider>{view}</I18nProvider>)); }
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.clear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host); overrides = {}; io.invoke.mockReset();
  io.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
    if (overrides[command]) return overrides[command]!(args);
    if (command === "list_agents") return [agent];
    if (command === "list_skills") return [skill];
    if (command === "read_skill") return skill;
    if (command === "agent_info") return { model: "fixture", provider_type: "fixture", guardrails: "approval required", tools: [] };
    if (command === "agent_tools") return [{ name: "triage", description: "Review crashes" }];
    if (command.startsWith("save_")) return null;
    throw new Error(command);
  });
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

it("preserves an agent completion rule when editing its description", async () => {
  await render(<AgentsView />); await click("Edit"); await field("Description", "Updated description"); await click("Save");
  expect(io.invoke).toHaveBeenCalledWith("save_agent", { definition: expect.objectContaining({ description: "Updated description", completion_requirement: agent.completion_requirement }) });
});
it.each(["51", "0", "1.5"])("rejects invalid iteration limit %s without rewriting it", async value => {
  await render(<AgentsView />); await click("Edit"); await field("Max iterations", value); await click("Save");
  expect(io.invoke.mock.calls.filter(([command]) => command === "save_agent")).toHaveLength(0);
  expect(host.textContent).toContain("between 1 and 50");
});
it("rejects infinite temperature instead of submitting a null temperature", async () => {
  await render(<AgentsView />); await click("Edit"); await field("Temperature", "Infinity"); await click("Save");
  expect(io.invoke.mock.calls.filter(([command]) => command === "save_agent")).toHaveLength(0);
  expect(host.textContent).toContain("between 0 and 2");
});
it.each(["agents", "skills"])("prevents a new %s entry from replacing an existing id", async kind => {
  await render(kind === "agents" ? <AgentsView /> : <SkillsView />);
  await click(kind === "agents" ? "Duplicate into a new agent" : "Duplicate into a new skill");
  await field(kind === "agents" ? "Id" : "Name", kind === "agents" ? agent.id : skill.name); await click("Save");
  expect(io.invoke.mock.calls.filter(([command]) => command === (kind === "agents" ? "save_agent" : "save_skill"))).toHaveLength(0);
  expect(host.textContent).toContain("already exists");
});
it("ignores a pending skill read after starting a new skill", async () => {
  const read = deferred<typeof skill>(); overrides.read_skill = () => read.promise;
  await render(<SkillsView />); await click("Edit"); await click("New skill"); await field("Name", "new-playbook");
  await act(async () => read.resolve(skill));
  expect(host.querySelector<HTMLInputElement>("input")!.value).toBe("new-playbook");
});
it.each(["agents", "skills"])("does not close a newer %s draft when an old save finishes", async kind => {
  const save = deferred<null>(); overrides[kind === "agents" ? "save_agent" : "save_skill"] = () => save.promise;
  await render(kind === "agents" ? <AgentsView /> : <SkillsView />); await click("Edit"); await click("Save");
  await click("Close"); await click(kind === "agents" ? "New agent" : "New skill"); await field("Name", "New draft");
  await act(async () => save.resolve(null));
  expect(host.querySelector<HTMLInputElement>("input")?.value).toBe("New draft");
});
it.each(["agents", "skills"])("shows reset rather than delete for a built-in %s override", async kind => {
  overrides[kind === "agents" ? "list_agents" : "list_skills"] = () => [{ ...(kind === "agents" ? agent : skill), builtin_available: true }];
  await render(kind === "agents" ? <AgentsView /> : <SkillsView />);
  expect(button("Reset to shipped version")).toBeDefined(); expect(button("Delete")).toBeUndefined();
});
it("shows an agent tool-loading failure and allows retry", async () => {
  overrides.agent_tools = () => { throw new Error("tools unavailable"); };
  await render(<AgentsView />); await click("Edit");
  expect(host.textContent).toContain("tools unavailable");
  delete overrides.agent_tools; await click("Retry");
  expect(host.textContent).toContain("Review crashes"); expect(host.textContent).not.toContain("tools unavailable");
});
it("shows a skill-choice loading failure instead of claiming no skills exist", async () => {
  overrides.list_skills = () => { throw new Error("skills unavailable"); };
  await render(<AgentsView />); await click("Edit");
  expect(host.textContent).toContain("skills unavailable");
  expect(host.textContent).not.toContain("No skills available");
});
it.each(["agents", "skills"])("prevents edits to submitted %s fields while saving", async kind => {
  const save = deferred<null>(); overrides[kind === "agents" ? "save_agent" : "save_skill"] = () => save.promise;
  await render(kind === "agents" ? <AgentsView /> : <SkillsView />); await click("Edit"); await click("Save");
  const description = [...host.querySelectorAll("label")].find(node => node.textContent?.startsWith("Description"))!.querySelector("input")!;
  expect(description.matches(":disabled")).toBe(true);
  expect(button("Close").disabled).toBe(false);
  expect(button("Cancel")).toBeUndefined();
  await act(async () => save.resolve(null));
});
it("lets an explicitly edited id remain empty while replacing an auto-generated id", async () => {
  await render(<AgentsView />); await click("New agent"); await field("Name", "Review Agent");
  const id = [...host.querySelectorAll("label")].find(node => node.textContent?.startsWith("Id"))!.querySelector("input")!;
  expect(id.value).toBe("review-agent");
  await field("Id", ""); expect(id.value).toBe("");
  await field("Id", "chosen-id"); await field("Name", "Changed display name");
  expect(id.value).toBe("chosen-id");
});
