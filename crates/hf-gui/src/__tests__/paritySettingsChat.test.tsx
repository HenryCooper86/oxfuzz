// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ChatView } from "../views/ChatView";
import { I18nProvider } from "../i18n";
import { ProjectContext } from "../providers/project";

const io = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({
  pickFolder: async () => null,
  getTransport: () => ({ invoke: io.invoke, listen: async () => () => {} }),
}));
let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.setItem("hf_project_sessions_v1", JSON.stringify({ "/p": "s1" }));
  io.invoke.mockReset();
  io.invoke.mockImplementation(async (command: string) => {
    if (command === "chat_history") return [{ role: "assistant", content: "hello", timestamp: "2026-11-07T06:16:24Z" }];
    if (command === "create_session") return "s-new";
    if (command === "list_models" || command === "list_agents") return [];
    return null;
  });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });
async function mount() {
  await act(async () => root.render(<I18nProvider><ProjectContext.Provider value={{
    activeProject: "/p", recentProjects: [], setActiveProject: () => {}, addRecent: () => {}, removeRecent: () => {}, deleteProjectData: async () => {},
  }}><ChatView /></ProjectContext.Provider></I18nProvider>));
  await act(async () => {});
}
const newButton = () => host.querySelector<HTMLButtonElement>('button[aria-label="New session"]')!;

it("creates a session with the optional title", async () => {
  await mount();
  const input = host.querySelector<HTMLInputElement>('input[aria-label="Session title (optional)"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "Parser triage");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => newButton().click());
  expect(io.invoke).toHaveBeenCalledWith("create_session", { title: "Parser triage" });
});

it("creates an untitled session with no arguments", async () => {
  await mount();
  await act(async () => newButton().click());
  expect(io.invoke).toHaveBeenCalledWith("create_session", undefined);
});
