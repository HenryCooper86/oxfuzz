// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ChatView } from "../views/ChatView";
import { I18nProvider } from "../i18n";

// The chat composer controls one turn at a time: the provider picker chooses
// who answers it, and Stop cancels it by the id the view sent with it.
const backend = vi.hoisted(() => {
  const state = {
    rejectTurn: undefined as undefined | ((error: unknown) => void),
    resolveTurn: undefined as undefined | ((answer: string) => void),
  };
  const invoke = vi.fn(async (command: string) => {
    switch (command) {
      case "create_session": return "session-1";
      case "chat_history": return [];
      case "list_agents": return [];
      case "list_models": return [
        { id: "deepseek-main", provider_type: "deepseek", model: "deepseek-chat" },
        { id: "openai-main", provider_type: "openai", model: "gpt-x" },
      ];
      case "chat_agent":
        return new Promise((resolve, reject) => {
          state.resolveTurn = resolve;
          state.rejectTurn = reject;
        });
      case "chat_cancel": return "accepted";
      default: return null;
    }
  });
  return { state, invoke };
});
vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: backend.invoke, listen: async () => () => {} }),
  pickFolder: vi.fn(),
}));
vi.mock("../providers/project", () => ({
  useProject: () => ({ activeProject: "", recentProjects: [], setActiveProject: vi.fn() }),
}));
vi.mock("../providers/prefs", () => ({ usePrefs: () => ({ sendOnEnter: true }) }));
vi.mock("../providers/runOutput", () => ({ useRunOutput: () => ({ running: false }) }));
vi.mock("../providers/confirm", () => ({ useConfirm: () => vi.fn() }));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));

let host: HTMLDivElement; let root: Root;
const byLabel = (label: string) => host.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
const buttonWithText = (text: string) => [...host.querySelectorAll("button")].find((b) => b.textContent === text)!;
const composer = () => host.querySelector("textarea")!;
const calls = (command: string) => backend.invoke.mock.calls.filter(([name]) => name === command);

async function type(text: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
  await act(async () => {
    setter.call(composer(), text);
    composer().dispatchEvent(new Event("input", { bubbles: true }));
  });
}

beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  backend.invoke.mockClear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await act(async () => root.render(<I18nProvider><ChatView /></I18nProvider>));
});
afterEach(async () => {
  await act(async () => root.unmount()); host.remove();
  vi.unstubAllGlobals();
});

it("sends the picked provider with the turn, and no provider for Auto", async () => {
  await act(async () => buttonWithText("Auto-route").click());
  expect([...host.querySelectorAll('[role="option"]')].map((o) => o.textContent)).toEqual(["Auto-route", "deepseek-chat", "gpt-x"]);
  await act(async () => buttonWithText("gpt-x").click());

  await type("find targets");
  await act(async () => byLabel("Send")!.click());
  const [, args] = calls("chat_agent")[0] as unknown as [string, Record<string, unknown>];
  expect(args.provider).toBe("openai-main");
  expect(typeof args.turnId).toBe("string");
  expect(localStorage.getItem("hf_chat_provider")).toBe("openai-main");

  await act(async () => backend.state.resolveTurn!("done"));
  await act(async () => buttonWithText("gpt-x").click());
  await act(async () => buttonWithText("Auto-route").click());
  await type("again");
  await act(async () => byLabel("Send")!.click());
  const [, second] = calls("chat_agent")[1] as unknown as [string, Record<string, unknown>];
  expect(second.provider).toBeNull();
  expect(second.turnId).not.toBe(args.turnId);
});

it("replaces Send with Stop while a turn runs and cancels that turn", async () => {
  await type("run a long campaign");
  await act(async () => byLabel("Send")!.click());
  expect(byLabel("Send")).toBeNull();
  const stop = byLabel("Stop")!;
  expect(stop).not.toBeNull();

  await act(async () => stop.click());
  const [, turn] = calls("chat_agent")[0] as unknown as [string, Record<string, unknown>];
  expect(calls("chat_cancel")).toEqual([["chat_cancel", { turnId: turn.turnId }]]);
  await act(async () => byLabel("Stop")?.click());
  expect(calls("chat_cancel")).toHaveLength(1);

  await act(async () => backend.state.rejectTurn!("cancelled"));
  // The cancelled turn was rolled back: no error reply, the text is back in
  // the composer, and the view is idle again.
  expect(host.textContent).not.toContain("cancelled");
  expect(composer().value).toBe("run a long campaign");
  expect(byLabel("Stop")).toBeNull();
  expect(byLabel("Send")).not.toBeNull();
});
