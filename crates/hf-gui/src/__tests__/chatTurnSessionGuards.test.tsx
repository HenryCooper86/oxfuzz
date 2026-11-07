// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ChatView } from "../views/ChatView";
import { I18nProvider } from "../i18n";
import { ProjectContext } from "../providers/project";

// A running turn is bound to the session it started in: Stop must always
// release its button, the project controls are locked while it runs, and a
// turn that settles after the view moved to another session must not
// overwrite that session's transcript.
const backend = vi.hoisted(() => {
  const state = {
    cancelOutcome: "accepted",
    resolveTurn: undefined as undefined | ((answer: string) => void),
    sessions: 0,
  };
  const turns = (text: string) => [{ role: "assistant", content: text }];
  const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
    switch (command) {
      case "create_session": return `session-${++state.sessions}`;
      case "chat_history":
        return args?.sessionId === "session-1" ? turns("old session history") : turns("new session history");
      case "list_agents": return [];
      case "list_models": return [];
      case "chat_agent":
        return new Promise((resolve) => {
          state.resolveTurn = resolve;
        });
      case "chat_cancel": return state.cancelOutcome;
      default: return null;
    }
  });
  return { state, invoke };
});
vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: backend.invoke, listen: async () => () => {} }),
  pickFolder: vi.fn(async () => null),
}));
vi.mock("../providers/prefs", () => ({ usePrefs: () => ({ sendOnEnter: true }) }));
vi.mock("../providers/runOutput", () => ({ useRunOutput: () => ({ running: false }) }));
vi.mock("../providers/confirm", () => ({ useConfirm: () => vi.fn() }));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));

let host: HTMLDivElement; let root: Root;
const byLabel = (label: string) => host.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
const composer = () => host.querySelector("textarea")!;

function render(activeProject: string) {
  return act(async () =>
    root.render(
      <I18nProvider>
        <ProjectContext.Provider value={{ activeProject, recentProjects: [], setActiveProject: vi.fn(), addRecent: vi.fn(), removeRecent: vi.fn(), deleteProjectData: vi.fn() }}>
          <ChatView />
        </ProjectContext.Provider>
      </I18nProvider>,
    ),
  );
}

async function sendMessage(text: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
  await act(async () => {
    setter.call(composer(), text);
    composer().dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => byLabel("Send")!.click());
}

beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  backend.invoke.mockClear();
  backend.state.cancelOutcome = "accepted";
  backend.state.sessions = 0;
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await render("/work/proj");
});
afterEach(async () => {
  await act(async () => root.unmount()); host.remove();
  vi.unstubAllGlobals();
});

it("releases the Stop button when the backend reports the turn is not running", async () => {
  backend.state.cancelOutcome = "not_running";
  await sendMessage("hello");
  await act(async () => byLabel("Stop")!.click());
  expect(byLabel("Stop")!.disabled).toBe(false);
  expect(host.textContent).not.toContain("Stopping");
});

it("locks the project chip and folder picker while a turn runs", async () => {
  expect(byLabel("Remove attachment")!.disabled).toBe(false);
  expect(byLabel("Attach project folder")!.disabled).toBe(false);
  await sendMessage("hello");
  expect(byLabel("Remove attachment")!.disabled).toBe(true);
  expect(byLabel("Attach project folder")!.disabled).toBe(true);
  await act(async () => backend.state.resolveTurn!("done"));
  expect(byLabel("Remove attachment")!.disabled).toBe(false);
});

it("does not let a stale turn overwrite another session's transcript", async () => {
  await sendMessage("hello");
  // The view moves to a different session while the turn is still running.
  localStorage.setItem("hf_project_sessions_v1", JSON.stringify({ "": "session-9" }));
  await render("");
  expect(host.textContent).toContain("new session history");
  await act(async () => backend.state.resolveTurn!("done"));
  expect(host.textContent).toContain("new session history");
  expect(host.textContent).not.toContain("old session history");
});
