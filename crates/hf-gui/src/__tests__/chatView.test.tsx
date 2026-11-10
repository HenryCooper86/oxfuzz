// @vitest-environment jsdom
import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ChatView } from "../views/ChatView";
import { MarkdownContent } from "../components/MarkdownContent";
import { I18nProvider } from "../i18n";
import { useI18n } from "../i18nContext";
import { ProjectContext } from "../providers/project";

const PROJECT = "/work/proj";
const transport = vi.hoisted(() => ({
  history: [] as Array<{ role: string; content: string; timestamp?: string }>,
  emit: undefined as undefined | ((payload: unknown) => void),
  finishTurn: undefined as undefined | (() => void),
  invoke: vi.fn(),
}));
vi.mock("../lib", () => ({
  pickFolder: async () => null,
  getTransport: () => ({
    invoke: transport.invoke,
    listen: async (event: string, handler: (e: { payload: unknown }) => void) => {
      if (event === "chat:event") transport.emit = (payload) => handler({ payload });
      return () => {
        transport.emit = undefined;
      };
    },
  }),
}));

let host: HTMLDivElement;
let root: Root;

function LanguageControl() {
  const { setLocale } = useI18n();
  return <><button data-language="en" onClick={() => setLocale("en")}>English</button>
    <button data-language="zh" onClick={() => setLocale("zh")}>Chinese</button></>;
}

function Harness({ initial }: { initial: string }) {
  const [activeProject, setActiveProject] = useState(initial);
  return (
    <ProjectContext.Provider
      value={{
        activeProject,
        recentProjects: [PROJECT],
        setActiveProject,
        addRecent: () => {},
        removeRecent: () => {},
        deleteProjectData: async () => {},
      }}
    >
      <I18nProvider>
        <LanguageControl />
        <ChatView />
      </I18nProvider>
    </ProjectContext.Provider>
  );
}

async function mount(initialProject = PROJECT) {
  await act(async () => root.render(<Harness initial={initialProject} />));
  await act(async () => {});
}

function setSessions(map: Record<string, string>) {
  localStorage.setItem("hf_project_sessions_v1", JSON.stringify(map));
}

function type(text: string) {
  const ta = host.querySelector("textarea")!;
  const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
  setter.call(ta, text);
  ta.dispatchEvent(new Event("input", { bubbles: true }));
}

const sendButton = () => host.querySelector<HTMLButtonElement>('button[aria-label="Send"]')!;

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  transport.history = [];
  transport.emit = undefined;
  transport.finishTurn = undefined;
  transport.invoke.mockReset();
  transport.invoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "chat_history":
        return transport.history;
      case "create_session":
        return "s-new";
      case "list_models":
      case "list_agents":
        return [];
      case "chat_agent":
        return new Promise<string>((resolve) => {
          transport.finishTurn = () => resolve("done");
        });
      default:
        return null;
    }
  });
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.unstubAllGlobals();
});

it("renders assistant Markdown as elements and never raw HTML", async () => {
  setSessions({ [PROJECT]: "s1" });
  transport.history = [
    {
      role: "assistant",
      content: [
        "**bold** and `inline`",
        "",
        "- one",
        "- two",
        "",
        "| a | b |",
        "|---|---|",
        "| 1 | 2 |",
        "",
        "```c",
        "int x = 1;",
        "```",
        "",
        '<script id="evil">window.__pwned = 1</script><img id="rawimg" src="x" onerror="1">',
        "",
        "[docs](https://example.com/guide)",
      ].join("\n"),
      timestamp: "2026-11-07T06:16:24Z",
    },
  ];
  await mount();
  expect(host.querySelector("strong")?.textContent).toBe("bold");
  expect(host.querySelector("table th")?.textContent).toBe("a");
  expect(host.querySelectorAll("table td")).toHaveLength(2);
  expect(host.querySelectorAll("ul li")).toHaveLength(2);
  expect(host.querySelector("pre code")?.textContent).toContain("int x = 1;");
  expect(host.textContent).not.toContain("**bold**");
  expect(host.querySelector("#evil")).toBeNull();
  expect(host.querySelector("#rawimg")).toBeNull();
  // No anchors: the app has no safe external-open path, so links are text.
  expect(host.querySelector("a")).toBeNull();
  expect(host.textContent).toContain("docs");
  expect(host.textContent).toContain("https://example.com/guide");
});

it("shows each message's persisted time", async () => {
  setSessions({ [PROJECT]: "s1" });
  transport.history = [
    { role: "user", content: "first", timestamp: "2026-11-07T06:16:24Z" },
    { role: "assistant", content: "second", timestamp: "2026-11-07T06:19:22Z" },
  ];
  await mount();
  expect(host.textContent).toContain(new Date("2026-11-07T06:16:24Z").toLocaleTimeString());
  expect(host.textContent).toContain(new Date("2026-11-07T06:19:22Z").toLocaleTimeString());
});

it("removing the project chip stops the project being sent", async () => {
  await mount();
  const remove = host.querySelector<HTMLButtonElement>('button[aria-label="Remove attachment"]')!;
  expect(remove).not.toBeNull();
  await act(async () => remove.click());
  await act(async () => {});
  expect(host.querySelector('button[aria-label="Remove attachment"]')).toBeNull();

  await act(async () => type("hello"));
  await act(async () => sendButton().click());
  const call = transport.invoke.mock.calls.find(([command]) => command === "chat_agent")!;
  expect((call[1] as { project: unknown }).project).toBeNull();
});

it("sends the project while the chip is present", async () => {
  await mount();
  await act(async () => type("hello"));
  await act(async () => sendButton().click());
  const call = transport.invoke.mock.calls.find(([command]) => command === "chat_agent")!;
  expect((call[1] as { project: unknown }).project).toBe(PROJECT);
});

it("shows tool activity compactly with expandable pretty JSON", async () => {
  await mount();
  await act(async () => type("find c files"));
  await act(async () => sendButton().click());
  await act(async () => transport.emit!({ type: "tool_call", name: "Glob", args: { pattern: "**/*.c" } }));
  await act(async () =>
    transport.emit!({ type: "tool_result", name: "Glob", summary: '{"count":1,"matches":["a.c"]}' }),
  );
  expect(host.textContent).toContain("Calling tool: Glob (pattern=**/*.c)");
  const details = host.querySelector("details")!;
  expect(details).not.toBeNull();
  expect(details.open).toBe(false);
  expect(details.querySelector("summary")?.textContent).toBe("Glob: count=1, matches[1]");
  expect(details.querySelector("pre")?.textContent).toBe(
    JSON.stringify({ count: 1, matches: ["a.c"] }, null, 2),
  );
  expect(host.textContent).not.toContain("Glob -> ");
});

it("starts the composer comfortably tall", async () => {
  await mount();
  const ta = host.querySelector("textarea")!;
  expect(ta.rows).toBeGreaterThanOrEqual(3);
  expect(parseInt(ta.style.height, 10)).toBeGreaterThanOrEqual(72);
});

it("renders Markdown content without HTML passthrough", async () => {
  await act(async () => root.render(<MarkdownContent text={"<b id=x>hi</b> *em*"} />));
  expect(host.querySelector("#x")).toBeNull();
  expect(host.querySelector("em")?.textContent).toBe("em");
});

// A language switch must affect the next request without replacing the session.
it("sends the current interface language on every turn in an existing chat", async () => {
  setSessions({ [PROJECT]: "s1" });
  await mount();
  for (const locale of ["en", "zh", "en"]) {
    await act(async () => host.querySelector<HTMLButtonElement>(`[data-language="${locale}"]`)!.click());
    await act(async () => type("Explain fuzzing without using tools."));
    await act(async () => host.querySelector<HTMLTextAreaElement>("textarea")!.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
    ));
    const call = transport.invoke.mock.calls.filter(([command]) => command === "chat_agent").at(-1)!;
    expect(call[1]).toMatchObject({ sessionId: "s1", responseLanguage: locale });
    await act(async () => transport.finishTurn!());
  }
});
