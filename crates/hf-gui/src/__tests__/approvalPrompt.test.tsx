// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApprovalPrompt } from "../components/ApprovalPrompt";
import { I18nProvider } from "../i18n";

// The prompt must be reachable from every view: it is mounted once in the app
// shell and is driven only by the backend's `chat:permission_request` event.
const transport = vi.hoisted(() => ({
  emit: undefined as undefined | ((payload: unknown) => void),
  close: undefined as undefined | ((payload: unknown) => void),
  invoke: vi.fn(async () => true),
}));
vi.mock("../lib", () => ({
  getTransport: () => ({
    invoke: transport.invoke,
    listen: async (event: string, handler: (e: { payload: unknown }) => void) => {
      if (event === "chat:permission_request") {
        transport.emit = payload => handler({ payload });
        return () => { transport.emit = undefined; };
      }
      if (event === "chat:permission_closed") {
        transport.close = payload => handler({ payload });
        return () => { transport.close = undefined; };
      }
      return () => {};
    },
  }),
}));
const toast = vi.hoisted(() => vi.fn());
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast }) }));

let host: HTMLDivElement; let root: Root;
const request = (id: string, action = "shell: make fuzz") => ({ id, action, reason: "agent wants to build", risk: "critical", timeout_secs: 300 });
const dialog = () => host.querySelector('[role="alertdialog"]');
const button = (label: string) => [...host.querySelectorAll("button")].find(b => b.textContent === label)!;

beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.useFakeTimers();
  transport.invoke.mockClear(); toast.mockClear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await act(async () => root.render(<I18nProvider><ApprovalPrompt /></I18nProvider>));
});
afterEach(async () => {
  await act(async () => root.unmount()); host.remove();
  vi.useRealTimers(); vi.unstubAllGlobals();
});

it("shows the action, reason, risk tier, and deadline, with Deny focused", async () => {
  expect(dialog()).toBeNull();
  await act(async () => transport.emit!(request("a")));
  expect(dialog()).not.toBeNull();
  expect(host.textContent).toContain("shell: make fuzz");
  expect(host.textContent).toContain("agent wants to build");
  expect(host.textContent).toContain("Critical");
  expect(host.textContent).toContain("5:00");
  expect(document.activeElement?.textContent).toBe("Deny");
});

it("sends the decision and closes", async () => {
  await act(async () => transport.emit!(request("a")));
  await act(async () => button("Approve").click());
  expect(transport.invoke).toHaveBeenCalledWith("chat_answer_permission", { id: "a", approved: true });
  expect(dialog()).toBeNull();
});

it("queues concurrent requests instead of replacing the first", async () => {
  await act(async () => transport.emit!(request("a", "run libfuzzer for 60s")));
  await act(async () => transport.emit!(request("b", "write host file: /tmp/x")));
  expect(host.textContent).toContain("run libfuzzer for 60s");
  expect(host.textContent).toContain("1 more waiting");
  await act(async () => button("Deny").click());
  expect(transport.invoke).toHaveBeenCalledWith("chat_answer_permission", { id: "a", approved: false });
  expect(host.textContent).toContain("write host file: /tmp/x");
});

it("denies on Escape", async () => {
  await act(async () => transport.emit!(request("a")));
  await act(async () => dialog()!.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })));
  expect(transport.invoke).toHaveBeenCalledWith("chat_answer_permission", { id: "a", approved: false });
});

it("counts down and drops the prompt once the backend has denied it", async () => {
  await act(async () => transport.emit!(request("a")));
  await act(async () => { vi.advanceTimersByTime(61_000); });
  expect(host.textContent).toContain("3:59");
  await act(async () => { vi.advanceTimersByTime(240_000); });
  expect(dialog()).toBeNull();
  // The backend already denied it on its own timeout; nothing is sent.
  expect(transport.invoke).not.toHaveBeenCalled();
});

it("withdraws a prompt the backend closed, such as one of a stopped chat turn", async () => {
  await act(async () => transport.emit!(request("a", "run libfuzzer for 60s")));
  await act(async () => transport.emit!(request("b", "write host file: /tmp/x")));
  await act(async () => transport.close!({ id: "a" }));
  expect(host.textContent).not.toContain("run libfuzzer for 60s");
  expect(host.textContent).toContain("write host file: /tmp/x");
  await act(async () => transport.close!({ id: "b" }));
  expect(dialog()).toBeNull();
  expect(transport.invoke).not.toHaveBeenCalled();
});
