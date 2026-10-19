// @vitest-environment jsdom
import { setTimeout as delay } from "node:timers/promises";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { CommandPalette } from "../components/CommandPalette";
import { I18nContext } from "../i18nContext";

let host: HTMLDivElement;
let root: Root;
const navigate = vi.fn();

beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  HTMLElement.prototype.scrollIntoView = vi.fn();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  navigate.mockClear();
  await act(async () => root.render(
    <I18nContext.Provider value={{ locale: "en", setLocale: () => {}, t: key => key }}>
      <button>Origin</button>
      <CommandPalette onNavigate={navigate} />
    </I18nContext.Provider>,
  ));
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  Reflect.deleteProperty(HTMLElement.prototype, "scrollIntoView");
  vi.unstubAllGlobals();
});

async function open() {
  host.querySelector("button")!.focus();
  await act(async () => {
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true, cancelable: true }));
  });
}

it("keeps keyboard focus in the modal and restores the origin on Escape", async () => {
  await open();
  await act(async () => host.querySelector("button")!.focus());
  expect(document.activeElement?.closest('[role="dialog"]')).not.toBeNull();
  await act(async () => {
    document.activeElement!.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  });
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  await act(async () => { await delay(0); });
  expect(document.activeElement).toBe(host.querySelector("button"));
});

it("lets keyboard users open the change-comparison workspace", async () => {
  await open();
  const input = document.querySelector<HTMLInputElement>('[role="dialog"] input')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "changes");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true })));
  expect(navigate).toHaveBeenCalledWith("changes");
  expect(document.querySelector('[role="dialog"]')).toBeNull();
});

it("activates a tab-focused result instead of the search highlight", async () => {
  await open();
  const button = [...document.querySelectorAll<HTMLButtonElement>('[role="dialog"] button')]
    .find(item => item.textContent === "nav.reports")!;
  await act(async () => button.focus());
  const enter = new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
  await act(async () => button.dispatchEvent(enter));
  expect(enter.defaultPrevented).toBe(false);
  expect(navigate).not.toHaveBeenCalled();
  // Native button activation follows an unhandled Enter key in the browser.
  await act(async () => button.click());
  expect(navigate).toHaveBeenCalledWith("reports");
});
