// @vitest-environment jsdom

import { StrictMode, act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { I18nContext } from "../i18nContext";
import { ConfirmProvider } from "../providers/ConfirmContext";
import { useConfirm } from "../providers/confirm";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const i18n = { locale: "en" as const, setLocale: () => undefined, t: (key: string) => key };

type ConfirmResults = { first: boolean | null; second: boolean | null };

let pending: Promise<boolean> | null = null;

function Probe() {
  const confirm = useConfirm();
  const [results, setResults] = useState<ConfirmResults>({ first: null, second: null });
  const track = (key: keyof ConfirmResults, request: Promise<boolean>) => {
    void request.then((value) => setResults((previous) => ({ ...previous, [key]: value })));
  };
  return (
    <div>
      <output data-results>{JSON.stringify(results)}</output>
      <button
        type="button"
        onClick={() => {
          pending = confirm({ title: "solo", confirmLabel: "solo-confirm", cancelLabel: "solo-cancel" });
        }}
      >
        open solo
      </button>
      <button
        type="button"
        onClick={() => {
          track("first", confirm({ title: "first", confirmLabel: "first-confirm", cancelLabel: "first-cancel" }));
          track("second", confirm({ title: "second", confirmLabel: "second-confirm", cancelLabel: "second-cancel" }));
        }}
      >
        stack confirms
      </button>
    </div>
  );
}

let container: HTMLDivElement;
let root: Root;

beforeEach(async () => {
  pending = null;
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () =>
    root.render(
      <StrictMode>
        <I18nContext.Provider value={i18n}>
          <ConfirmProvider>
            <Probe />
          </ConfirmProvider>
        </I18nContext.Provider>
      </StrictMode>,
    ),
  );
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

async function click(label: string) {
  const button = [...container.querySelectorAll("button")].find((item) => item.textContent === label);
  if (!button) throw new Error(`Missing action: ${label}`);
  await act(async () => button.click());
}

function state() {
  return JSON.parse(container.querySelector("output")!.textContent!) as {
    first: boolean | null;
    second: boolean | null;
  };
}

describe("ConfirmProvider pending dialog ownership", () => {
  it("settles a superseded confirmation as cancelled instead of leaking its promise", async () => {
    await click("stack confirms");
    // The newest request owns the dialog; the replaced one must not hang.
    expect(container.querySelector('[role="alertdialog"]')?.getAttribute("aria-label")).toBe("second");
    expect(state()).toEqual({ first: false, second: null });
    await click("second-confirm");
    expect(state()).toEqual({ first: false, second: true });
  });

  it("cancels the pending confirmation when the provider unmounts with a dialog open", async () => {
    await click("open solo");
    expect(container.querySelector('[role="alertdialog"]')?.getAttribute("aria-label")).toBe("solo");
    await act(async () => root.unmount());
    // The cleanup settles synchronously during unmount, so the race is decided
    // without timers: an unresolved promise reports "unsettled".
    expect(await Promise.race([pending!, Promise.resolve("unsettled")])).toBe(false);
  });
});
