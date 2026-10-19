// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ProvidersTab } from "../components/settings/ProvidersTab";
import { normalizeProvider, type Provider } from "../components/settings/providerTypes";

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));

vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: mocks.invoke }),
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const i18n = {
  locale: "en" as const,
  setLocale: () => undefined,
  t: (key: string) => key,
};

function button(container: HTMLElement, text: string): HTMLButtonElement {
  const match = [...container.querySelectorAll("button")].find((candidate) =>
    candidate.textContent === text,
  );
  if (!(match instanceof HTMLButtonElement)) throw new Error(`button not found: ${text}`);
  return match;
}

function render(root: Root, value: Provider[]) {
  return act(async () => {
    root.render(
      <I18nContext.Provider value={i18n}>
        <ProvidersTab value={value} onChange={() => undefined} />
      </I18nContext.Provider>,
    );
  });
}

describe("ProvidersTab connection test", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    mocks.invoke.mockReset();
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
  });

  it("shows the verified message for an unchanged provider", async () => {
    const provider = normalizeProvider({ id: "p1", provider_type: "openai", model: "gpt-4o", api_key: "sk-a" });
    let finish!: (value: string) => void;
    mocks.invoke.mockImplementation((command: string) =>
      command === "provider_test" ? new Promise<string>((resolve) => { finish = resolve; }) : Promise.resolve(undefined),
    );

    await render(root, [provider]);
    await act(async () => { button(container, "settings.providers.testConnection").click(); });
    await act(async () => { finish("Connected"); });

    expect(container.textContent).toContain("Connected");
  });

  it("discards a connection-test result that completes after the provider was edited", async () => {
    const original = normalizeProvider({ id: "p1", provider_type: "openai", model: "gpt-4o", api_key: "sk-a" });
    const edited: Provider = { ...original, model: "changed-model" };
    let finish!: (value: string) => void;
    mocks.invoke.mockImplementation((command: string) =>
      command === "provider_test" ? new Promise<string>((resolve) => { finish = resolve; }) : Promise.resolve(undefined),
    );

    await render(root, [original]);
    await act(async () => { button(container, "settings.providers.testConnection").click(); });

    // The operator edits the provider (model change) while the probe is in flight.
    await render(root, [edited]);

    // The probe resolves successfully for the OLD configuration.
    await act(async () => { finish("Connected"); });

    expect(container.textContent).not.toContain("Connected");
  });

  it("discards a connection-test error that completes after the provider was edited", async () => {
    const original = normalizeProvider({ id: "p1", provider_type: "openai", model: "gpt-4o", api_key: "sk-a" });
    const edited: Provider = { ...original, model: "changed-model" };
    let fail!: (reason: Error) => void;
    mocks.invoke.mockImplementation((command: string) =>
      command === "provider_test" ? new Promise<string>((_, reject) => { fail = reject; }) : Promise.resolve(undefined),
    );

    await render(root, [original]);
    await act(async () => { button(container, "settings.providers.testConnection").click(); });
    await render(root, [edited]);
    await act(async () => { fail(new Error("probe failed")); });

    expect(container.textContent).not.toContain("probe failed");
  });

  it("clears a previously shown result as soon as the provider is edited", async () => {
    const original = normalizeProvider({ id: "p1", provider_type: "openai", model: "gpt-4o", api_key: "sk-a" });
    const edited: Provider = { ...original, model: "changed-model" };
    let finish!: (value: string) => void;
    mocks.invoke.mockImplementation((command: string) =>
      command === "provider_test" ? new Promise<string>((resolve) => { finish = resolve; }) : Promise.resolve(undefined),
    );

    await render(root, [original]);
    await act(async () => { button(container, "settings.providers.testConnection").click(); });
    await act(async () => { finish("Connected"); });
    expect(container.textContent).toContain("Connected");

    // The verified result describes the old config; editing must drop it.
    await render(root, [edited]);
    expect(container.textContent).not.toContain("Connected");
  });
});
