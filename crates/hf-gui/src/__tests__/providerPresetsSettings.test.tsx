// @vitest-environment jsdom

import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ProvidersTab } from "../components/settings/ProvidersTab";
import { normalizeProvider, type Provider } from "../components/settings/providerTypes";

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));

vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: mocks.invoke }),
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
// jsdom lacks scrollIntoView, which Radix Select calls when focusing options.
Element.prototype.scrollIntoView = () => {};

interface Holder {
  current: Provider[];
  changes: number;
}

// Roots are unmounted per-test, but a mid-test assertion failure would leak a
// mounted root (and its Radix portal) into the shared jsdom document. Register
// every teardown here and drain it in afterEach so a failing case cannot pollute
// the next one.
const cleanups: Array<() => Promise<void>> = [];

// Controlled owner mirroring the SettingsView orchestrator: it owns the pool,
// hands ProvidersTab the current value, and counts every onChange it receives.
// A zero `changes` count after mount proves the tab never rewrote the loaded
// provider (no applyProviderPreset on load).
function Harness({ initial, onChange }: { initial: Provider[]; onChange: (next: Provider[]) => void }) {
  const [providers, setProviders] = useState<Provider[]>(initial);
  return (
    <I18nProvider>
      <ProvidersTab
        value={providers}
        onChange={(next) => {
          onChange(next);
          setProviders(next);
        }}
      />
    </I18nProvider>
  );
}

async function mount(initial: Provider[]) {
  const holder: Holder = { current: initial, changes: 0 };
  const container = document.createElement("div");
  document.body.append(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(<Harness initial={initial} onChange={next => { holder.current = next; holder.changes += 1; }} />);
  });
  const unmount = async () => {
    await act(async () => root.unmount());
    container.remove();
  };
  cleanups.push(unmount);
  return { container, holder, unmount };
}

function inputByLabel(container: HTMLElement, label: string): HTMLInputElement {
  const el = container.querySelector<HTMLInputElement>(`[aria-label="${label}"]`);
  if (!el) throw new Error(`input not found: ${label}`);
  return el;
}

async function selectProviderType(container: HTMLElement, label: string) {
  const trigger = container.querySelector<HTMLElement>('[aria-label="Provider Type"]');
  expect(trigger, container.textContent ?? "").toBeTruthy();
  await act(async () => {
    trigger!.click();
  });
  const options = [...document.querySelectorAll<HTMLElement>('[role="option"]')];
  const option = options.find((node) => node.textContent === label);
  expect(option, options.map((node) => node.textContent).join(" | ")).toBeTruthy();
  await act(async () => {
    option!.click();
  });
}

async function clickTestConnection(container: HTMLElement) {
  const button = [...container.querySelectorAll("button")].find((b) => b.textContent === "Test Connection");
  expect(button, container.textContent ?? "").toBeTruthy();
  await act(async () => {
    button!.click();
  });
}

function testedProvider(): Provider | undefined {
  const call = mocks.invoke.mock.calls.find(([command]) => command === "provider_test");
  return call?.[1]?.provider as Provider | undefined;
}

describe("ProvidersTab provider presets", () => {
  beforeEach(() => {
    mocks.invoke.mockReset().mockImplementation(async (command: string) =>
      command === "provider_test" ? "Connected" : undefined,
    );
  });

  afterEach(async () => {
    while (cleanups.length > 0) {
      await cleanups.pop()!();
    }
    mocks.invoke.mockReset();
  });

  it("fills a Kimi Coding selection with the coding adapter, endpoint, model, and native tool mode while clearing credentials and preserving metadata", async () => {
    const initial = normalizeProvider({
      id: "legacy-openai",
      provider_type: "openai",
      model: "gpt-4o",
      api_key: "sk-legacy",
      api_key_env: "LEGACY_KEY",
      api_key_configured: true,
      api_key_env_configured: true,
      headers: { "X-Org": "acme", Authorization: "Bearer legacy" },
      headers_configured: true,
      tags: ["general", "code"],
      max_concurrency: 7,
      context_window: 200000,
      cost_per_1k_input: 1.5,
    });
    const { container, holder, unmount } = await mount([initial]);

    await selectProviderType(container, "Kimi Coding (subscription)");

    expect(holder.current[0]).toMatchObject({
      id: "legacy-openai",
      provider_type: "openai-compat",
      base_url: "https://api.kimi.ai/coding/v1",
      model: "kimi-for-coding",
      tool_calling_mode: "native",
      api_key: null,
      api_key_env: null,
      api_key_configured: false,
      api_key_env_configured: false,
      headers: {},
      headers_configured: false,
      tags: ["general", "code"],
      max_concurrency: 7,
      context_window: 200000,
      cost_per_1k_input: 1.5,
    });
    // The switch is a non-preset metadata field that must survive too.
    expect(holder.current[0].enabled).toBe(true);

    await unmount();
  });

  it("fills a GLM BigModel selection with the platform endpoint and native tool mode", async () => {
    const { container, holder, unmount } = await mount([
      normalizeProvider({ id: "p", provider_type: "openai", model: "gpt-4o" }),
    ]);

    await selectProviderType(container, "GLM API (BigModel.cn)");

    expect(holder.current[0]).toMatchObject({
      provider_type: "openai-compat",
      base_url: "https://open.bigmodel.cn/api/paas/v4",
      model: "glm-5.3",
      tool_calling_mode: "native",
    });

    await unmount();
  });

  it("routes a Z.AI coding selection to the dedicated coding endpoint for both the form and the connection test", async () => {
    const { container, holder, unmount } = await mount([
      normalizeProvider({ id: "p", provider_type: "openai", api_key: "sk-old" }),
    ]);

    await selectProviderType(container, "GLM Coding Plan (Z.AI)");
    await clickTestConnection(container);

    expect(holder.current[0]).toMatchObject({
      provider_type: "openai-compat",
      base_url: "https://api.z.ai/api/coding/paas/v4",
      model: "glm-5.3",
      tool_calling_mode: "native",
      api_key: null,
    });
    expect(holder.current[0].base_url).not.toBe("https://api.z.ai/api/paas/v4");

    // The probe must carry the same cleared-credential, coding-endpoint config.
    const tested = testedProvider();
    expect(tested).toBeTruthy();
    expect(tested).toMatchObject({
      provider_type: "openai-compat",
      base_url: "https://api.z.ai/api/coding/paas/v4",
      model: "glm-5.3",
      tool_calling_mode: "native",
    });
    expect(tested?.api_key).toBeNull();
    expect(tested?.base_url).not.toBe("https://api.z.ai/api/paas/v4");

    await unmount();
  });

  it("recognizes loaded compatible coding providers, including CN Kimi endpoints with trailing slashes, without mutating them", async () => {
    const cases = [
      { base_url: "https://api.kimi.ai/coding/v1", label: "Kimi Coding (subscription)" },
      { base_url: "https://api.kimi.ai/coding/v1/", label: "Kimi Coding (subscription)" },
      { base_url: "https://api.kimi.com/coding/v1", label: "Kimi Coding (subscription)" },
      { base_url: "https://api.moonshot.cn/v1/", label: "Kimi API (Moonshot)" },
      { base_url: "https://open.bigmodel.cn/api/coding/paas/v4/", label: "GLM Coding Plan (BigModel.cn)" },
    ];

    for (const c of cases) {
      const provider = normalizeProvider({
        id: "loaded",
        provider_type: "openai-compat",
        base_url: c.base_url,
        model: "custom-model",
        api_key: "sk-loaded",
      });
      const { container, holder, unmount } = await mount([provider]);

      // The combobox shows the branded preset...
      expect(container.querySelector('[aria-label="Provider Type"]')?.textContent).toContain(c.label);
      // ...but the stored endpoint (trailing slash included) and the user's own
      // model survive exactly as loaded: inference must not rewrite input.
      expect(inputByLabel(container, "Base URL").value).toBe(c.base_url);
      expect(inputByLabel(container, "Model ID").value).toBe("custom-model");
      // The loaded key is untouched: inference must not clear credentials on load.
      expect(holder.current[0].api_key).toBe("sk-loaded");
      expect(holder.changes).toBe(0);

      await unmount();
    }
  });

  it("leaves a custom compatible endpoint generic and unchanged across a reload", async () => {
    const build = () =>
      normalizeProvider({
        id: "gateway",
        provider_type: "openai-compat",
        base_url: "https://llm.example.com/v1",
        model: "custom-model",
        api_key: "sk-gateway",
      });

    const first = await mount([build()]);
    expect(first.container.querySelector('[aria-label="Provider Type"]')?.textContent).toContain("OpenAI-compatible");
    expect(inputByLabel(first.container, "Base URL").value).toBe("https://llm.example.com/v1");
    expect(inputByLabel(first.container, "Model ID").value).toBe("custom-model");
    expect(first.holder.changes).toBe(0);
    await first.unmount();

    // Reopening Settings loads the same provider again: it must stay generic and
    // untouched, not be rebranded or have its endpoint/model rewritten.
    const second = await mount([build()]);
    expect(second.container.querySelector('[aria-label="Provider Type"]')?.textContent).toContain("OpenAI-compatible");
    expect(inputByLabel(second.container, "Base URL").value).toBe("https://llm.example.com/v1");
    expect(inputByLabel(second.container, "Model ID").value).toBe("custom-model");
    expect(second.holder.changes).toBe(0);
    await second.unmount();
  });

  it("keeps the native Azure selection usable and shows its resource fields", async () => {
    const { container, holder, unmount } = await mount([
      normalizeProvider({ id: "az", provider_type: "openai" }),
    ]);

    await selectProviderType(container, "Azure OpenAI");

    expect(holder.current[0]).toMatchObject({ provider_type: "azure", base_url: null, model: "" });
    // The Azure-specific group renders once the native adapter is selected.
    expect(container.textContent).toContain("Resource Name");
    expect(container.querySelector('input[placeholder="myresource"]')).toBeTruthy();

    await unmount();
  });

  it("fills the native Ollama selection with its host root URL (no /v1)", async () => {
    const { container, holder, unmount } = await mount([
      normalizeProvider({ id: "local", provider_type: "openai" }),
    ]);

    await selectProviderType(container, "Ollama (local)");

    expect(holder.current[0]).toMatchObject({
      provider_type: "ollama",
      base_url: "http://localhost:11434",
      model: "llama3.1:8b",
    });
    expect(holder.current[0].base_url).not.toContain("/v1");

    await unmount();
  });
});
