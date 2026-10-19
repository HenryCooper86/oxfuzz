// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { SettingsView } from "../components/settings/SettingsView";

const mocks = vi.hoisted(() => ({ invoke: vi.fn(), toast: vi.fn(), confirm: vi.fn() }));

vi.mock("../lib", () => ({
  getTransport: () => ({ invoke: mocks.invoke }),
  isTauriEnvironment: () => false,
  emitDataChanged: () => undefined,
  onDataChanged: () => () => undefined,
  openExternal: vi.fn(),
  pickFolder: vi.fn(),
  pickFile: vi.fn(),
}));
vi.mock("../providers/prefs", () => ({
  usePrefs: () => ({
    theme: "dark",
    setTheme: () => undefined,
    fontSize: 14,
    setFontSize: () => undefined,
    sendOnEnter: false,
    setSendOnEnter: () => undefined,
    customDecorations: false,
    setCustomDecorations: () => undefined,
    sandboxArch: "linux/arm64",
    setSandboxArch: () => undefined,
  }),
}));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: mocks.toast }) }));
vi.mock("../providers/confirm", () => ({ useConfirm: () => mocks.confirm }));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const i18n = {
  locale: "en" as const,
  setLocale: () => undefined,
  t: (key: string) => key,
};

const FUZZING = {
  enabled_engines: ["libfuzzer"],
  default_engine: "libfuzzer",
  collect_function_coverage: false,
  default_duration_secs: 60,
  sandbox: { max_mem_mb: 2048, max_cpus: 1, max_duration_secs: 7200 },
};

async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

describe("SettingsView save", () => {
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

  function coverageSwitch(): HTMLButtonElement {
    const el = container.querySelector<HTMLButtonElement>('button[aria-label="settings.fuzzing.functionCoverage"]');
    if (!el) throw new Error("function coverage switch not found");
    return el;
  }

  it("preserves an edit made while a save is in flight", async () => {
    // Load phase: serve the fuzzing config from disk.
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "read_config") return Promise.resolve("[fuzzing]\n");
      if (command === "config_toml_to_value") return Promise.resolve({ fuzzing: { ...FUZZING } });
      throw new Error(`Unexpected command during load: ${command}`);
    });

    await act(async () => {
      root.render(<I18nContext.Provider value={i18n}><SettingsView /></I18nContext.Provider>);
    });
    const nav = [...container.querySelectorAll("button")].find((b) => b.textContent === "settings.tab.fuzzing");
    expect(nav).toBeTruthy();
    await act(async () => { (nav as HTMLButtonElement).click(); });
    await flush();

    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("false");

    // First edit: enable function coverage.
    await act(async () => { coverageSwitch().click(); });
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("true");

    // Save phase: hold the serialize reply open so we can edit during the save.
    let savedCoverage = false;
    let serializedCoverage = false;
    let resolveSerialize!: (value: string) => void;
    mocks.invoke.mockImplementation((command: string, args?: { value?: Record<string, unknown> }) => {
      if (command === "read_config") return Promise.resolve("[fuzzing]\n");
      if (command === "config_toml_to_value") {
        return Promise.resolve({ fuzzing: { ...FUZZING, collect_function_coverage: savedCoverage } });
      }
      if (command === "config_value_to_toml") {
        const fuzzing = (args?.value as { fuzzing?: { collect_function_coverage?: boolean } } | undefined)?.fuzzing;
        serializedCoverage = fuzzing?.collect_function_coverage ?? false;
        // ES2022 target predates Promise.withResolvers; store the resolver.
        return new Promise<string>((resolve) => { resolveSerialize = resolve; });
      }
      if (command === "write_config") { savedCoverage = serializedCoverage; return Promise.resolve(undefined); }
      throw new Error(`Unexpected command during save: ${command}`);
    });

    const save = [...container.querySelectorAll("button")].find((b) => b.textContent === "settings.save");
    expect(save).toBeTruthy();
    await act(async () => { (save as HTMLButtonElement).click(); });

    // Second edit during the save: disable coverage again.
    await act(async () => { coverageSwitch().click(); });
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("false");

    // The stale serialize completes.
    await act(async () => { resolveSerialize("[fuzzing]\n"); });
    await flush();

    // The clicked snapshot was persisted, and the second edit survives: it stays
    // in the draft (dirty), so Save remains enabled to persist it next.
    expect(savedCoverage).toBe(true);
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("false");
    const saveAfter = [...container.querySelectorAll("button")].find((b) => b.textContent === "settings.save");
    expect((saveAfter as HTMLButtonElement).disabled).toBe(false);
  });

  it("marks unchanged saved settings clean after reloading", async () => {
    let savedCoverage = false;
    let serializedCoverage = false;
    mocks.invoke.mockImplementation((command: string, args?: { value?: Record<string, unknown> }) => {
      if (command === "read_config") return Promise.resolve("[fuzzing]\n");
      if (command === "config_toml_to_value") {
        return Promise.resolve({ fuzzing: { ...FUZZING, collect_function_coverage: savedCoverage } });
      }
      if (command === "config_value_to_toml") {
        const fuzzing = (args?.value as { fuzzing?: { collect_function_coverage?: boolean } } | undefined)?.fuzzing;
        serializedCoverage = fuzzing?.collect_function_coverage ?? false;
        return Promise.resolve("[fuzzing]\n");
      }
      if (command === "write_config") { savedCoverage = serializedCoverage; return Promise.resolve(undefined); }
      throw new Error(`Unexpected command: ${command}`);
    });

    await act(async () => {
      root.render(<I18nContext.Provider value={i18n}><SettingsView /></I18nContext.Provider>);
    });
    const nav = [...container.querySelectorAll("button")].find((b) => b.textContent === "settings.tab.fuzzing");
    expect(nav).toBeTruthy();
    await act(async () => { (nav as HTMLButtonElement).click(); });
    await flush();

    // Edit then save with no interruption.
    await act(async () => { coverageSwitch().click(); });
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("true");

    const save = [...container.querySelectorAll("button")].find((b) => b.textContent === "settings.save");
    expect(save).toBeTruthy();
    await act(async () => { (save as HTMLButtonElement).click(); });
    await flush();

    // The post-save reload still runs: the saved value is shown and the draft is
    // clean, so Save is disabled again.
    expect(savedCoverage).toBe(true);
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("true");
    const saveAfter = [...container.querySelectorAll("button")].find((b) => b.textContent === "settings.save");
    expect((saveAfter as HTMLButtonElement).disabled).toBe(true);
  });

  it("does not apply a stale form-to-raw conversion over an intervening edit", async () => {
    // Load phase: serve the fuzzing config from disk.
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "read_config") return Promise.resolve("[fuzzing]\n");
      if (command === "config_toml_to_value") return Promise.resolve({ fuzzing: { ...FUZZING } });
      throw new Error(`Unexpected command during load: ${command}`);
    });

    await act(async () => {
      root.render(<I18nContext.Provider value={i18n}><SettingsView /></I18nContext.Provider>);
    });
    const nav = [...container.querySelectorAll("button")].find((b) => b.textContent === "settings.tab.fuzzing");
    expect(nav).toBeTruthy();
    await act(async () => { (nav as HTMLButtonElement).click(); });
    await flush();

    // First edit: enable coverage.
    await act(async () => { coverageSwitch().click(); });
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("true");

    // Start the form -> raw conversion, holding the serialize reply open.
    let resolveSerialize!: (value: string) => void;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "config_value_to_toml") {
        return new Promise<string>((resolve) => { resolveSerialize = resolve; });
      }
      throw new Error(`Unexpected command during conversion: ${command}`);
    });

    const toggle = container.querySelector<HTMLButtonElement>('button[aria-label="settings.toggleFormRaw"]');
    expect(toggle).toBeTruthy();
    await act(async () => { toggle!.click(); });

    // Intervening edit while still in form mode: disable coverage again.
    await act(async () => { coverageSwitch().click(); });
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("false");

    // The conversion completes for the stale snapshot.
    await act(async () => { resolveSerialize("[fuzzing]\n"); });
    await flush();

    // The stale conversion must neither switch to raw nor overwrite the edit.
    expect(coverageSwitch().getAttribute("aria-pressed")).toBe("false");
  });
});
