// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SetupWizard } from "../components/wizard/SetupWizard";
import { I18nProvider } from "../i18n";
import { normalizeProvider } from "../components/settings/providerTypes";
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), desktop: true }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke, listen: async () => () => {} }), isTauriEnvironment: () => mocks.desktop }));
let cleanup = async () => {};
const ready = { runtime_ready: true, status: { docker: true, sandbox_image: true, libfuzzer: true, aflplusplus: false, honggfuzz: false, syzkaller: false, defectdojo: false } };
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.clear(); mocks.desktop = true;
  mocks.invoke.mockReset().mockImplementation(async command => command === "setup_providers" ? [] : command === "setup_readiness" ? ready : command === "provider_test" ? "Connected" : undefined);
});
afterEach(async () => { await cleanup(); cleanup = async () => {}; vi.unstubAllGlobals(); });
async function mount() {
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host); const complete = vi.fn();
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  await act(async () => root.render(<I18nProvider><SetupWizard onComplete={complete} /></I18nProvider>));
  const click = async (text: string) => {
    const button = [...host.querySelectorAll("button")].find(button => button.textContent === text);
    expect(button, host.textContent ?? "").toBeTruthy(); await act(async () => button!.click());
  };
  const fill = async (label: string, value: string) => {
    const fieldLabel = [...host.querySelectorAll("label")].find(node => node.textContent?.startsWith(label));
    expect(fieldLabel?.htmlFor).toBeTruthy(); const input = host.querySelector<HTMLInputElement>(`#${fieldLabel!.htmlFor}`)!;
    await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
  };
  return { host, complete, click, fill };
}
it("defers setup explicitly without saving providers or claiming completion", async () => {
  const { host, complete, click } = await mount();
  expect(host.textContent).toContain("AI connection");
  expect(host.textContent).not.toContain("DefectDojo");
  await click("Set up later");
  expect(complete).toHaveBeenCalledWith("deferred");
  expect(mocks.invoke.mock.calls.some(([command]) => command === "initialize_provider")).toBe(false);
});
it("preserves an existing provider pool and requires service readiness before finishing", async () => {
  mocks.invoke.mockImplementation(async command => command === "setup_providers" ? [normalizeProvider({ id: "existing", model: "retained-model" })] : command === "setup_readiness" ? { ...ready, runtime_ready: false } : undefined);
  const { host, click, complete } = await mount();
  expect(host.textContent).toContain("retained-model"); await click("Continue");
  expect(document.activeElement?.textContent).toBe("Sandbox");
  expect([...host.querySelectorAll("button")].find(button => button.textContent === "Continue")?.disabled).toBe(true);
  expect(complete).not.toHaveBeenCalled();
  expect(mocks.invoke.mock.calls.some(([command]) => command === "initialize_provider")).toBe(false);
});
it("ignores a late successful probe after the configuration changes", async () => {
  let finish: ((value: string) => void) | undefined;
  mocks.invoke.mockImplementation(async command => command === "setup_providers" ? [] : command === "provider_test" ? new Promise<string>(resolve => { finish = resolve; }) : ready);
  const { host, click, fill } = await mount();
  await fill("API key", "fixture-key"); await click("Test connection"); await fill("Model", "changed-model");
  await act(async () => finish!("Connected"));
  expect([...host.querySelectorAll("button")].find(button => button.textContent === "Save and continue")?.disabled).toBe(true);
  expect(host.textContent).not.toContain("Connection verified");
});
it("saves only an explicitly tested first provider then opens the project workflow", async () => {
  const { host, click, fill, complete } = await mount();
  await fill("API key", "fixture-key"); await click("Test connection");
  expect(host.textContent).toContain("Connection verified"); await click("Save and continue");
  expect(mocks.invoke.mock.calls.filter(([command]) => command === "initialize_provider")).toHaveLength(1);
  await click("Continue"); await click("Open project workflow");
  expect(complete).toHaveBeenCalledWith("complete");
});
it("offers server recheck rather than a fake preparation operation in web mode", async () => {
  mocks.desktop = false;
  mocks.invoke.mockImplementation(async command => command === "setup_providers" ? [normalizeProvider({ id: "existing" })] : { ...ready, runtime_ready: false });
  const { host, click } = await mount(); await click("Continue");
  expect(host.textContent).toContain("server administrator");
  expect(host.textContent).not.toContain("Prepare sandbox"); await click("Check again");
  expect(mocks.invoke.mock.calls.some(([command]) => command === "ensure_docker")).toBe(false);
});
it("discards readiness from before sandbox preparation even when preparation fails", async () => {
  let finishCheck: ((value: typeof ready) => void) | undefined;
  let failPrepare: ((error: Error) => void) | undefined;
  mocks.invoke.mockImplementation(async command => command === "setup_providers" ? [normalizeProvider({ id: "existing" })] : command === "setup_readiness" ? new Promise(resolve => { finishCheck = resolve; }) : new Promise((_, reject) => { failPrepare = reject; }));
  const { host, click } = await mount(); await click("Continue"); await click("Prepare sandbox");
  await act(async () => finishCheck!(ready));
  await act(async () => failPrepare!(new Error("Preparation failed")));
  expect(host.textContent).toContain("Preparation failed");
  expect(host.textContent).toContain("Prepare sandbox");
  expect([...host.querySelectorAll("button")].find(button => button.textContent === "Continue")?.disabled).toBe(true);
});
it("does not overwrite a provider pool added while the connection was being tested", async () => {
  const { host, click, fill } = await mount();
  await fill("API key", "fixture-key"); await click("Test connection");
  mocks.invoke.mockRejectedValue(new Error("Provider configuration already exists"));
  await click("Save and continue");
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("Provider configuration already exists");
  expect(mocks.invoke.mock.calls.filter(([command]) => command === "initialize_provider")).toHaveLength(1);
  expect(host.textContent).toContain("AI connection");
});
