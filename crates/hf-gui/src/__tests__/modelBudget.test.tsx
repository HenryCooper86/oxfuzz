// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ModelBudgetSettings } from "../components/settings/ModelBudgetSettings";
import { ModelBudgetPanel } from "../components/ModelBudgetPanel";
const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }) }));
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const i18n = { locale: "en" as const, setLocale: () => undefined, t: (key: string) => key };
let container: HTMLDivElement;
let root: Root;
beforeEach(() => { mocks.invoke.mockReset(); container = document.createElement("div"); document.body.append(container); root = createRoot(container); });
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });
it("keeps exact decimal limits in the existing settings draft", async () => {
  const onChange = vi.fn();
  const value = { unrelated: { keep: true }, model_budget: { scope_id: "trial", max_tokens: "9007199254740993" } };
  await act(async () => root.render(<I18nContext.Provider value={i18n}><ModelBudgetSettings value={value} onChange={onChange} /></I18nContext.Provider>));
  const input = container.querySelector<HTMLInputElement>('input[aria-label="budget.max_tokens"]')!;
  expect(input.value).toBe("9007199254740993");
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "9007199254740995"); input.dispatchEvent(new Event("input", { bubbles: true })); });
  expect(onChange).toHaveBeenCalledWith({ ...value, model_budget: { ...value.model_budget, max_tokens: "9007199254740995" } });
  expect(mocks.invoke).not.toHaveBeenCalled();
});
it("shows retained scope charges and denial without converting counters to numbers", async () => {
  mocks.invoke.mockResolvedValue({ available: true, settings: { scope_id: "trial-a", max_calls: "10", max_tokens: "9007199254740999", max_cost_microusd: null, max_output_tokens: "4096" }, usage: { scope_id: "trial-a", calls: "10", tokens: "9007199254740993", cost_microusd: "0", blocked: false, terminal_reason: "calls_exhausted" } });
  await act(async () => root.render(<I18nContext.Provider value={i18n}><ModelBudgetPanel /></I18nContext.Provider>));
  expect(mocks.invoke).toHaveBeenCalledWith("model_budget_view");
  expect(container.textContent).toContain("trial-a"); expect(container.textContent).toContain("9007199254740993"); expect(container.textContent).toContain("calls_exhausted");
});
it("keeps read errors visible and offers refresh", async () => {
  mocks.invoke.mockRejectedValue(new Error("ledger unavailable"));
  await act(async () => root.render(<I18nContext.Provider value={i18n}><ModelBudgetPanel /></I18nContext.Provider>));
  expect(container.querySelector('[role="alert"]')?.textContent).toContain("ledger unavailable"); expect(container.querySelector('button')?.textContent).toContain("common.refresh");
});
it("edits a dollar cost limit as exact micro-USD in the shared config draft", async () => {
  const onChange = vi.fn();
  const value = { model_budget: { scope_id: "trial", max_cost_microusd: "1000000" } };
  await act(async () => root.render(<I18nContext.Provider value={i18n}><ModelBudgetSettings value={value} onChange={onChange} /></I18nContext.Provider>));
  const input = container.querySelector<HTMLInputElement>('input[aria-label="budget.max_cost_microusd"]')!;
  expect(input.value).toBe("1.00");
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "2.50"); input.dispatchEvent(new Event("input", { bubbles: true })); });
  expect(onChange).toHaveBeenCalledWith({ model_budget: { scope_id: "trial", max_cost_microusd: "2500000" } });
});
it.each(["-1", "2.1234567"])("shows invalid dollar input %s and does not leave the prior limit savable", async (text) => {
  const onChange = vi.fn();
  const value = { model_budget: { max_cost_microusd: "1000000" } };
  const render = (next: Record<string, unknown>) => root.render(<I18nContext.Provider value={i18n}><ModelBudgetSettings value={next} onChange={onChange} /></I18nContext.Provider>);
  await act(async () => render(value));
  const input = container.querySelector<HTMLInputElement>('input[aria-label="budget.max_cost_microusd"]')!;
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, text); input.dispatchEvent(new Event("input", { bubbles: true })); });
  const draft = onChange.mock.lastCall![0];
  expect(draft.model_budget.max_cost_microusd).toBe(`invalid-usd:${text}`);
  await act(async () => render(draft));
  expect(input.value).toBe(text);
  expect(input.getAttribute("aria-invalid")).toBe("true");
  expect(container.querySelector('[role="alert"]')?.textContent).toContain("budget.invalidUsd");
});
it("displays exact dollar costs and dollar limits in Dashboard", async () => {
  mocks.invoke.mockResolvedValue({ available: true, settings: { scope_id: "trial", max_calls: null, max_tokens: null, max_cost_microusd: "9007199254740995", max_output_tokens: "4096" }, usage: { scope_id: "trial", calls: "1", tokens: "10", cost_microusd: "9007199254740993", blocked: false, terminal_reason: null } });
  await act(async () => root.render(<I18nContext.Provider value={i18n}><ModelBudgetPanel /></I18nContext.Provider>));
  expect(container.textContent).toContain("$9007199254.740993 / $9007199254.740995");
});
