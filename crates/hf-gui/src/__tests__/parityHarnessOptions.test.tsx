// @vitest-environment jsdom
import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { HarnessOptionsPanel } from "../components/HarnessOptionsPanel";
import { HarnessRevisionActions } from "../components/HarnessRevisionActions";
import { ManagedMutatorPanel } from "../components/ManagedMutatorPanel";
import { BuildProfileEditor } from "../components/BuildProfileEditor";
import { buildOptionsFor, clampRepairs, DEFAULT_HARNESS_OPTIONS, needsSmokeOptions } from "../lib/parityHarness";

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }) }));

let host: HTMLDivElement;
let root: Root;
const revision = "a8a7d885-7794-4836-ae66-c191c6de04a7";
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  mocks.invoke.mockReset();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); });

const byLabel = (label: string) => host.querySelector(`[aria-label="${label}"]`) as HTMLInputElement;
const button = (text: string) => Array.from(host.querySelectorAll("button")).find((b) => b.textContent === text) as HTMLButtonElement;
async function setValue(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  await act(async () => { Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value); el.dispatchEvent(new Event("input", { bubbles: true })); });
}

it("maps options to the build argument and keeps defaults omitted", () => {
  expect(buildOptionsFor(DEFAULT_HARNESS_OPTIONS, "afl++")).toBeUndefined();
  expect(buildOptionsFor({ ...DEFAULT_HARNESS_OPTIONS, sanitizer: "thread" }, "libfuzzer")).toEqual({ sanitizer: "thread" });
  expect(buildOptionsFor({ ...DEFAULT_HARNESS_OPTIONS, cmplog: true, persistent: true }, "afl++")).toEqual({ cmplog: true, persistent: true });
  expect(buildOptionsFor({ ...DEFAULT_HARNESS_OPTIONS, cmplog: true, persistent: true }, "libfuzzer")).toBeUndefined();
  expect(needsSmokeOptions(DEFAULT_HARNESS_OPTIONS)).toBe(false);
  expect(needsSmokeOptions({ ...DEFAULT_HARNESS_OPTIONS, repairs: 2 })).toBe(true);
  expect(needsSmokeOptions({ ...DEFAULT_HARNESS_OPTIONS, skipModelReview: true })).toBe(true);
  expect(clampRepairs(9)).toBe(5);
  expect(clampRepairs(-3)).toBe(0);
});

function Options({ engine }: { engine: string }) {
  const [value, setValue] = useState(DEFAULT_HARNESS_OPTIONS);
  return <I18nProvider><HarnessOptionsPanel value={value} onChange={setValue} engine={engine} disabled={false} /><output data-testid="v">{JSON.stringify(value)}</output></I18nProvider>;
}
const state = () => JSON.parse(host.querySelector("output")!.textContent!);

it("limits CmpLog and persistent mode to AFL++ and clamps repairs", async () => {
  await act(async () => root.render(<Options engine="libfuzzer" />));
  expect(byLabel("CmpLog companion").disabled).toBe(true);
  expect(byLabel("Persistent mode").disabled).toBe(true);
  await act(async () => root.render(<Options engine="afl++" />));
  await act(async () => byLabel("CmpLog companion").click());
  await setValue(byLabel("Repair attempts"), "9");
  await act(async () => byLabel("Skip the model review").click());
  expect(state()).toMatchObject({ cmplog: true, repairs: 5, skipModelReview: true });
  expect(host.textContent).toContain("audit trail");
  expect(host.textContent).toContain("human approval is still required");
});

it("refines and adopts through the typed commands", async () => {
  mocks.invoke.mockImplementation(async (name: string) => name === "harness_refine" ? { status: "Compiled", harness_id: "new", repairs_used: 1, lint: [] } : { status: "Compiled" });
  const changed = vi.fn();
  await act(async () => root.render(<I18nProvider><HarnessRevisionActions project="/p" target="parse" engine="afl++" lang="c" ai="auto" repairs={0} disabled={false} onChanged={changed} /></I18nProvider>));
  await act(async () => button("Refine for coverage").click());
  expect(mocks.invoke).toHaveBeenCalledWith("harness_refine", { project: "/p", target: "parse", engine: "afl++", lang: "c", repairs: 0, ai: "auto" });
  expect(changed).toHaveBeenCalledTimes(1);
  expect(host.textContent).toContain("needs a new smoke test and human approval");
  expect(button("Adopt revision").disabled).toBe(true);
  await setValue(byLabel("Harness revision id"), "not-a-uuid");
  await act(async () => button("Adopt revision").click());
  expect(mocks.invoke).not.toHaveBeenCalledWith("harness_adopt_revision", expect.anything());
  await setValue(byLabel("Harness revision id"), revision);
  await act(async () => button("Adopt revision").click());
  expect(mocks.invoke).toHaveBeenCalledWith("harness_adopt_revision", { project: "/p", target: "parse", engine: "afl++", lang: "c", harnessId: revision });
  expect(changed).toHaveBeenCalledTimes(2);
});

it("previews and attaches a grammar mutator against the active revision", async () => {
  mocks.invoke.mockImplementation(async (name: string) => {
    if (name === "managed_mutator_status") return { harness_id: revision, source: "native", mutator: null };
    if (name === "grammar_mutator_source") return "/* generated */";
    return { harness_id: "new", source: "native", mutator: null };
  });
  const imported = vi.fn();
  await act(async () => root.render(<I18nProvider><ManagedMutatorPanel project="/p" target="parse" engine="afl++" lang="c" harnessId={revision} disabled={false} onImported={imported} /></I18nProvider>));
  await setValue(byLabel("BNF grammar") as unknown as HTMLTextAreaElement, "<a> ::= 'x'");
  await act(async () => button("Preview generated source").click());
  expect(mocks.invoke).toHaveBeenCalledWith("grammar_mutator_source", { grammar: "<a> ::= 'x'", engine: "afl++" });
  expect(host.textContent).toContain("/* generated */");
  await act(async () => button("Attach grammar mutator").click());
  expect(mocks.invoke).toHaveBeenCalledWith("attach_grammar_mutator", { project: "/p", target: "parse", engine: "afl++", expectedHarnessId: revision, grammar: "<a> ::= 'x'" });
  expect(imported).toHaveBeenCalledTimes(1);
});

it("offers meson, autotools and bazel in the build profile editor", async () => {
  await act(async () => root.render(<I18nProvider><BuildProfileEditor profile={null} busy={false} onSave={async () => {}} /></I18nProvider>));
  const values = Array.from(host.querySelectorAll('select[aria-label="Build system"] option')).map((o) => (o as HTMLOptionElement).value);
  expect(values).toEqual(["cmake", "make", "meson", "autotools", "bazel"]);
});
