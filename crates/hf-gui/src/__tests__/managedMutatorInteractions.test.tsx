// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ManagedMutatorPanel } from "../components/ManagedMutatorPanel";
const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }) }));
let host: HTMLDivElement;
let root: Root;
const imported = vi.fn();
const revision = "a8a7d885-7794-4836-ae66-c191c6de04a7";
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  imported.mockReset(); mocks.invoke.mockReset();
  mocks.invoke.mockImplementation(async (name: string) => name === "managed_mutator_status" ? { harness_id: revision, source: "size_t afl_custom_fuzz(void);", mutator: null } : { harness_id: "new", source: "native", mutator: null });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); });
async function mount(target = "parse") {
  await act(async () => root.render(<I18nProvider><ManagedMutatorPanel project="/project" target={target} engine="afl++" lang="c" harnessId={revision} disabled={false} onImported={imported} /></I18nProvider>));
}
async function submit() {
  const button = Array.from(host.querySelectorAll("button")).find(element => element.textContent === "Compile with mutator");
  expect(button).toBeDefined(); await act(async () => button!.click());
}
it("attaches source against the exact active revision and asks the parent to refresh qualification", async () => {
  await mount(); await submit();
  expect(mocks.invoke).toHaveBeenCalledWith("attach_managed_mutator", { project: "/project", target: "parse", engine: "afl++", expectedHarnessId: revision, source: "size_t afl_custom_fuzz(void);" });
  expect(imported).toHaveBeenCalledTimes(1);
  expect(host.textContent).toContain("needs smoke qualification and human approval");
});
it("ignores an attachment response after its selected harness panel is removed", async () => {
  let resolve: (value: unknown) => void = () => {};
  mocks.invoke.mockImplementation(async (name: string) => name === "managed_mutator_status" ? { harness_id: revision, source: "native", mutator: null } : new Promise(done => { resolve = done; }));
  await mount(); await submit();
  await act(async () => root.render(<div>Another target</div>));
  await act(async () => resolve({ harness_id: "new", source: "native", mutator: null }));
  expect(imported).not.toHaveBeenCalled();
  expect(host.textContent).toBe("Another target");
});

it("does not show an old status after switching the selected target", async () => {
  let resolve: (value: unknown) => void = () => {};
  mocks.invoke.mockImplementation(async (_name: string, args: {target: string}) => args.target === "parse" ? new Promise(done => { resolve = done; }) : { harness_id: "other", source: "new target source", mutator: null });
  await mount(); await mount("other");
  await act(async () => resolve({ harness_id: revision, source: "old target source", mutator: null }));
  expect(host.querySelector("textarea")?.value).toBe("new target source");
});
it("discards an old source file read after switching targets", async () => {
  let resolve: (value: string) => void = () => {};
  await mount();
  const input = host.querySelector('input[type="file"]')!;
  Object.defineProperty(input, "files", { value: [{ size: 10, text: () => new Promise<string>(done => { resolve = done; }) }] });
  await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
  await mount("other");
  await act(async () => resolve("stale file"));
  expect(host.querySelector("textarea")?.value).toBe("size_t afl_custom_fuzz(void);");
  expect(imported).not.toHaveBeenCalled();
});
