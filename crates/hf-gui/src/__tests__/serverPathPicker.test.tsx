// @vitest-environment jsdom
import { act } from "react";
import { expect, it, vi } from "vitest";
import { pickServerPath } from "../lib/serverPathPicker";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", () => ({ getTransport: () => ({ invoke }) }));
it("validates a server folder, keeps failures open, and returns its canonical path", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  invoke.mockRejectedValueOnce(new Error("outside approved projects")).mockResolvedValueOnce({ project: "/approved/sample" });
  let result: Promise<string | null>;
  await act(async () => { result = pickServerPath("folder"); });
  const input = document.querySelector<HTMLInputElement>('[aria-label="Folder path on the server"]')!;
  expect(input).not.toBeNull();
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "/requested/sample"); input.dispatchEvent(new Event("input", { bubbles: true })); });
  const submit = () => document.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await act(async () => { submit(); });
  expect(document.querySelector('[role="alert"]')?.textContent).toContain("outside approved");
  await act(async () => { submit(); });
  expect(await result!).toBe("/approved/sample");
  expect(invoke).toHaveBeenCalledWith("select_project", { project: "/requested/sample" });
  vi.unstubAllGlobals();
});
it("settles cancellation without reading a client file or contacting the service", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); invoke.mockClear();
  let result: Promise<string | null>;
  await act(async () => { result = pickServerPath("file"); });
  await act(async () => [...document.querySelectorAll("button")].find(b => b.textContent === "Cancel")!.click());
  expect(await result!).toBeNull(); expect(invoke).not.toHaveBeenCalled();
  vi.unstubAllGlobals();
});
