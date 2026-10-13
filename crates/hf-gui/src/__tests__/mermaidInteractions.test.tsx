// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Mermaid } from "../components/Mermaid";

const renderer = vi.hoisted(() => ({ initialize: vi.fn(), render: vi.fn() }));
vi.mock("mermaid", () => ({ default: renderer }));

let host: HTMLDivElement;
let root: Root;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

async function render(code: string) {
  await act(async () => root.render(<Mermaid code={code} />));
}

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  renderer.render.mockReset();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.unstubAllGlobals();
});

describe("Mermaid diagram recovery", () => {
  it("replaces the source fallback when corrected code renders successfully", async () => {
    renderer.render.mockRejectedValueOnce(new Error("invalid graph"));
    await render("invalid graph");
    expect(host.querySelector("pre code")?.textContent).toBe("invalid graph");

    renderer.render.mockResolvedValueOnce({ svg: '<svg aria-label="corrected diagram"></svg>' });
    await render("graph TD; A-->B");

    expect(host.querySelector('svg[aria-label="corrected diagram"]')).not.toBeNull();
    expect(host.querySelector("pre")).toBeNull();
  });

  it("removes previous diagram output while a changed source is rendering", async () => {
    renderer.render.mockResolvedValueOnce({ svg: '<svg aria-label="previous diagram"></svg>' });
    await render("graph TD; A-->B");
    expect(host.querySelector("svg")).not.toBeNull();
    const pending = deferred<{ svg: string }>();
    renderer.render.mockReturnValueOnce(pending.promise);
    await render("graph TD; C-->D");

    expect(host.querySelector("svg")).toBeNull();
    await act(async () => pending.resolve({ svg: '<svg aria-label="current diagram"></svg>' }));
    expect(host.querySelector('svg[aria-label="current diagram"]')).not.toBeNull();
  });

  it.each(["success", "failure"])("ignores obsolete render %s after newer code succeeds", async (outcome) => {
    const pending = deferred<{ svg: string }>();
    renderer.render.mockReturnValueOnce(pending.promise);
    await render("graph TD; old-->diagram");
    renderer.render.mockResolvedValueOnce({ svg: '<svg aria-label="current diagram"></svg>' });
    await render("graph TD; current-->diagram");
    await act(async () => {
      if (outcome === "success") pending.resolve({ svg: '<svg aria-label="old diagram"></svg>' });
      else pending.reject(new Error("old diagram failed"));
    });

    expect(host.querySelector('svg[aria-label="current diagram"]')).not.toBeNull();
    expect(host.querySelector('svg[aria-label="old diagram"]')).toBeNull();
    expect(host.querySelector("pre")).toBeNull();
  });
});
