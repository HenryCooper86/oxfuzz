// @vitest-environment jsdom
import { act, lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { ErrorBoundary } from "../components/ErrorBoundary";

it("offers an exit when a deferred full-window view cannot load", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
  const exit = vi.fn();
  const Broken = lazy(async () => { throw new Error("Module download failed"); });
  const host = document.createElement("div");
  const root = createRoot(host);
  try {
    await act(async () => root.render(
      <ErrorBoundary recoveryAction={{ label: "Back to workspace", onClick: exit }}>
        <Suspense fallback={<p>Loading</p>}><Broken /></Suspense>
      </ErrorBoundary>,
    ));
    expect(host.textContent).toContain("Module download failed");
    const back = [...host.querySelectorAll("button")].find(button => button.textContent === "Back to workspace");
    expect(back).toBeTruthy();
    await act(async () => back!.click());
    expect(exit).toHaveBeenCalledOnce();
  } finally {
    await act(async () => root.unmount());
    errorLog.mockRestore();
    vi.unstubAllGlobals();
  }
});
