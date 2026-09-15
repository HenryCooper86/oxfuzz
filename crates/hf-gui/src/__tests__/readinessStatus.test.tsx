// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { StatusBar } from "../components/StatusBar";
import { I18nProvider } from "../i18n";
const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke, listen: async () => () => {} }), useDefectDojo: () => ({ configured: false }) }));
vi.mock("../providers/prefs", () => ({ usePrefs: () => ({ sandboxArch: "linux/arm64" }) }));
vi.mock("../providers/runStatus", () => ({ useRunStatus: () => ({ activeEngine: null }) }));
it("marks readiness unknown after polling fails and restores it without preparing Docker", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); vi.useFakeTimers();
  const host = document.createElement("div"); const root = createRoot(host);
  let offline = false;
  mocks.invoke.mockImplementation(async command => {
    if (offline) throw new Error("offline");
    return command === "system_status_cmd" || command === "ensure_docker" ? { docker: true, sandbox_image: true, libfuzzer: true } : { cost_usd: 0 };
  });
  try {
    await act(async () => root.render(<I18nProvider><StatusBar /></I18nProvider>));
    expect(mocks.invoke.mock.calls.some(([command]) => command === "ensure_docker")).toBe(false);
    expect(host.textContent).toContain("Docker");
    offline = true;
    await act(async () => vi.advanceTimersByTimeAsync(5000));
    expect(host.textContent).toContain("Service disconnected");
    expect(host.textContent).not.toContain("libFuzzer");
    offline = false;
    await act(async () => vi.advanceTimersByTimeAsync(5000));
    expect(host.textContent).not.toContain("Service disconnected");
    expect(host.textContent).toContain("libFuzzer");
  } finally { await act(async () => root.unmount()); vi.useRealTimers(); vi.unstubAllGlobals(); }
});
