// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { DefectDojoView } from "../views/DefectDojoView";
import { I18nProvider } from "../i18n";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", () => ({ getTransport: () => ({ invoke, listen: async () => () => {} }), isTauriEnvironment: () => true }));

it("reports a failed status check with Retry instead of checking forever", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  let failing = true;
  invoke.mockImplementation(async (command: string) => {
    if (command === "defectdojo_status") {
      if (failing) throw new Error("status endpoint unreachable");
      return { state: "stopped", managed: false, url: "http://localhost:8080", message: "DefectDojo is stopped" };
    }
    return null;
  });
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  const flush = async () => act(async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); });
  try {
    await act(async () => root.render(<I18nProvider><DefectDojoView onBack={vi.fn()} /></I18nProvider>));
    await flush();
    expect(host.textContent).toContain("Could not check DefectDojo");
    expect(host.textContent).toContain("status endpoint unreachable");
    failing = false;
    await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent === "Retry")!.click());
    await flush();
    expect(host.textContent).toContain("DefectDojo is stopped");
    expect(host.textContent).not.toContain("Could not check DefectDojo");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
