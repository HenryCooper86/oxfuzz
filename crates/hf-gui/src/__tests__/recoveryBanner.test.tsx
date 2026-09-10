// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { RecoveryBanner } from "../components/RecoveryBanner";
import { I18nProvider } from "../i18n";
const invoke = vi.hoisted(() => vi.fn());
const environment = vi.hoisted(() => ({ native: true }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke }), isTauriEnvironment: () => environment.native }));
it("retries failed reads, opens the retained owner, and preserves failed dismissals", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const run = {run_id: "11111111-1111-4111-8111-111111111111",project:"/other/project",target:"parse",engine:"libfuzzer",started_at: 1};
  invoke.mockRejectedValueOnce(new Error("Journal unavailable")).mockResolvedValueOnce([run]).mockRejectedValueOnce(new Error("Cannot save dismissal"));
  const review = vi.fn(); const host=document.createElement("div"); document.body.append(host); const root=createRoot(host);
  const click = async (text: string) => { const button=[...host.querySelectorAll("button")].find(b=>b.textContent===text); expect(button,text).toBeTruthy(); await act(async()=>button!.click()); };
  try {
    await act(async()=>root.render(<I18nProvider><RecoveryBanner onReview={review}/></I18nProvider>));
    expect(host.textContent).toContain("Journal unavailable");
    await click("Retry"); expect(host.textContent).toContain("parse");
    await click("Review run"); expect(review).toHaveBeenCalledWith(run);
    expect(invoke).toHaveBeenCalledTimes(2);
    await click("Dismiss"); expect(host.textContent).toContain("Cannot save dismissal"); expect(host.textContent).toContain("parse");
    expect(host.textContent).not.toContain("intact");
  } finally { await act(async()=>root.unmount());host.remove();vi.unstubAllGlobals(); }
});

it("does not invoke desktop journal commands in browser mode", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); environment.native = false; invoke.mockClear();
  const host = document.createElement("div"); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><RecoveryBanner /></I18nProvider>));
    expect(invoke).not.toHaveBeenCalled(); expect(host.textContent).toBe("");
  } finally { await act(async () => root.unmount()); environment.native = true; vi.unstubAllGlobals(); }
});
