// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { GeneralTab } from "../components/settings/GeneralTab";
import { ReportsView } from "../views/ReportsView";
import { SetupWizard } from "../components/wizard/SetupWizard";
import { I18nProvider } from "../i18n";
const mocks = vi.hoisted(() => ({ desktop: false, invoke: vi.fn(async (command: string) => command === "app_paths" ? {config_dir:"<redacted-path>",data_dir:"<redacted-path>"} : []) }));
vi.mock("../lib", () => ({ isTauriEnvironment: () => mocks.desktop, getTransport: () => ({ invoke: mocks.invoke }), onDataChanged: () => () => {}, openExternal: vi.fn() }));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock("../providers/confirm", () => ({ useConfirm: () => vi.fn() }));
async function check(view: React.ReactNode, inspect: (host: HTMLElement) => void | Promise<void>) {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); const root = createRoot(host);
  try { await act(async () => root.render(<I18nProvider>{view}</I18nProvider>)); await inspect(host); }
  finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}
it("keeps web settings useful and gives each interactive preference a name", async () => {
  await check(<GeneralTab />, host => {
    expect(host.textContent).not.toContain("<redacted-path>");
    expect(host.textContent).not.toContain("Custom window decorations");
    expect(host.textContent).not.toContain("Changing this rebuilds");
    expect(host.querySelector('input[type="range"]')?.getAttribute("aria-label")).toBe("Font Size");
    expect(host.querySelector('[aria-pressed]')?.getAttribute("aria-label")).toBeTruthy();
  });
});
it("explains explicit report composition and offers navigation without promising unavailable formats", async () => {
  const navigate = vi.fn();
  await check(<ReportsView onNavigate={navigate} />, async host => {
    expect(host.textContent).toContain("Compose Report");
    expect(host.textContent).not.toContain("automatically");
    expect(host.textContent).not.toContain("PDF / DOCX");
    await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent === "Review findings")!.click());
    expect(navigate).toHaveBeenCalledWith("triage");
  });
});
it("offers offline help obtaining credentials before leaving setup", async () => {
  await check(<SetupWizard onComplete={vi.fn()} />, host => {
    expect(host.textContent).toContain("Where do I get an API key?");
    expect(host.textContent).toContain("model name");
  });
});
