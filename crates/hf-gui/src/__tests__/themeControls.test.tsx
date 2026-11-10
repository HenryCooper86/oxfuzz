// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { Header } from "../components/Header";
import { GeneralTab } from "../components/settings/GeneralTab";
import { PrefsProvider } from "../providers/PrefsContext";
import { usePrefs } from "../providers/prefs";
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: async () => "linux/arm64" }), isTauriEnvironment: () => false }));
vi.mock("../i18nContext", () => ({ LOCALES: [], useI18n: () => ({ locale: "en", setLocale: vi.fn(), t: (key: string) => key }) }));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));
function Fixture({ settings }: { settings: boolean }) {
  const { theme, setTheme } = usePrefs();
  return settings ? <GeneralTab /> : <Header title="Workflow" theme={theme} onThemeChange={setTheme} />;
}
for (const settings of [false, true]) {
  it(`${settings ? "Settings" : "Header"} changes theme with each button press, without a dropdown`, async () => {
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    localStorage.clear(); localStorage.setItem("hf_theme", "dark");
    const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
    try {
      await act(async () => root.render(<PrefsProvider><Fixture settings={settings} /></PrefsProvider>));
      expect(host.querySelector('[role="combobox"][aria-label="settings.general.theme"]')).toBeNull();
      for (const [current, next] of [["Dark", "light"], ["Light", "system"], ["System", "dark"]]) {
        const button = host.querySelector<HTMLButtonElement>('button[aria-label^="settings.general.theme:"]');
        expect(button).not.toBeNull();
        expect(button?.textContent).toContain(`settings.general.theme${current}`);
        await act(async () => button!.click());
        expect(localStorage.getItem("hf_theme")).toBe(next);
      }
    } finally {
      await act(async () => root.unmount()); host.remove(); localStorage.clear(); vi.unstubAllGlobals();
    }
  });
}
