// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { HelpView } from "../views/HelpView";
import { I18nProvider } from "../i18n";
it("supports compact help navigation without a second sidebar", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><HelpView /></I18nProvider>));
    const select = host.querySelector<HTMLSelectElement>('select[aria-label="Choose a help topic"]');
    expect(select).not.toBeNull();
    const option = [...select!.options].find(option => option.textContent === "First Run & Setup")!;
    await act(async () => { select!.value = option.value; select!.dispatchEvent(new Event("change", { bubbles: true })); });
    expect(host.querySelector(".markdown-body")?.textContent).toContain("The setup wizard, step by step");
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
