// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import { useI18n } from "../i18nContext";
import { enExtra } from "../i18n.extra";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem("hf_locale", "zh");
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  localStorage.clear();
});

describe("i18n locale fallback", () => {
  it("falls back to the full English dictionary before the raw key", async () => {
    let translated: Record<string, string> = {};
    function Probe() {
      const { t, locale } = useI18n();
      translated = {
        locale,
        repro: t("triage.downloadRepro"),
        saved: t("triage.reproSaved", { path: "/tmp/repro" }),
        missing: t("no.such.key"),
      };
      return null;
    }
    await act(async () => {
      root.render(
        <I18nProvider>
          <Probe />
        </I18nProvider>,
      );
    });

    // Keys that exist only in the extra dictionary (deliberately without a
    // Chinese entry) must render the English extra value, not the raw key.
    expect(translated.locale).toBe("zh");
    expect(translated.repro).toBe(enExtra["triage.downloadRepro"]);
    expect(translated.saved).toBe("Reproduction bundle saved to /tmp/repro");
    // A key no dictionary knows still falls back to itself.
    expect(translated.missing).toBe("no.such.key");
  });
});
