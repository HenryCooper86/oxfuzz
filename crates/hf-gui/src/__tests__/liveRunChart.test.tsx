// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { CoverageCurve } from "../components/CoverageCurve";
import { I18nProvider } from "../i18n";

it("draws the shared coverage curve from service samples", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><CoverageCurve samples={[{ t: 0, edges: 0, execs: 0 }, { t: 30, edges: 120, execs: 900 }]} /></I18nProvider>));
    expect(host.querySelector("svg path")).not.toBeNull();
    expect(host.textContent).toContain("120");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});

it("shows coverage over time on the Run page while the run streams", () => {
  const run = readFileSync(resolve(__dirname, "../views/RunView.tsx"), "utf8");
  expect(run).toMatch(/coverageSeries\.length >= 2 && <[^>]*>?\s*<CoverageCurve samples=\{coverageSeries\}/);
});
