import { existsSync, readFileSync } from "node:fs";
import { expect, it } from "vitest";

// Coverage experiments and campaign advice were removed (2026-11-04 audit):
// no screen, transport mapping, or translation file may bring them back.
it("keeps retired features out of the GUI", () => {
  const transport = readFileSync(new URL("../lib/httpTransport.ts", import.meta.url), "utf8");
  expect(transport).not.toMatch(/coverage_experiment|campaign_advice/);
  expect(existsSync(new URL("../components/CoverageExperimentPanel.tsx", import.meta.url))).toBe(false);
  expect(existsSync(new URL("../i18n.experiments.ts", import.meta.url))).toBe(false);
});
