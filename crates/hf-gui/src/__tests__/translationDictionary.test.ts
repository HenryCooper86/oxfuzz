import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { enExtra, zhExtra } from "../i18n.extra";

function dictionaryDigest(dictionary: Record<string, string>) {
  const sorted = Object.entries(dictionary).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  return createHash("sha256").update(JSON.stringify(sorted)).digest("hex");
}

// Captured before deduplicating the shipped translation table. Changing user-facing
// text intentionally requires reviewing and updating these characterization values.
it("preserves every shipped English and Chinese key and value", () => {
  expect(Object.keys(enExtra)).toHaveLength(2050);
  expect(Object.keys(zhExtra)).toHaveLength(2048);
  expect(dictionaryDigest(enExtra)).toBe("4448143558f2c1ff36ea0e0c35f389dca701f86d713fd400d7858ed2a4add016");
  expect(dictionaryDigest(zhExtra)).toBe("f1c7fe26b60d3e1b1dd5d6d36ebf3187023ad064d3ebfaec7ba73f4f239a4a77");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
