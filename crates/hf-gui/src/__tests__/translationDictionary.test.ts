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
  expect(Object.keys(enExtra)).toHaveLength(2029);
  expect(Object.keys(zhExtra)).toHaveLength(2027);
  expect(dictionaryDigest(enExtra)).toBe("88129f7dc7c1bcb3dd19dfbb359b934930fd35069cb6c29548e4d6ae95603d8f");
  expect(dictionaryDigest(zhExtra)).toBe("22e60732fc7a16b1d9d340548e2f91cb769c313df61c3a87690a2c6a772c46d7");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
