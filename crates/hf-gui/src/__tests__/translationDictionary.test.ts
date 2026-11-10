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
  expect(Object.keys(enExtra)).toHaveLength(2054);
  expect(Object.keys(zhExtra)).toHaveLength(2052);
  expect(dictionaryDigest(enExtra)).toBe("4f33cb588b82f1dd5006da9c7303a603c37fc701e1fcc648113443baf1ec58f9");
  expect(dictionaryDigest(zhExtra)).toBe("df8dbbdac47c8130d7f5681fa6d782452d310f1092e42dea40ad2fda6840d3f5");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
