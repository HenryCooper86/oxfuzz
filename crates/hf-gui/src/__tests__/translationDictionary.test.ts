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
  expect(Object.keys(enExtra)).toHaveLength(2067);
  expect(Object.keys(zhExtra)).toHaveLength(2065);
  expect(dictionaryDigest(enExtra)).toBe("77570910925ab835cf37e7b1d9fa2fd1b1b18e4f8199e57151e413075d2fe00e");
  expect(dictionaryDigest(zhExtra)).toBe("ee26d80c263e448aaaf3f731065fa21fc9a65d40b518797fde139d50441f6b08");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
