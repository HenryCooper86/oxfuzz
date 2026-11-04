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
  expect(Object.keys(enExtra)).toHaveLength(2019);
  expect(Object.keys(zhExtra)).toHaveLength(2017);
  expect(dictionaryDigest(enExtra)).toBe("f645026bbb2eeb1074c817c4bfa429f3d6be49d628b2fb5acfea7f3594bdf8df");
  expect(dictionaryDigest(zhExtra)).toBe("02df3822fd68e0519ce17137dee3e872b1312f8a1d252358fc84868029159f5d");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
