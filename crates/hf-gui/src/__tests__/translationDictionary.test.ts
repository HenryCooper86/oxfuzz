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
  expect(Object.keys(enExtra)).toHaveLength(1989);
  expect(Object.keys(zhExtra)).toHaveLength(1987);
  expect(dictionaryDigest(enExtra)).toBe("3b3e431f3e02692fbedd90bb59f748995a89005870895a264713c66c3394b9c3");
  expect(dictionaryDigest(zhExtra)).toBe("97522e194fcbb65c19c4013ede54ea265fdcf063a88b462dfd2b7c407b995879");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
