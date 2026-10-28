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
  expect(Object.keys(enExtra)).toHaveLength(1971);
  expect(Object.keys(zhExtra)).toHaveLength(1969);
  expect(dictionaryDigest(enExtra)).toBe("0a5a211cc096fc08f966c89c226aec12b049fd3a7c8bdeecfc538ff6d7233544");
  expect(dictionaryDigest(zhExtra)).toBe("2bf5d255bf91370ad6330294d5cf506933848f78579166ecf7fdb599515c37da");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
