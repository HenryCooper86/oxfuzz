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
  expect(Object.keys(enExtra)).toHaveLength(2058);
  expect(Object.keys(zhExtra)).toHaveLength(2056);
  expect(dictionaryDigest(enExtra)).toBe("cc72397c144f099a203bae3fde300f6de58946d01dd4735a1eadb189088e4966");
  expect(dictionaryDigest(zhExtra)).toBe("c10c81d18a8e88ebf7619ad90bf5f6503b00849bda3f7efccde42ef2a8743147");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
