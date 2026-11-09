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
  expect(Object.keys(enExtra)).toHaveLength(2035);
  expect(Object.keys(zhExtra)).toHaveLength(2033);
  expect(dictionaryDigest(enExtra)).toBe("7d22c119802f2ad64aff68ddd69517a0b1a47d06e63e9115f2f81b586cedb22a");
  expect(dictionaryDigest(zhExtra)).toBe("ad80ac43da702c946fe0ff9b9d8ad3c0ac6de4b2e4a7575d70ab26d2b99f0e2b");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
