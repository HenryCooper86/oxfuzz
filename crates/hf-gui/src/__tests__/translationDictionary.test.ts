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
  expect(Object.keys(enExtra)).toHaveLength(1993);
  expect(Object.keys(zhExtra)).toHaveLength(1991);
  expect(dictionaryDigest(enExtra)).toBe("e706d0699e74a6fb086c1d97c33c1156fd025615240d60da3bf62f063692240e");
  expect(dictionaryDigest(zhExtra)).toBe("17724197a1ec3714ed9821e529777ec23f1c155a0d1a4aff9292aaaba451acda");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
