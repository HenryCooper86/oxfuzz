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
  expect(dictionaryDigest(enExtra)).toBe("6ae585b688d799452dd09af3002e371196da7dadceef145ab288d1f0e7f8beba");
  expect(dictionaryDigest(zhExtra)).toBe("fe6464d222dca9f56fb29cba328d62ca3cce3cb783ca06c9459ea77298a9f33a");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
