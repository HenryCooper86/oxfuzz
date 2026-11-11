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
  expect(Object.keys(enExtra)).toHaveLength(2031);
  expect(Object.keys(zhExtra)).toHaveLength(2029);
  expect(dictionaryDigest(enExtra)).toBe("93c621b4a963cd23387b58d157106c0e35793d09a5ac9aacdc042c61641f1c01");
  expect(dictionaryDigest(zhExtra)).toBe("b4be9cc245a092eb1eace92a801f663346806c0c40f5eea0a6f7386dbdb941a9");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
