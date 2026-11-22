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
  expect(Object.keys(enExtra)).toHaveLength(2050);
  expect(Object.keys(zhExtra)).toHaveLength(2048);
  expect(dictionaryDigest(enExtra)).toBe("082aa3de269cf1dd988d8f6e4762c998bd6dfe9e00dea67bd2b7a80b152d816f");
  expect(dictionaryDigest(zhExtra)).toBe("2fd14fed51a94a538dbd444c89a7bf6b4f3f5fb883ac8f5b85be5afcd48d89e5");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
