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
  expect(Object.keys(enExtra)).toHaveLength(2024);
  expect(Object.keys(zhExtra)).toHaveLength(2022);
  expect(dictionaryDigest(enExtra)).toBe("70f3e452aef702c7e80cb344e6ba34b6cddabbd3aee6eac4dd57df30d15e671e");
  expect(dictionaryDigest(zhExtra)).toBe("717a93583eadc57ecb6780901dbca5dc8789f1109f96d29fb01a50b7263e237c");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
