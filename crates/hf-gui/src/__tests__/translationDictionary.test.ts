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
  expect(Object.keys(enExtra)).toHaveLength(2065);
  expect(Object.keys(zhExtra)).toHaveLength(2063);
  expect(dictionaryDigest(enExtra)).toBe("101fd62a9c94d4b4eb7a7953ef0e8e45aeb648a32b3a2ee8b70f2691f371349f");
  expect(dictionaryDigest(zhExtra)).toBe("585f39729ec0173e232ce2fd6755029463ee405e47677a9c7a70df3def534471");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
