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
  expect(Object.keys(enExtra)).toHaveLength(2030);
  expect(Object.keys(zhExtra)).toHaveLength(2028);
  expect(dictionaryDigest(enExtra)).toBe("f1568de0c9b54d6b0100bda98f942c460e2c657d0586ec4f6f74b5bc0c12c1b6");
  expect(dictionaryDigest(zhExtra)).toBe("0e273ade409ea41f23f6d3205bad62d13141a1e85b4234088477bf82610452d0");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
