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
  expect(Object.keys(enExtra)).toHaveLength(1988);
  expect(Object.keys(zhExtra)).toHaveLength(1986);
  expect(dictionaryDigest(enExtra)).toBe("f7dc4749f9232d254603ea651b842f00f3002cea8cf9de5cd1956022e0502aea");
  expect(dictionaryDigest(zhExtra)).toBe("d10a6a9261f9b60730d108c425f28c97452e26c84ea66b2a14ab30ee698ce662");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
