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
  expect(Object.keys(enExtra)).toHaveLength(2032);
  expect(Object.keys(zhExtra)).toHaveLength(2030);
  expect(dictionaryDigest(enExtra)).toBe("ed89fbc40de29fde160672147526ec032877ec6ff1033f90e119782cb9591802");
  expect(dictionaryDigest(zhExtra)).toBe("7815b8344835474eb9fbb8d8555260a32b69f6bedf8ecb71a0b5017bfdd3dc46");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
