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
  expect(dictionaryDigest(enExtra)).toBe("8f7d4194fba21f967cd134f161ac82cf0c1526b86267e1d1f48de4a04b107f4b");
  expect(dictionaryDigest(zhExtra)).toBe("5156700819b84e9995b045d9c129478c50dbd053cde32e4b5b32e409d1b25481");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
