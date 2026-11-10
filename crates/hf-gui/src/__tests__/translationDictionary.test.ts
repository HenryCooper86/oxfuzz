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
  expect(Object.keys(enExtra)).toHaveLength(2061);
  expect(Object.keys(zhExtra)).toHaveLength(2059);
  expect(dictionaryDigest(enExtra)).toBe("57bfb360eefd033539bc4c68710b43e100f438336359651c1343b7e216c311b5");
  expect(dictionaryDigest(zhExtra)).toBe("35b3271f6301425e6b2b4f51c7ce079f2dd44f5623300d2da599ca1884928cc9");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
