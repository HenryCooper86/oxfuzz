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
  expect(Object.keys(enExtra)).toHaveLength(1970);
  expect(Object.keys(zhExtra)).toHaveLength(1968);
  expect(dictionaryDigest(enExtra)).toBe("5ec8fd56652a2bb87bf1f2507e65247fbc725ddf6b78cd9ab2371e09ed84f393");
  expect(dictionaryDigest(zhExtra)).toBe("db4a24e33b30c231aa0ed7cbaa2644fd4b327fce83066d5aa9da84b0c70fee2f");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
