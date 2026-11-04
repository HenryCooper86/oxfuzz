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
  expect(Object.keys(enExtra)).toHaveLength(2001);
  expect(Object.keys(zhExtra)).toHaveLength(1999);
  expect(dictionaryDigest(enExtra)).toBe("769ad12b5ec0d0c285e590431a26df68a0e4bb6648f7aa9541000a4e79dee9f6");
  expect(dictionaryDigest(zhExtra)).toBe("abc0948fca019f03d53358277dbe2bcda7c4b1d1369acf6d8eae9fca405aad89");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
