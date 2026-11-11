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
  expect(Object.keys(enExtra)).toHaveLength(2073);
  expect(Object.keys(zhExtra)).toHaveLength(2071);
  expect(dictionaryDigest(enExtra)).toBe("b5200891a7df6871f68503f4172bee942533919c8cbfb9ac3308782d747c8fc9");
  expect(dictionaryDigest(zhExtra)).toBe("9b825ca8ed08987c9f0a3b9c13b6c79b323256e3537a9c51767afeaca88d2fc8");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
