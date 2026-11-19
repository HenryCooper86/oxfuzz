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
  expect(Object.keys(enExtra)).toHaveLength(2050);
  expect(Object.keys(zhExtra)).toHaveLength(2048);
  expect(dictionaryDigest(enExtra)).toBe("cb9a9fb4167cb7653cac2c2d7669636d4ee4ee43a266fdf003edecab1223c3a3");
  expect(dictionaryDigest(zhExtra)).toBe("8c9340ecb4bc98338891db2940889ac8135dd2e245aa924068c87718c272cb9b");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
