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
  expect(Object.keys(enExtra)).toHaveLength(2036);
  expect(Object.keys(zhExtra)).toHaveLength(2034);
  expect(dictionaryDigest(enExtra)).toBe("cb779b206f45a23044eaf1daa9841a66383797825439caa1261767a2e8dbd7d2");
  expect(dictionaryDigest(zhExtra)).toBe("ec8507a48015ae22b2dd3e9627f954361d3ee513ec736a3895261d338846a695");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
