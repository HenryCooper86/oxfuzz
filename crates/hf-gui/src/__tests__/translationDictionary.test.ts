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
  expect(dictionaryDigest(enExtra)).toBe("5fa46c42bd5236366b17246f57802c254132ba09360ad1a1eb591c2e0715a511");
  expect(dictionaryDigest(zhExtra)).toBe("d386ecac235681d8349074d6402260efe167cf766867fa0bd8a933b97e9f5f60");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
