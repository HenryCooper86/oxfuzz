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
  expect(Object.keys(enExtra)).toHaveLength(2072);
  expect(Object.keys(zhExtra)).toHaveLength(2070);
  expect(dictionaryDigest(enExtra)).toBe("307da232bc97a400758d45eb9d26a5d8340b0db0a5429fca24347da834184a0b");
  expect(dictionaryDigest(zhExtra)).toBe("0b3a5a273fc28ff369080f7e3c8d0bbeb2fa79c58dc6ee7c72272cd0d36328ce");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
