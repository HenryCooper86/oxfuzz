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
  expect(Object.keys(enExtra)).toHaveLength(2045);
  expect(Object.keys(zhExtra)).toHaveLength(2043);
  expect(dictionaryDigest(enExtra)).toBe("5ddd4cab2d81ab1afc04a873412c3e2b46dd2ec1b17d225b243f11fc2eee282f");
  expect(dictionaryDigest(zhExtra)).toBe("8f4796deb97882c991221cdb685cecd134c61d48363bc215dcdd5c468d8934b1");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
