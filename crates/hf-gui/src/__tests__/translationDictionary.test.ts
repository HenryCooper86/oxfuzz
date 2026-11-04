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
  expect(Object.keys(enExtra)).toHaveLength(2007);
  expect(Object.keys(zhExtra)).toHaveLength(2005);
  expect(dictionaryDigest(enExtra)).toBe("bc82b38e3692eb8af9ebcfa623d9e9c0b51d211349a2d3d0d918634ce611c24b");
  expect(dictionaryDigest(zhExtra)).toBe("7a5d5acebdf9de95cf151c218deb43825bbb13e9d793585e1b1d278ab56557ab");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
