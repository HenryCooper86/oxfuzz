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
  expect(dictionaryDigest(enExtra)).toBe("471f589ecfa09109e22dcdf1ea0869b5c1bba17d860f53fb6f76afdd9539efd3");
  expect(dictionaryDigest(zhExtra)).toBe("c3cfe502ed9796899e72f9736b6641c4cfd0224d995521dab119c3ff3e525781");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
