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
  expect(Object.keys(enExtra)).toHaveLength(2034);
  expect(Object.keys(zhExtra)).toHaveLength(2032);
  expect(dictionaryDigest(enExtra)).toBe("b4591767ec2300b7dc69725bb10571199f81789f7f30b0dc8e3d05bdfd4940f9");
  expect(dictionaryDigest(zhExtra)).toBe("a61c75e46d60cd5949a5676dea5f2614257247187111a2afe72e5c12c1fd5f0e");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
