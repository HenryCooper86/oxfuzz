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
  expect(Object.keys(enExtra)).toHaveLength(2069);
  expect(Object.keys(zhExtra)).toHaveLength(2067);
  expect(dictionaryDigest(enExtra)).toBe("c79a82974f000eda2991ea1184724e3c726a61d6d6f610e42db1cb5735e2d569");
  expect(dictionaryDigest(zhExtra)).toBe("9261a25868b7c7b05a770c3ca01570827b429dbec3c7b5ff044265ac14ae864b");
});
it("preserves deliberate missing Chinese entries and existing locale fallback", () => {
  expect(Object.keys(enExtra).filter(key => !(key in zhExtra)).sort()).toEqual(["triage.downloadRepro", "triage.reproSaved"]);
});
