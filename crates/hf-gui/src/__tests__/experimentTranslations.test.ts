import { expect, it } from "vitest";
import { enExperiments, zhExperiments } from "../i18n.experiments";
it("pairs every experiment status, error, limitation and control in English and Chinese", () => {
  expect(Object.keys(enExperiments).sort()).toEqual(Object.keys(zhExperiments).sort());
  for (const key of Object.keys(enExperiments)) { expect(enExperiments[key].trim(),key).not.toBe(""); expect(zhExperiments[key].trim(),key).not.toBe(""); }
});
