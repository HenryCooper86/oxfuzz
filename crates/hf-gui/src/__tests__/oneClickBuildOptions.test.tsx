import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { enParityLanguages, zhParityLanguages } from "../i18n.parityLanguages";

const source = readFileSync(new URL("../components/OneClickFuzz.tsx", import.meta.url), "utf8");

it("sends the fuzz command's build options only when the user set them", () => {
  expect(source).toContain("if (sanitizer) build.sanitizer = sanitizer;");
  expect(source).toContain('if (cmplog && requestEngine === "afl++") build.cmplog = true;');
  expect(source).toContain("if (Object.keys(build).length > 0) request.build = build;");
  expect(source).toContain("if (skipModelReview) request.skipModelReview = true;");
});

it("labels the one-click build options in both languages", () => {
  for (const key of ["parity.lang.sanitizer", "parity.lang.sanitizerDefault", "parity.lang.cmplog", "parity.lang.skipModelReview"]) {
    expect(enParityLanguages[key]).toBeTruthy();
    expect(zhParityLanguages[key]).toBeTruthy();
  }
});
