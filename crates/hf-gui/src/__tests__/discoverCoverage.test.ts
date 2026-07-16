import { describe, expect, it } from "vitest";
import { shouldLoadCoverage } from "../lib/discoverCoverage";

describe("discover coverage loading", () => {
  it("loads only when a call tree is being opened for the first time", () => {
    expect(shouldLoadCoverage(true, null, false, "/project")).toBe(true);
    expect(shouldLoadCoverage(false, null, false, "/project")).toBe(false);
    expect(shouldLoadCoverage(true, new Set(), false, "/project")).toBe(false);
    expect(shouldLoadCoverage(true, null, true, "/project")).toBe(false);
    expect(shouldLoadCoverage(true, null, false, "")).toBe(false);
  });
});
