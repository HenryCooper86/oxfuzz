import { describe, it, expect } from "vitest";
import { parseTargetArgs } from "../lib/parityBinary";

describe("binary target arguments", () => {
  it("splits the field on whitespace and keeps the @@ placeholder", () => {
    // Real tools take flags before the input file (Fuzzing101 runs
    // `tiffinfo -D -j -c -r -s -w @@`).
    expect(parseTargetArgs("  -D -j\t@@  ")).toEqual(["-D", "-j", "@@"]);
    expect(parseTargetArgs("")).toEqual([]);
  });
});
