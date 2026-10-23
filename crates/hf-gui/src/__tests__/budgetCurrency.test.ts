import { expect, it } from "vitest";
import { formatMicroUsd, parseUsdLimit } from "../lib/budgetCurrency";
it("converts dollar input to exact micro-USD without number rounding", () => {
  expect(parseUsdLimit("2.50")).toEqual({ valid: true, microUsd: "2500000" });
  expect(parseUsdLimit("9007199254.740993")).toEqual({ valid: true, microUsd: "9007199254740993" });
  expect(parseUsdLimit("0.000001")).toEqual({ valid: true, microUsd: "1" });
  expect(parseUsdLimit("")).toEqual({ valid: true, microUsd: undefined });
});
it("formats the full stored precision with a minimum of two decimal places", () => {
  expect(formatMicroUsd("9007199254740993")).toBe("9007199254.740993");
  expect(formatMicroUsd("2500000")).toBe("2.50");
  expect(formatMicroUsd("0")).toBe("0.00");
  expect(formatMicroUsd("1")).toBe("0.000001");
});
it("rejects negative, zero, excess precision and nondecimal input", () => {
  for (const input of ["-1", "0", "2.1234567", "1e3", "2,50", "NaN"]) expect(parseUsdLimit(input)).toEqual({ valid: false });
});
