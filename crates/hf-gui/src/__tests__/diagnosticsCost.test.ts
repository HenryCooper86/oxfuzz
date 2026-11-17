import { expect, it } from "vitest";
import { formatCost } from "../lib/cost";

// A model with no configured price reports a cost of zero. Showing "$0" beside
// 30.7k tokens told the operator the calls were free.
it("does not present unpriced usage as free", () => {
  expect(formatCost(0, 30_700)).toBeNull();
  expect(formatCost(0, 0)).toBe("$0");
  expect(formatCost(0.0042, 30_700)).toBe("$0.0042");
  expect(formatCost(1.5, 30_700)).toBe("$1.50");
});
