import { expect, it } from "vitest";
import { formatRunStat } from "../lib/runStats";

it("drops the fraction of a fast mean exec rate, like the rates beside it", () => {
  expect(formatRunStat(206727.692)).toBe("206,728");
  expect(formatRunStat(235709)).toBe("235,709");
});

it("keeps one decimal place for a slow rate, where it is the measurement", () => {
  expect(formatRunStat(62.5)).toBe("62.5");
  expect(formatRunStat(62.456)).toBe("62.5");
  expect(formatRunStat(9)).toBe("9");
  expect(formatRunStat(0)).toBe("0");
});
