/**
 * Text for a run stat tile. A whole-run mean is a quotient: at fuzzing speeds
 * its fraction is noise next to the integer current and peak rates beside it,
 * but a slow target (a kernel VM, a heavy parser) runs at tens of execs per
 * second, where one decimal place is the measurement.
 */
export function formatRunStat(value: number): string {
  const slow = Math.abs(value) < 1000;
  return value.toLocaleString("en-US", { maximumFractionDigits: slow ? 1 : 0 });
}
