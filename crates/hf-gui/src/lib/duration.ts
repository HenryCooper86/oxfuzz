export type DurationUnit = "s" | "m" | "h";

const FACTOR: Record<DurationUnit, number> = { s: 1, m: 60, h: 3600 };

/** A seconds value as an amount in the largest unit that divides it evenly. */
export function splitDuration(seconds: string): { amount: string; unit: DurationUnit } {
  const value = Number(seconds);
  if (seconds.trim() === "" || !Number.isSafeInteger(value) || value <= 0) return { amount: seconds, unit: "s" };
  const unit: DurationUnit = value % 3600 === 0 ? "h" : value % 60 === 0 ? "m" : "s";
  return { amount: String(value / FACTOR[unit]), unit };
}

/** An amount in a unit as a seconds string; text that is not a number passes through for validation. */
export function toSeconds(amount: string, unit: DurationUnit): string {
  const value = Number(amount);
  if (amount.trim() === "" || !Number.isFinite(value)) return amount;
  return String(Math.round(value * FACTOR[unit]));
}

/** Seconds as people say them: "45 s", "1 min 30 s", "2 h". */
export function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const parts = [h ? `${h} h` : "", m ? `${m} min` : "", s || (!h && !m) ? `${s} s` : ""];
  return parts.filter(Boolean).join(" ");
}

/**
 * The service summarizes an interval trigger as "every 3600s". Show its
 * interval the way every other duration is shown; other summaries (cron
 * expressions, one-time instants) pass through unchanged.
 */
export function formatTriggerSummary(trigger: string): string {
  const interval = /^every (\d+)s$/.exec(trigger);
  return interval ? `every ${formatDuration(Number(interval[1]))}` : trigger;
}
