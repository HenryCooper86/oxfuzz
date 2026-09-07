import type { RunOwner } from "../lib/transport";
import type { AutoRevert, RunSummary } from "./runOutput";
import type { HealthItem } from "./runOutputState";

export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function uuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
  );
}
export function rate(value: unknown): number | null {
  return typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= Number.MAX_SAFE_INTEGER
    ? value
    : null;
}
export function count(value: unknown): number | null {
  const number = rate(value);
  return number !== null && Number.isSafeInteger(number) ? number : null;
}
function timestampNanos(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const match =
    /^(\d{4}-\d{2}-\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})$/.exec(
      value,
    );
  if (!match) return null;
  const [, date, hour, minute, second, fraction = "", zone] = match;
  if (Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return null;
  const calendar = Date.parse(`${date}T00:00:00Z`);
  if (!Number.isFinite(calendar) || new Date(calendar).toISOString().slice(0, 10) !== date)
    return null;
  const wholeSecond = Date.parse(`${date}T${hour}:${minute}:${second}${zone}`);
  if (!Number.isFinite(wholeSecond)) return null;
  return BigInt(wholeSecond) * 1_000_000n + BigInt(fraction.padEnd(9, "0"));
}
export function timestamp(value: unknown): value is string {
  return timestampNanos(value) !== null;
}
/** Compare service RFC3339 timestamps without discarding fractional-second precision. */
export function compareTimestamps(left: string, right: string): -1 | 0 | 1 | null {
  const first = timestampNanos(left),
    second = timestampNanos(right);
  if (first === null || second === null) return null;
  return first < second ? -1 : first > second ? 1 : 0;
}
export function activeStatus(status: string | null): boolean {
  return (
    status === "Running" || status === "Pending" || status === "running" || status === "pending"
  );
}
export function validStatus(status: unknown): status is string {
  return (
    typeof status === "string" &&
    [
      "Running",
      "Pending",
      "Done",
      "Failed",
      "Cancelled",
      "running",
      "pending",
      "done",
      "failed",
      "cancelled",
    ].includes(status)
  );
}
export function parseOwner(value: unknown, id?: string): RunOwner | null {
  if (
    !record(value) ||
    !uuid(value.run_id) ||
    (id !== undefined && value.run_id !== id) ||
    typeof value.project_root !== "string" ||
    !value.project_root ||
    (value.target !== null && typeof value.target !== "string") ||
    typeof value.engine !== "string" ||
    !value.engine ||
    typeof value.kind !== "string" ||
    !validStatus(value.status) ||
    !timestamp(value.started_at)
  )
    return null;
  return {
    run_id: value.run_id,
    project_root: value.project_root,
    target: value.target,
    engine: value.engine,
    kind: value.kind,
    status: value.status,
    started_at: value.started_at,
  };
}
export function newer(candidate: RunOwner, current: RunOwner | null): boolean {
  if (!current) return true;
  const delta = compareTimestamps(candidate.started_at, current.started_at);
  return delta === 1 || (delta === 0 && candidate.run_id > current.run_id);
}
function parseAutoRevert(value: unknown): AutoRevert | null {
  if (
    !record(value) ||
    !uuid(value.reverted_to_run) ||
    typeof value.from_rev !== "string" ||
    typeof value.to_rev !== "string" ||
    typeof value.reverted !== "boolean"
  )
    return null;
  const previous = count(value.previous_edges),
    regressed = count(value.regressed_edges),
    drop = rate(value.drop_pct);
  if (previous === null || regressed === null || drop === null) return null;
  return {
    reverted_to_run: value.reverted_to_run,
    from_rev: value.from_rev,
    to_rev: value.to_rev,
    previous_edges: previous,
    regressed_edges: regressed,
    drop_pct: drop,
    reverted: value.reverted,
  };
}
export function parseSummary(value: unknown): RunSummary | null {
  if (!record(value)) return null;
  const edges = count(value.edges),
    crashes = count(value.crashes),
    execs = rate(value.execs);
  if (
    crashes === null ||
    (value.edges != null && edges === null) ||
    (value.execs != null && execs === null)
  )
    return null;
  return {
    edges,
    crashes,
    execs,
    stagnation: typeof value.stagnation === "string" ? value.stagnation : null,
    autoRevert: parseAutoRevert(value.auto_revert ?? value.autoRevert),
  };
}
export function parseHealth(value: unknown, runId: string): HealthItem | null {
  if (
    !record(value) ||
    value.schema_version !== 2 ||
    value.run_id !== runId ||
    !uuid(value.id) ||
    (value.severity !== "warning" && value.severity !== "error") ||
    typeof value.condition !== "string" ||
    typeof value.detail !== "string" ||
    !timestamp(value.observed_at) ||
    !record(value.evidence) ||
    value.evidence.schema_version !== 2 ||
    value.evidence.run_id !== runId ||
    value.evidence.condition !== value.condition
  )
    return null;
  return {
    id: value.id,
    severity: value.severity,
    condition: value.condition,
    detail: value.detail.slice(0, 4096),
  };
}
