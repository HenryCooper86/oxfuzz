import type { ViewType } from "../types";

const ACTION_DESTINATIONS: Readonly<Record<string, ViewType>> = {
  run_discovery: "discover",
  review_harnesses: "harness",
  triage_crashes: "triage",
  smoke_campaign: "run",
  select_project: "projects",
  init_persistence: "settings",
};

export function dashboardActionDestination(actionCode: string): ViewType | null {
  return ACTION_DESTINATIONS[actionCode] ?? null;
}
