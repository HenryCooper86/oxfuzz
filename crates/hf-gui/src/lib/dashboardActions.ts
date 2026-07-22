import type { ViewType } from "../types";

export function dashboardActionDestination(actionCode: string): ViewType | null {
  switch (actionCode) {
    case "run_discovery":
      return "discover";
    case "review_harnesses":
      return "harness";
    case "triage_crashes":
      return "triage";
    case "smoke_campaign":
      return "run";
    case "select_project":
      return "projects";
    case "init_persistence":
      return "settings";
    default:
      return null;
  }
}

export function isDashboardActionInteractive(
  destination: ViewType | null,
  navigationAvailable: boolean,
): destination is ViewType {
  return destination !== null && navigationAvailable;
}
