import type { ViewType } from "../types";

export const RESULTS_VIEW_IDS = ["projects", "artifacts", "reports", "runs", "audit"] as const satisfies readonly ViewType[];

export const AI_SYSTEM_VIEW_IDS = ["chat", "agents", "skills", "knowledge", "automation"] as const satisfies readonly ViewType[];

export function sidebarSectionContainsView(section: readonly ViewType[], activeView: ViewType): boolean {
  return section.includes(activeView);
}
