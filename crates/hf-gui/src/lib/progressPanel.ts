import type { ViewType } from "../types";

export function getProgressPercentage(doneCount: number, total: number): number {
  return total === 0 ? 0 : Math.round((doneCount / total) * 100);
}

export function getInitialProgressPanelOpen(doneCount: number, total: number): boolean {
  return total === 0 || doneCount !== total;
}

export function getProgressPanelWidth(open: boolean): "280px" | "64px" {
  return open ? "280px" : "64px";
}

export function getProgressPanelOpenAfterCompletionChange(
  open: boolean,
  wasComplete: boolean,
  isComplete: boolean,
): boolean {
  if (!wasComplete && isComplete) return false;
  if (wasComplete && !isComplete) return true;
  return open;
}

const PIPELINE_VIEWS: ReadonlySet<ViewType> = new Set<ViewType>(["workflow", "discover", "harness", "run", "triage", "corpus"]);

/** The Progress panel belongs to the pipeline screens; elsewhere it is opt-in. */
export function progressPanelScope(view: ViewType): "pipeline" | "other" {
  return PIPELINE_VIEWS.has(view) ? "pipeline" : "other";
}
