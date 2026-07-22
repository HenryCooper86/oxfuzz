import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  getInitialProgressPanelOpen,
  getProgressPercentage,
  getProgressPanelOpenAfterCompletionChange,
  getProgressPanelWidth,
} from "../lib/progressPanel";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("progress panel presentation", () => {
  it("calculates a zero-safe rounded percentage", () => {
    expect(getProgressPercentage(0, 0)).toBe(0);
    expect(getProgressPercentage(3, 0)).toBe(0);
    expect(getProgressPercentage(2, 3)).toBe(67);
  });

  it("opens initially unless a non-empty pipeline is complete", () => {
    expect(getInitialProgressPanelOpen(0, 0)).toBe(true);
    expect(getInitialProgressPanelOpen(0, 4)).toBe(true);
    expect(getInitialProgressPanelOpen(4, 4)).toBe(false);
  });

  it("selects the expanded and compact panel widths", () => {
    expect(getProgressPanelWidth(true)).toBe("280px");
    expect(getProgressPanelWidth(false)).toBe("64px");
  });

  it("compacts and expands when completion changes", () => {
    expect(getProgressPanelOpenAfterCompletionChange(true, false, true)).toBe(false);
    expect(getProgressPanelOpenAfterCompletionChange(false, true, false)).toBe(true);
  });

  it("preserves a manual state while completion remains stable", () => {
    expect(getProgressPanelOpenAfterCompletionChange(true, true, true)).toBe(true);
    expect(getProgressPanelOpenAfterCompletionChange(false, true, true)).toBe(false);
  });

  it("uses translated accessibility and completion labels in compact mode", () => {
    const panel = source("../components/ProgressPanel.tsx");

    expect(panel).toContain(
      'aria-label={complete ? t("info.allStagesComplete") : t("header.progress")}',
    );
  });
});
