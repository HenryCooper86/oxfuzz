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

  it("defines bilingual action labels for expanding compact progress", () => {
    const i18n = source("../i18n.tsx");

    expect(i18n).toContain('"progress.expandDetails": "Expand progress details"');
    expect(i18n).toContain(
      '"progress.expandCompleteDetails": "Expand progress details — all stages complete"',
    );
    expect(i18n).toContain('"progress.expandDetails": "展开进度详情"');
    expect(i18n).toContain(
      '"progress.expandCompleteDetails": "展开进度详情——所有阶段均已完成"',
    );
  });

  it("uses an action-oriented label and stable details relationship in compact mode", () => {
    const panel = source("../components/ProgressPanel.tsx");

    expect(panel).toContain(
      'aria-label={complete ? t("progress.expandCompleteDetails") : t("progress.expandDetails")}',
    );
    expect(panel).toContain('aria-controls="progress-panel-details"');
  });

  it("keeps the controlled details region mounted while toggling its visibility", () => {
    const panel = source("../components/ProgressPanel.tsx");

    expect(panel).toMatch(
      /<div\s+id="progress-panel-details"\s+hidden=\{!open\}/,
    );
  });
});
