import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

const dashboard = readFileSync(new URL("../views/DashboardView.tsx", import.meta.url), "utf8");

function functionSource(name: string, nextName: string): string {
  const start = dashboard.indexOf(`function ${name}`);
  const end = dashboard.indexOf(`function ${nextName}`, start);
  if (start < 0 || end < 0) throw new Error(`Could not isolate ${name}`);
  return dashboard.slice(start, end);
}

it("keeps the model budget in Health instead of leading the overview", () => {
  expect(dashboard).not.toMatch(/tab === "overview" && <ModelBudgetPanel/);
  expect(dashboard).not.toMatch(/if \(!activeProject\) return <div[^\n]*<ModelBudgetPanel/);
  expect(dashboard).toMatch(/tab === "health" && \([\s\S]*?<ModelBudgetPanel \/>[\s\S]*?<HealthPanel/);
});

it("offers one Draft report action, in the header", () => {
  expect(functionSource("NextActions", "HarnessQueue")).not.toContain("dashboard.draftReport");
  expect(dashboard.match(/t\("dashboard\.draftReport"\)/g)).toHaveLength(1);
});

it("names the issue tab for both GitHub and GitLab", () => {
  const tabs = functionSource("workbenchTabs", "OverviewTab");
  expect(tabs).not.toContain('label: "GitLab"');
  expect(tabs).toContain('t("dashboard.tabIssues")');
});
