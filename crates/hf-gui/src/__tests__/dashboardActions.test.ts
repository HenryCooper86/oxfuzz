import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { dashboardActionDestination } from "../lib/dashboardActions";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

function functionSource(file: string, name: string, nextName: string): string {
  const start = file.indexOf(`function ${name}`);
  const end = file.indexOf(`function ${nextName}`, start);
  if (start < 0 || end < 0) throw new Error(`Could not isolate ${name}`);
  return file.slice(start, end);
}

describe("dashboard action destinations", () => {
  it("routes every known action code to its existing safe view", () => {
    expect(dashboardActionDestination("run_discovery")).toBe("discover");
    expect(dashboardActionDestination("review_harnesses")).toBe("harness");
    expect(dashboardActionDestination("triage_crashes")).toBe("triage");
    expect(dashboardActionDestination("smoke_campaign")).toBe("run");
    expect(dashboardActionDestination("select_project")).toBe("projects");
    expect(dashboardActionDestination("init_persistence")).toBe("settings");
  });

  it("keeps none and unknown action codes non-navigable", () => {
    expect(dashboardActionDestination("none")).toBeNull();
    expect(dashboardActionDestination("future_action")).toBeNull();
  });
});

describe("action-first dashboard overview", () => {
  it("puts Next Actions first once and passes through navigation", () => {
    const dashboard = source("../views/DashboardView.tsx");
    const overview = functionSource(dashboard, "OverviewTab", "ReadinessSummary");

    expect(overview.indexOf("<NextActions")).toBeLessThan(overview.indexOf("<ReadinessSummary"));
    expect(overview.match(/<NextActions/g)).toHaveLength(1);
    expect(overview).toMatch(/<NextActions[\s\S]*?onNavigate=\{onNavigate\}/);
  });

  it("renders known actions as accessible directional buttons and unknown actions as status rows", () => {
    const dashboard = source("../views/DashboardView.tsx");
    const actions = functionSource(dashboard, "NextActions", "HarnessQueue");

    expect(actions).toContain("dashboardActionDestination");
    expect(actions).toContain("<button");
    expect(actions).toContain('aria-label={t("dashboard.openAction"');
    expect(actions).toContain("<ChevronRight");
    expect(actions).toContain("dashboard-action-status");
  });

  it("groups readiness and metrics in a responsive supporting band", () => {
    const dashboard = source("../views/DashboardView.tsx");
    const css = source("../styles/index.css");
    const overview = functionSource(dashboard, "OverviewTab", "ReadinessSummary");

    expect(overview).toMatch(/className="dashboard-supporting-band"[\s\S]*?<ReadinessSummary[\s\S]*?<MetricGrid/);
    expect(css).toMatch(/\.dashboard-supporting-band\s*\{[\s\S]*?display:\s*grid/);
    expect(css).toMatch(/@media\s*\([^)]*max-width:[^)]*\)[\s\S]*?\.dashboard-supporting-band\s*\{/);
  });

  it("provides the new visible copy in English and Chinese", () => {
    const dictionaries = source("../i18n.extra.ts");

    expect(dictionaries.match(/"dashboard\.attention": "Needs attention"/g)).toHaveLength(1);
    expect(dictionaries.match(/"dashboard\.attention": "待处理事项"/g)).toHaveLength(1);
    expect(dictionaries.match(/"dashboard\.openAction": "Open \{action\}"/g)).toHaveLength(1);
    expect(dictionaries.match(/"dashboard\.openAction": "打开：\{action\}"/g)).toHaveLength(1);
  });
});
