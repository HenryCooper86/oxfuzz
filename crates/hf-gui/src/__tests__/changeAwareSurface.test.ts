import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned change-aware surface", () => {
  it("declares the serialized comparison and impact views", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface ChangeImpactView");
    expect(types).toContain("interface RevisionComparisonView");
    expect(types).toContain("interface AffectedTarget");
    expect(types).toContain("type TargetImpact");
    expect(types).toContain("type FindingChange");
    expect(types).toContain("type ComparabilityRefusal");
    // There is deliberately no "unaffected" member of the impact union.
    expect(types).not.toContain('| "unaffected"');
    expect(types).toContain('"changes"');
  });

  it("renders the service verdict without reclassifying anything", () => {
    const panel = source("../views/ChangesView.tsx");
    expect(panel).toContain("comparison.comparable");
    expect(panel).toContain("comparison.refusal");
    expect(panel).toContain("comparison.coverage.status");
    expect(panel).toContain("finding.change");
    expect(panel).toContain("entry.impact");
    // No presentation-layer derivation of the verdict.
    expect(panel).not.toContain("deriveComparison");
    expect(panel).not.toContain("computeRegression");
    expect(panel).not.toMatch(/findings\.filter\([^)]*base/);
  });

  it("shows an incomparable pair as a refusal instead of a coverage verdict", () => {
    const panel = source("../views/ChangesView.tsx");
    expect(panel).toContain("changeAware.refusal.");
    // The coverage block is only rendered for a comparable pair.
    expect(panel).toMatch(/comparison\.comparable\s*(&&|\?)/);
  });

  it("keeps publication an explicit, separate operator step", () => {
    const panel = source("../views/ChangesView.tsx");
    expect(panel).toContain('invoke<PublishedComparison>("change_publish"');
    expect(panel).toContain("changeAware.confirmPublish");
    const compareIndex = panel.indexOf('invoke<RevisionComparisonView>("change_compare"');
    const publishIndex = panel.indexOf('invoke<PublishedComparison>("change_publish"');
    expect(compareIndex).toBeGreaterThan(-1);
    expect(publishIndex).toBeGreaterThan(compareIndex);
  });

  it("keeps REST and Tauri as transports for the service workflow", () => {
    const transport = source("../lib/httpTransport.ts");
    expect(transport).toContain('path: "/change/impact"');
    expect(transport).toContain('path: "/change/compare"');
    expect(transport).toContain('path: "/change/publish"');
    const commands = source("../../src-tauri/src/commands.rs");
    expect(commands).toContain("pub async fn change_impact");
    expect(commands).toContain("pub async fn change_compare");
    expect(commands).toContain("pub async fn change_publish");
    expect(source("../../../hf-web/src/router.rs")).toContain('.route("/change/compare"');
  });

  it("is reachable from the flat sidebar and routed in the app", () => {
    expect(source("../components/Sidebar.tsx")).toContain('view: "changes"');
    expect(source("../App.tsx")).toContain('activeView === "changes"');
  });

  it("keeps English and Chinese change-aware labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"changeAware.title": "Change Review"');
    expect(translations).toContain('"changeAware.title": "变更审查"');
    expect(translations).toContain('"changeAware.impact.changed": "Changed"');
    expect(translations).toContain('"changeAware.impact.changed": "已更改"');
  });
});
