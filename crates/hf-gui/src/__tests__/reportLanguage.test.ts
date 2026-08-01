import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

/** Isolate one component so an assertion cannot be satisfied by another one. */
function componentSource(file: string, name: string, nextName: string): string {
  const start = file.indexOf(`function ${name}`);
  const end = file.indexOf(`function ${nextName}`, start);
  if (start < 0 || end < 0) throw new Error(`Could not isolate ${name}`);
  return file.slice(start, end);
}

const dashboardFile = source("../views/DashboardView.tsx");
const triage = componentSource(source("../views/TriageView.tsx"), "TriageView", "CrashDetail");
const dashboard = componentSource(dashboardFile, "DashboardView", "workbenchTabs");
// emptyEditor sits at module scope, above DashboardView, so the isolated
// component above does not cover it.
const emptyEditor = componentSource(dashboardFile, "emptyEditor", "DashboardView");

describe("report language reaches every desktop report call", () => {
  it("takes the locale from the enclosing component's own i18n hook", () => {
    // DashboardView.tsx declares eighteen useI18n() calls. Only the one inside
    // DashboardView itself is in scope at its report call site, so assert on
    // the isolated component and that it holds exactly one hook.
    expect(triage.match(/useI18n\(\)/g)).toHaveLength(1);
    expect(triage).toContain("const { t, locale } = useI18n();");
    expect(dashboard.match(/useI18n\(\)/g)).toHaveLength(1);
    expect(dashboard).toContain("const { t, locale } = useI18n();");
  });

  it("passes the locale from the triage compose helper", () => {
    // TriageView composes through a reportArgs() helper, so the field has to
    // live inside the helper's object literal, not at the call site.
    expect(triage).toMatch(
      /const reportArgs = useCallback\(\s*\(\) => \(\{[^}]*language: locale[^}]*\}\)/,
    );
  });

  it("passes the locale from the triage export call", () => {
    // export_report builds its own argument object and does not reuse
    // reportArgs(), so the previous assertion cannot cover this site.
    expect(triage).toMatch(/invoke<string \| null>\("export_report", \{[^}]*language: locale[^}]*\}/);
  });

  it("passes the locale from the dashboard generate call", () => {
    expect(dashboard).toMatch(/invoke<string>\("generate_report", \{[^}]*language: locale[^}]*\}/);
  });

  it("leaves no report invocation without a language", () => {
    for (const file of ["../views/TriageView.tsx", "../views/DashboardView.tsx"]) {
      const text = source(file);
      const calls = text.match(/invoke<[^>]*>\("(?:generate_report|export_report)"[^;]*;/g) ?? [];
      expect(calls.length).toBeGreaterThan(0);
      for (const call of calls) {
        expect(call.includes("language: locale") || call.includes("reportArgs()")).toBe(true);
      }
    }
  });
});

// The draft title is persisted with the report and listed in the Reports view,
// so an English title on the Chinese path is not cosmetic: it accumulates.
// Three separate literals produced it, none of them covered by the block above,
// which only asserts that `language` reaches the backend.
describe("report draft titles follow the interface language", () => {
  it("titles the dashboard's freshly generated draft from the dictionary", () => {
    expect(dashboard).toContain('title: t("reports.targetDraftTitle", { target })');
  });

  it("titles a blank dashboard draft from the dictionary", () => {
    // Both branches: a named target and the untitled fallback.
    expect(emptyEditor).toContain('t("reports.targetDraftTitle", { target })');
    expect(emptyEditor).toContain('t("reports.untitledDraftTitle")');
    // emptyEditor is module scope with no hook, so `t` has to be a parameter.
    expect(emptyEditor).toMatch(/function emptyEditor\([^)]*\bt: TFn\b/);
  });

  it("titles the triage draft from the dictionary", () => {
    expect(triage).toContain(
      'title: t("reports.triageDraftTitle", { target: lastTarget || t("reports.unknownTarget") })',
    );
  });

  it("leaves no English report-title literal in either view", () => {
    // The assertions above would all still pass if a localized title were
    // computed and then ignored. This one fails the moment any of the three is
    // reverted to its template literal, and it catches a new English title
    // added to either of these two views.
    //
    // It does NOT catch a title added elsewhere: AutomotiveView.tsx builds
    // "Automotive campaign report — {...}" and persists it, and is not scanned
    // here. That report has no language parameter at all, so its body is
    // English too; localizing it is a separate piece of work, not a gap in
    // this guard.
    for (const text of [source("../views/TriageView.tsx"), dashboardFile]) {
      expect(text).not.toMatch(/fuzzing report/);
      expect(text).not.toMatch(/Triage report/);
    }
  });

  it("translates every draft-title key in both dictionaries", () => {
    const extra = source("../i18n.extra.ts");
    for (const key of [
      "reports.targetDraftTitle",
      "reports.triageDraftTitle",
      "reports.unknownTarget",
      "reports.untitledDraftTitle",
    ]) {
      // Once in the English block, once in the Chinese one. `t` resolves
      // DICTS[locale][key] ?? en[key] ?? key, where `en` is the *inline*
      // dictionary rather than this file, so a key added only to the English
      // block here renders as the raw key string -- "reports.untitledDraftTitle"
      // shown to the user -- not as English prose.
      expect(extra.match(new RegExp(`"${key.replace(/\./g, "\\.")}":`, "g"))).toHaveLength(2);
    }
    // And the Chinese values are actually Chinese, not copied English.
    expect(extra).toContain('"reports.targetDraftTitle": "{target} 模糊测试报告"');
    expect(extra).toContain('"reports.triageDraftTitle": "分类定级报告 — {target}"');
    expect(extra).toContain('"reports.unknownTarget": "目标"');
    expect(extra).toContain('"reports.untitledDraftTitle": "未命名模糊测试报告"');
  });
});
