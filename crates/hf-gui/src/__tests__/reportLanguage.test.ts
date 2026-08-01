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
const automotiveFile = source("../views/AutomotiveView.tsx");
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
    // Scope: TriageView.tsx and DashboardView.tsx, and nothing else. The
    // automotive report's own two titles live in AutomotiveView.tsx and are
    // guarded by the block below, which scans that file and only that file.
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

// The automotive campaign report is composed by a separate service method and a
// separate desktop view, so none of the assertions above reach it.
describe("the automotive report follows the interface language", () => {
  it("takes the locale from the view's own i18n hook", () => {
    // AutomotiveView declares exactly one useI18n(), so there is no sibling
    // hook whose `locale` an assertion below could be satisfied by.
    expect(automotiveFile.match(/useI18n\(\)/g)).toHaveLength(1);
    expect(automotiveFile).toContain("const { t, locale } = useI18n();");
  });

  it("passes the locale on the compose call", () => {
    expect(automotiveFile).toContain(
      "generateAutomotiveReport(activeProject, includeAi, locale)",
    );
  });

  it("titles the retained draft from the dictionary", () => {
    // The draft is persisted and listed in the Reports view, so an English
    // title on the Chinese path is not cosmetic: it accumulates.
    expect(automotiveFile).toContain(
      'title: t("automotive.report.documentTitle", { project: next.project_name })',
    );
  });

  it("titles the exported document from the dictionary", () => {
    // A second, independent literal: the export builds its own argument object
    // from `report` rather than reusing the compose path's `next`, so the
    // assertion above cannot cover it.
    expect(automotiveFile).toContain(
      'title: t("automotive.report.documentTitle", { project: report.project_name })',
    );
  });

  it("leaves no English report-title literal in this view", () => {
    // Scope: AutomotiveView.tsx, and nothing else. Both assertions above would
    // still pass if a localized title were computed and then ignored; this one
    // fails the moment either site is reverted to its template literal, and it
    // catches a new English automotive title added to this view.
    expect(automotiveFile).not.toMatch(/Automotive campaign report/);
    expect(automotiveFile).not.toMatch(/campaign report —/);
  });

  it("translates the document title in both dictionaries", () => {
    const extra = source("../i18n.extra.ts");
    // Once in the English block, once in the Chinese one -- a key present only
    // in the English block renders as the raw key string to a Chinese reader.
    expect(extra.match(/"automotive\.report\.documentTitle":/g)).toHaveLength(2);
    // The English value is byte-identical to the literal it replaced, so the
    // English path does not move.
    expect(extra).toContain(
      '"automotive.report.documentTitle": "Automotive campaign report — {project}"',
    );
    // The Chinese value is the same document name the report's own H1 carries,
    // so the draft list and the document agree.
    expect(extra).toContain(
      '"automotive.report.documentTitle": "汽车协议模糊测试活动报告：{project}"',
    );
  });
});
