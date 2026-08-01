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

const triage = componentSource(source("../views/TriageView.tsx"), "TriageView", "CrashDetail");
const dashboard = componentSource(
  source("../views/DashboardView.tsx"),
  "DashboardView",
  "workbenchTabs",
);

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
