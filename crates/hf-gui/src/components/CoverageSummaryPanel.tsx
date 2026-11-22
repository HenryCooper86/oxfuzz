import "../i18n.parityAnalysis";
import { useEffect, useRef, useState } from "react";
import { Download } from "lucide-react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import { isObject, percentText, type CoverageSummary, type LineReportOutcome } from "../lib/parityAnalysis";
import { Button } from "./ui";

type Summary = { status: "loading" } | { status: "none" } | { status: "error"; error: string } | { status: "ready"; value: CoverageSummary };

/** Retained coverage of the selected target, with lcov and HTML line reports. */
export function CoverageSummaryPanel({ project, target, refreshKey = 0 }: { project: string; target: string; refreshKey?: number }) {
  const { t } = useI18n();
  const [summary, setSummary] = useState<Summary>({ status: "loading" });
  const [saving, setSaving] = useState<"lcov" | "html" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  useEffect(() => {
    let active = true;
    Promise.resolve().then(() => getTransport().invoke<CoverageSummary | null>("coverage_summary", { project, target })).then((value) => {
      if (active) setSummary(isObject(value) ? { status: "ready", value: value as unknown as CoverageSummary } : { status: "none" });
    }).catch((caught: unknown) => { if (active) setSummary({ status: "error", error: String(caught) }); });
    return () => { active = false; };
  }, [project, target, refreshKey]);

  async function save(format: "lcov" | "html") {
    if (saving) return;
    setSaving(format); setError(null); setNotice(null);
    try {
      const report = await getTransport().invoke<LineReportOutcome>("export_coverage_line_report", { project, target, format });
      if (!mounted.current) return;
      setNotice(report.path
        ? t("parity.analysis.coverage.saved", { path: report.path, hit: report.lines_hit, total: report.lines_total, files: report.files })
        : t("parity.analysis.coverage.cancelled"));
    } catch (caught) {
      if (mounted.current) setError(String(caught));
    } finally {
      if (mounted.current) setSaving(null);
    }
  }

  const value = summary.status === "ready" ? summary.value : null;
  return <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }} aria-label={t("parity.analysis.coverage.title")}>
    <div className="text-sm font-medium">{t("parity.analysis.coverage.title")}</div>
    {summary.status === "loading" && <p role="status" className="text-xs text-text-muted m-0">{t("parity.analysis.coverage.loading")}</p>}
    {summary.status === "none" && <p role="status" className="text-xs text-text-muted m-0">{t("parity.analysis.coverage.none")}</p>}
    {summary.status === "error" && <p role="alert" className="text-xs m-0" style={{ color: "var(--error)" }}>{t("parity.analysis.coverage.failed", { error: summary.error })}</p>}
    {value && <dl className="m-0 grid gap-x-4 gap-y-1 text-xs" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" }}>
      <div><dt className="text-text-muted">{t("parity.analysis.coverage.lines")}</dt><dd className="m-0">{value.lines_covered} / {value.lines_total} ({percentText(value.line_percent)})</dd></div>
      <div><dt className="text-text-muted">{t("parity.analysis.coverage.functions")}</dt><dd className="m-0">{value.functions_covered} / {value.functions_total} ({percentText(value.function_percent)})</dd></div>
      <div><dt className="text-text-muted">{t("parity.analysis.coverage.regions")}</dt><dd className="m-0">{value.regions_covered} / {value.regions_total} ({percentText(value.region_percent)})</dd></div>
    </dl>}
    <div className="flex flex-wrap gap-2">
      <Button size="sm" variant="outline" onClick={() => void save("lcov")} loading={saving === "lcov"} disabled={saving !== null || !target}><Download size={13} />{t("parity.analysis.coverage.saveLcov")}</Button>
      <Button size="sm" variant="outline" onClick={() => void save("html")} loading={saving === "html"} disabled={saving !== null || !target}><Download size={13} />{t("parity.analysis.coverage.saveHtml")}</Button>
    </div>
    {notice && <p role="status" className="text-xs text-text-muted m-0">{notice}</p>}
    {error && <p role="alert" className="text-xs m-0" style={{ color: "var(--error)" }}>{error}</p>}
  </section>;
}
