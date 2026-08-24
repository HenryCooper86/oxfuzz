import { useState, useEffect, useRef, useCallback, lazy, Suspense } from "react";
import { getTransport, isTauriEnvironment, emitDataChanged } from "../lib";
import { useProject } from "../providers/project";
import { usePipeline } from "../providers/pipeline";
import { useRunOutput } from "../providers/runOutput";
import type {
  Crash,
  CrashVerdict,
  FindingProofCard as FindingProofCardView,
  WorkbenchDashboard,
} from "../types";
import { Button, ViewHeader, SeverityBadge } from "../components/ui";
import { FindingProofCard } from "../components/FindingProofCard";
import { Bug, ChevronRight, Download, FileText, Share2 } from "lucide-react";
import { PathActions } from "../components/PathActions";
import { useI18n } from "../i18nContext";

// The report preview pulls in react-markdown + mermaid (heavy); load it only
// when the user opens a report, keeping it out of the initial bundle.
const ReportPreview = lazy(() =>
  import("../components/ReportPreview").then((m) => ({ default: m.ReportPreview })),
);

export function TriageView({ embedded = false }: { embedded?: boolean }) {
  const { t, locale } = useI18n();
  const { activeProject } = useProject();
  const { markDone, markSkipped } = usePipeline();
  // The target + crash count from the most recent run, so triage scans the
  // right workspace and we know whether there is anything to triage.
  const { lastTarget, lastEngine, summary } = useRunOutput();
  // Kernel (syzkaller) crashes live in the syzkaller workdir, not a per-target
  // workspace, so per-target triage does not apply to them.
  const isKernelRun = lastEngine === "syzkaller";
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [reporting, setReporting] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [reportMsg, setReportMsg] = useState<string | null>(null);
  const [reportMd, setReportMd] = useState<string | null>(null);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [proofs, setProofs] = useState<Record<string, FindingProofCardView>>({});
  const [proofLoadFailed, setProofLoadFailed] = useState(false);
  // On-demand LLM crash verdicts (L2 4c), keyed by crash id: "loading" while a
  // verdict is being fetched, "none" when verified with no provider configured,
  // or the verdict itself. Opt-in per crash so a scan is never blocked on it.
  const [verdicts, setVerdicts] = useState<Record<string, CrashVerdict | "loading" | "none">>({});
  // Export formats this host supports (md/html always; pdf/docx need pandoc).
  const [formats, setFormats] = useState<string[]>(["md", "html"]);

  useEffect(() => {
    if (!isTauriEnvironment()) return; // web export is client-side md only
    getTransport()
      .invoke<string[]>("report_formats")
      .then(setFormats)
      .catch(() => setFormats(["md", "html"]));
  }, []);

  // Whether the last run produced crashes (null = no run yet this session).
  const ranWithCrashes = summary ? summary.crashes > 0 : null;

  const triage = useCallback(async (): Promise<Crash[]> => {
    setLoading(true);
    setTriageError(null);
    try {
      const result = await getTransport().invoke<Crash[]>("triage", {
        project: activeProject || ".",
        target: lastTarget,
      });
      setCrashes(result);
      if (result.length > 0) {
        try {
          const dashboard = await getTransport().invoke<WorkbenchDashboard>("workbench_dashboard", {
            project: activeProject || undefined,
            target: lastTarget || undefined,
          });
          const triagedIds = new Set(result.map((crash) => crash.id));
          const proofById = Object.fromEntries(
            dashboard.crash_reviews
              .filter((crash) => triagedIds.has(crash.crash_id))
              .map((crash) => [crash.crash_id, crash.proof]),
          );
          setProofs(proofById);
          setProofLoadFailed(result.some((crash) => proofById[crash.id] === undefined));
        } catch {
          setProofs({});
          setProofLoadFailed(true);
        }
      } else {
        setProofs({});
        setProofLoadFailed(false);
      }
      if (result.length > 0) markDone("triage");
      else markSkipped("triage");
      return result;
    } catch (e) {
      // A failed scan previously looked identical to "no crashes found".
      setCrashes([]);
      setProofs({});
      setProofLoadFailed(false);
      setTriageError(String(e));
      return [];
    } finally {
      setLoading(false);
    }
  }, [activeProject, lastTarget, markDone, markSkipped]);

  const verifyCrash = useCallback(
    async (crash: Crash) => {
      setVerdicts((v) => ({ ...v, [crash.id]: "loading" }));
      try {
        const verdict = await getTransport().invoke<CrashVerdict | null>("verify_crash", {
          project: activeProject || ".",
          target: lastTarget,
          crash,
        });
        setVerdicts((v) => ({ ...v, [crash.id]: verdict ?? "none" }));
      } catch {
        setVerdicts((v) => ({ ...v, [crash.id]: "none" }));
      }
    },
    [activeProject, lastTarget],
  );

  // `locale` is already "en" | "zh", the identifiers the service parses, so the
  // current interface language passes through unmapped.
  const reportArgs = useCallback(
    () => ({ project: activeProject || ".", target: lastTarget, language: locale }),
    [activeProject, lastTarget, locale],
  );

  // Browser blob download (web mode, or when the native dialog is unavailable).
  const browserDownload = useCallback(
    (md: string) => {
      const blob = new Blob([md], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `oxfuzz_report_${(lastTarget || "target").replace(/[^a-zA-Z0-9_-]/g, "_")}.md`;
      a.click();
      URL.revokeObjectURL(url);
    },
    [lastTarget],
  );

  // Compose the report (AI-authored when a provider is configured), open the
  // preview, and persist it to the Workbench "Composed Reports" list so it is
  // never lost between the Triage and Dashboard surfaces. `announce` controls
  // whether a status message is shown (suppressed for silent auto-compose so it
  // doesn't stomp the triage summary message).
  const composeAndSaveReport = useCallback(async () => {
    setReporting(true);
    setReportMsg(null);
    try {
      const md = await getTransport().invoke<string>("generate_report", reportArgs());
      if (!md) {
        setReportMsg(t("triage.reportDesktopOnly"));
        return;
      }
      setReportMd(md);
      await getTransport().invoke("save_report_draft", {
        // Persisted with the draft and shown in the Reports list, so it follows
        // the interface language the body was just composed in. The target
        // symbol is a technical token and is interpolated verbatim.
        title: t("reports.triageDraftTitle", { target: lastTarget || t("reports.unknownTarget") }),
        project: activeProject || ".",
        target: lastTarget || undefined,
        status: "Draft",
        content: md,
      });
      emitDataChanged();
      setReportMsg(t("triage.reportComposed"));
    } catch (e) {
      setReportMsg(t("triage.reportFailed", { error: String(e) }));
    } finally {
      setReporting(false);
    }
  }, [reportArgs, lastTarget, activeProject, t]);

  // Export the composed report in a chosen format. Desktop opens a native save
  // dialog (md/html/pdf/docx); web falls back to a Markdown blob download.
  const exportReport = useCallback(
    async (format: string) => {
      setReportMsg(null);
      try {
        if (isTauriEnvironment()) {
          const saved = await getTransport().invoke<string | null>("export_report", {
            project: activeProject || ".",
            target: lastTarget,
            format,
            language: locale,
          });
          if (saved) setReportMsg(t("triage.reportSaved", { format: format.toUpperCase(), path: saved }));
        } else if (format === "md" && reportMd) {
          browserDownload(reportMd);
          setReportMsg(t("triage.reportDownloaded"));
        } else {
          setReportMsg(t("triage.exportDesktopOnly", { format: format.toUpperCase() }));
        }
      } catch (e) {
        setReportMsg(t("triage.exportFailed", { error: String(e) }));
      }
    },
    [activeProject, lastTarget, reportMd, browserDownload, locale, t],
  );

  // Export a self-contained reproduction bundle (harness + crash input +
  // REPRODUCE.md) for a crash. Desktop-only (a native folder picker); web users
  // use the `oxfuzz repro` CLI. The run context lacks the harness language,
  // so this assumes C -- power users pass `--lang` on the CLI.
  const exportRepro = useCallback(
    async (crashId?: string) => {
      setReportMsg(null);
      if (!isTauriEnvironment()) {
        setReportMsg(t("triage.exportDesktopOnly", { format: "Repro bundle" }));
        return;
      }
      try {
        const saved = await getTransport().invoke<string | null>("export_repro", {
          project: activeProject || ".",
          target: lastTarget,
          engine: lastEngine || "libfuzzer",
          lang: "c",
          crash: crashId,
        });
        if (saved) setReportMsg(t("triage.reproSaved", { path: saved }));
      } catch (e) {
        setReportMsg(t("triage.exportFailed", { error: String(e) }));
      }
    },
    [activeProject, lastTarget, lastEngine, t],
  );

  // Push the triaged crashes to DefectDojo as findings (import/reimport-scan).
  const pushToDefectDojo = useCallback(async () => {
    setReportMsg(null);
    setPushing(true);
    try {
      const outcome = await getTransport().invoke<{ findings_pushed: number; reimported: boolean; url: string | null }>(
        "push_to_defectdojo",
        { project: activeProject || ".", target: lastTarget || undefined },
      );
      const where = outcome.url ? ` (${outcome.url})` : "";
      setReportMsg(
        t("triage.pushed", {
          n: outcome.findings_pushed,
          reimport: outcome.reimported ? t("triage.reimportSuffix") : "",
          where,
        }),
      );
    } catch (e) {
      setReportMsg(t("triage.pushFailed", { error: String(e) }));
    } finally {
      setPushing(false);
    }
  }, [activeProject, lastTarget, t]);

  // Auto-triage + auto-report: once a run completes with crashes, ingest + dedup
  // them and (per the workflow) compose an AI report and save it to the
  // dashboard automatically -- once per run. Buttons remain for manual re-runs.
  const autoTriagedRef = useRef<typeof summary>(null);
  useEffect(() => {
    // Skip kernel runs: their crashes are not in a per-target workspace, so an
    // auto per-target scan would find nothing and read as "no crashes".
    if (isKernelRun) return;
    if (summary && summary.crashes > 0 && autoTriagedRef.current !== summary) {
      autoTriagedRef.current = summary;
      void (async () => {
        const list = await triage();
        if (list.length > 0) await composeAndSaveReport();
      })();
    }
  }, [summary, triage, composeAndSaveReport, isKernelRun]);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        {embedded ? (
          <span />
        ) : (
          <ViewHeader
            title={t("triage.title")}
            description={t("triage.description")}
          />
        )}
        <div className="flex items-center gap-2">
          {/* Compose a full report (AI-authored when a provider is configured),
              save it to the Workbench, and open the preview (with export
              options). Enabled once a run has happened (a target is known). */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => void composeAndSaveReport()}
            disabled={reporting || !lastTarget}
            loading={reporting}
            title={t("triage.composeReportTooltip")}
          >
            {!reporting && <FileText size={14} />}
            {reporting ? t("triage.composing") : t("triage.composeReport")}
          </Button>
          {crashes.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void pushToDefectDojo()}
              disabled={pushing}
              loading={pushing}
              title={t("triage.pushTooltip")}
            >
              {!pushing && <Share2 size={14} />}
              {pushing ? t("triage.pushing") : t("triage.pushToDefectDojo")}
            </Button>
          )}
          {crashes.length > 0 && isTauriEnvironment() && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void exportRepro(selected !== null ? crashes[selected]?.id : undefined)}
              title={t("triage.downloadRepro")}
            >
              <Download size={14} />
              {t("triage.downloadRepro")}
            </Button>
          )}
          <Button
            variant="primary"
            onClick={triage}
            disabled={loading || !lastTarget || isKernelRun}
            loading={loading}
            title={
              isKernelRun
                ? t("triage.scanTooltipKernel")
                : lastTarget
                  ? t("triage.scanTooltipReady")
                  : t("triage.scanTooltipNoTarget")
            }
          >
            {!loading && <Bug size={14} />}
            {loading ? t("triage.scanning") : t("triage.scanForCrashes")}
          </Button>
        </div>
      </div>

      {reportMsg && (
        <div className="text-xs text-text-muted" style={{ marginTop: "-0.5rem" }}>
          {reportMsg}
        </div>
      )}

      {triageError && (
        <div
          className="surface-card text-xs"
          style={{ padding: "var(--space-sm) var(--space-md)", color: "var(--danger, #e5484d)", borderColor: "var(--danger, #e5484d)" }}
        >
          {t("triage.scanFailed", { error: triageError })}
        </div>
      )}

      {/* Kernel campaigns collect crashes in the syzkaller workdir, outside the
          per-target triage path -- explain rather than scan into an empty result. */}
      {isKernelRun && summary && (
        <div
          className="surface-card text-sm"
          style={{ padding: "var(--space-md)", borderLeft: `3px solid ${summary.crashes > 0 ? "var(--error)" : "var(--success)"}` }}
        >
          {t("triage.kernelReportedPrefix")} <strong>{summary.crashes}</strong>{" "}
          {summary.crashes === 1 ? t("triage.crash") : t("triage.crashes")}
          {t("triage.kernelExplanation")}
        </div>
      )}

      {/* Context from the last run, so the user knows what to expect. */}
      {!isKernelRun && summary && crashes.length === 0 && (
        <div
          className="surface-card text-sm"
          style={{ padding: "var(--space-md)", borderLeft: `3px solid ${ranWithCrashes ? "var(--error)" : "var(--success)"}` }}
        >
          {ranWithCrashes ? (
            <>
              {lastTarget
                ? t("triage.lastRunReportedOn", { target: lastTarget })
                : t("triage.lastRunReported")}{" "}
              <strong>{summary.crashes}</strong>{" "}
              {summary.crashes === 1 ? t("triage.crash") : t("triage.crashes")}
              {t("triage.lastRunIngesting")}
            </>
          ) : lastTarget ? (
            t("triage.lastRunNoneOn", { target: lastTarget })
          ) : (
            t("triage.lastRunNone")
          )}
        </div>
      )}

      {crashes.length === 0 && !loading && !isKernelRun && (
        <div
          className="surface-card flex flex-col items-center justify-center"
          style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}
        >
          <Bug size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} />
          <p className="text-sm text-text-muted">{t("triage.noCrashesIngested")}</p>
          <p className="text-xs text-text-muted mt-1">
            {lastTarget
              ? t("triage.hintScanLastRun", { target: lastTarget })
              : t("triage.hintRunFirst")}
          </p>
        </div>
      )}

      {crashes.length > 0 && (
        <div className="flex gap-3" style={{ animation: "slideInUp 0.2s ease" }}>
          {/* Crash list */}
          <div className="flex flex-col gap-1 flex-1">
            {crashes.map((c, i) => (
              <button
                key={c.id}
                onClick={() => setSelected(i)}
                className={`surface-card flex items-center gap-2 text-left transition-all duration-150 ${
                  selected === i ? "border-[var(--border-focus)]" : ""
                }`}
                style={{ padding: "var(--space-sm) var(--space-md)" }}
              >
                <Bug size={14} className="shrink-0" style={{ color: "var(--error)" }} />
                <span className="text-xs font-mono flex-1 truncate">{c.kind}</span>
                {c.casr && <SeverityBadge severity={c.casr.severity} title={c.casr.severity_short || c.casr.severity} />}
                <span className="text-xs text-text-muted">{c.input_path.split("/").pop()}</span>
                <ChevronRight size={14} className="text-text-muted" />
              </button>
            ))}
          </div>

          {/* Detail panel */}
          {selected !== null && crashes[selected] && (
            <div className="surface-card flex-1" style={{ padding: "var(--space-md)" }}>
              <CrashDetail
                crash={crashes[selected]}
                proof={proofs[crashes[selected].id]}
                proofUnavailable={proofLoadFailed}
                verdict={verdicts[crashes[selected].id]}
                onVerify={() => verifyCrash(crashes[selected])}
              />
            </div>
          )}
        </div>
      )}

      {reportMd !== null && (
        <Suspense fallback={null}>
          <ReportPreview
            markdown={reportMd}
            onClose={() => setReportMd(null)}
            onExport={(format) => void exportReport(format)}
            formats={formats}
          />
        </Suspense>
      )}
    </div>
  );
}

function CrashDetail({
  crash,
  proof,
  proofUnavailable,
  verdict,
  onVerify,
}: {
  crash: Crash;
  proof: FindingProofCardView | undefined;
  proofUnavailable: boolean;
  verdict: CrashVerdict | "loading" | "none" | undefined;
  onVerify: () => void;
}) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <span
          className="text-xs px-2 py-1 rounded-sm font-medium"
          style={{ background: "var(--error-subtle)", color: "var(--error)" }}
        >
          {crash.kind}
        </span>
        {crash.casr && <SeverityBadge severity={crash.casr.severity} title={crash.casr.severity_short || crash.casr.severity} />}
        <span className="text-xs text-text-muted font-mono truncate min-w-0 flex-1" title={crash.input_path}>{crash.input_path.split("/").pop()}</span>
        <PathActions path={crash.input_path} />
      </div>
      {crash.summary && <p className="text-sm text-text-secondary">{crash.summary}</p>}
      <FindingProofCard proof={proof} unavailable={proofUnavailable} />
      {/* On-demand LLM crash verdict (L2 4c): opt in per crash. */}
      <div className="border-t border-border pt-3">
        {verdict === undefined && (
          <Button size="sm" variant="ghost" onClick={onVerify}>
            {t("triage.verifyCrash")}
          </Button>
        )}
        {verdict === "loading" && (
          <span className="text-xs text-text-muted">{t("triage.verifying")}</span>
        )}
        {verdict === "none" && (
          <span className="text-xs text-text-muted">{t("triage.noVerdict")}</span>
        )}
        {verdict && verdict !== "loading" && verdict !== "none" && (
          <div className="flex flex-col gap-1 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span
                style={{
                  color: verdict.likely_target_bug ? "var(--error)" : "var(--warning)",
                  fontWeight: 600,
                }}
              >
                {verdict.likely_target_bug ? t("triage.likelyTargetBug") : t("triage.likelyArtifact")}
              </span>
              <span className="text-text-muted">
                {t("triage.confidence", { level: verdict.confidence })}
              </span>
              {verdict.reproduces_deterministically && (
                <span className="text-text-muted">· {t("triage.reproduces")}</span>
              )}
            </div>
            {verdict.reasons.length > 0 && (
              <ul className="text-text-secondary" style={{ paddingLeft: 16, listStyleType: "disc" }}>
                {verdict.reasons.map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
      {crash.casr && (
        <div className="border-t border-border pt-3">
          <div className="text-xs text-text-muted uppercase mb-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            {t("triage.casrAnalysis")}
          </div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <SeverityBadge severity={crash.casr.severity} title={crash.casr.severity_short || crash.casr.severity} />
            {crash.casr.severity_short && (
              <span className="text-xs text-text-secondary font-mono">{crash.casr.severity_short}</span>
            )}
            {crash.casr.crashline && (
              <span className="text-xs text-text-muted font-mono">@ {crash.casr.crashline}</span>
            )}
            {crash.casr.cluster != null && (
              <span className="text-xs text-text-muted">{t("triage.cluster", { n: crash.casr.cluster })}</span>
            )}
          </div>
          {crash.casr.stack.length > 0 && (
            <code className="text-xs text-text-secondary block font-mono p-2 rounded-md whitespace-pre-wrap" style={{ background: "var(--surface-code)" }}>
              {crash.casr.stack.slice(0, 8).join("\n")}
            </code>
          )}
        </div>
      )}
      {crash.stack_signature && (
        <div>
          <div className="text-xs text-text-muted uppercase mb-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            {t("triage.stackSignature")}
          </div>
          <code className="text-xs text-text-secondary block font-mono p-2 rounded-md" style={{ background: "var(--surface-code)" }}>
            {crash.stack_signature.slice(0, 32)}...
          </code>
        </div>
      )}
      {crash.bug_report && (
        <div className="border-t border-border pt-3 mt-2">
          <div className="text-xs text-text-muted uppercase mb-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            {t("triage.draftBugReport")}
          </div>
          <p className="text-sm font-medium text-accent mb-1">{crash.bug_report.title}</p>
          <p className="text-xs text-text-secondary mb-2">{crash.bug_report.summary}</p>
          <div className="flex gap-2">
            <span
              className="text-xs px-2 py-0.5 rounded-sm"
              style={{
                background: "var(--surface-active)",
                color: "var(--text-secondary)",
              }}
            >
              {t("triage.severity", { value: crash.bug_report.severity_guess })}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
