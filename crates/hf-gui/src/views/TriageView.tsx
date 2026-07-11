import { useState, useEffect, useRef, useCallback, lazy, Suspense } from "react";
import { getTransport, isTauriEnvironment, emitDataChanged } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import { useRunOutput } from "../providers/RunOutputContext";
import type { Crash } from "../types";
import { Button, ViewHeader, SeverityBadge } from "../components/ui";
import { Bug, ChevronRight, FileText, Share2 } from "lucide-react";
import { PathActions } from "../components/PathActions";

// The report preview pulls in react-markdown + mermaid (heavy); load it only
// when the user opens a report, keeping it out of the initial bundle.
const ReportPreview = lazy(() =>
  import("../components/ReportPreview").then((m) => ({ default: m.ReportPreview })),
);

export function TriageView({ embedded = false }: { embedded?: boolean }) {
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
      if (result.length > 0) markDone("triage");
      else markSkipped("triage");
      return result;
    } catch (e) {
      // A failed scan previously looked identical to "no crashes found".
      setCrashes([]);
      setTriageError(String(e));
      return [];
    } finally {
      setLoading(false);
    }
  }, [activeProject, lastTarget, markDone, markSkipped]);

  const reportArgs = useCallback(
    () => ({ project: activeProject || ".", target: lastTarget }),
    [activeProject, lastTarget],
  );

  // Browser blob download (web mode, or when the native dialog is unavailable).
  const browserDownload = useCallback(
    (md: string) => {
      const blob = new Blob([md], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `hobot_fuzz_report_${(lastTarget || "target").replace(/[^a-zA-Z0-9_-]/g, "_")}.md`;
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
        setReportMsg("Report generation is only available in the desktop app.");
        return;
      }
      setReportMd(md);
      await getTransport().invoke("save_report_draft", {
        title: `Triage report — ${lastTarget || "target"}`,
        project: activeProject || ".",
        target: lastTarget || undefined,
        status: "Draft",
        content: md,
      });
      emitDataChanged();
      setReportMsg("AI report composed and saved to Workbench reports.");
    } catch (e) {
      setReportMsg(`Report failed: ${e}`);
    } finally {
      setReporting(false);
    }
  }, [reportArgs, lastTarget, activeProject]);

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
          });
          if (saved) setReportMsg(`Saved ${format.toUpperCase()} to ${saved}`);
        } else if (format === "md" && reportMd) {
          browserDownload(reportMd);
          setReportMsg("Report downloaded.");
        } else {
          setReportMsg(`${format.toUpperCase()} export is only available in the desktop app.`);
        }
      } catch (e) {
        setReportMsg(`Export failed: ${e}`);
      }
    },
    [activeProject, lastTarget, reportMd, browserDownload],
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
        `Pushed ${outcome.findings_pushed} finding(s) to DefectDojo${outcome.reimported ? " (reimport)" : ""}${where}.`,
      );
    } catch (e) {
      setReportMsg(`DefectDojo push failed: ${e}`);
    } finally {
      setPushing(false);
    }
  }, [activeProject, lastTarget]);

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
            title="Crash Triage"
            description="Ingest, classify, and deduplicate crash artifacts from fuzz runs."
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
            title="Compose an AI report, save it to the Workbench, and preview it"
          >
            {!reporting && <FileText size={14} />}
            {reporting ? "Composing..." : "Compose Report"}
          </Button>
          {crashes.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void pushToDefectDojo()}
              disabled={pushing}
              loading={pushing}
              title="Push these triaged crashes to DefectDojo as findings (configure in Settings > Integrations)"
            >
              {!pushing && <Share2 size={14} />}
              {pushing ? "Pushing..." : "Push to DefectDojo"}
            </Button>
          )}
          <Button
            variant="primary"
            onClick={triage}
            disabled={loading || !lastTarget || isKernelRun}
            loading={loading}
            title={
              isKernelRun
                ? "Kernel crashes are collected by syzkaller, not per-target triage"
                : lastTarget
                  ? "Scan the last run's output for crashes"
                  : "Run a fuzz campaign first"
            }
          >
            {!loading && <Bug size={14} />}
            {loading ? "Scanning..." : "Scan for Crashes"}
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
          Scan failed: {triageError}
        </div>
      )}

      {/* Kernel campaigns collect crashes in the syzkaller workdir, outside the
          per-target triage path -- explain rather than scan into an empty result. */}
      {isKernelRun && summary && (
        <div
          className="surface-card text-sm"
          style={{ padding: "var(--space-md)", borderLeft: `3px solid ${summary.crashes > 0 ? "var(--error)" : "var(--success)"}` }}
        >
          Kernel (syzkaller) campaign reported <strong>{summary.crashes}</strong> crash
          {summary.crashes === 1 ? "" : "es"}. Kernel crashes are collected in the syzkaller
          workspace (reproducers + logs under the run&apos;s workdir), not the per-target triage
          path, so per-target scanning does not apply here.
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
              Last run{lastTarget ? ` on ${lastTarget}` : ""} reported{" "}
              <strong>{summary.crashes}</strong> crash{summary.crashes === 1 ? "" : "es"} — ingesting
              and deduplicating automatically. Use Scan to re-run.
            </>
          ) : (
            <>
              Last run{lastTarget ? ` on ${lastTarget}` : ""} found no crashes — nothing to triage. This
              stage was skipped.
            </>
          )}
        </div>
      )}

      {crashes.length === 0 && !loading && !isKernelRun && (
        <div
          className="surface-card flex flex-col items-center justify-center"
          style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}
        >
          <Bug size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} />
          <p className="text-sm text-text-muted">No crash artifacts ingested yet.</p>
          <p className="text-xs text-text-muted mt-1">
            {lastTarget
              ? `Scan the output of the last run on "${lastTarget}".`
              : "Run a fuzz campaign first, then scan the output directory."}
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
              <CrashDetail crash={crashes[selected]} />
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

function CrashDetail({ crash }: { crash: Crash }) {
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
      {crash.casr && (
        <div className="border-t border-border pt-3">
          <div className="text-xs text-text-muted uppercase mb-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            CASR Analysis
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
              <span className="text-xs text-text-muted">cluster {crash.casr.cluster}</span>
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
            Stack Signature
          </div>
          <code className="text-xs text-text-secondary block font-mono p-2 rounded-md" style={{ background: "var(--surface-code)" }}>
            {crash.stack_signature.slice(0, 32)}...
          </code>
        </div>
      )}
      {crash.bug_report && (
        <div className="border-t border-border pt-3 mt-2">
          <div className="text-xs text-text-muted uppercase mb-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            Draft Bug Report
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
              Severity: {crash.bug_report.severity_guess}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}