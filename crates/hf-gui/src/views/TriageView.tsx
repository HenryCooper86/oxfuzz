import { useState, useEffect, useRef, useCallback, lazy, Suspense } from "react";
import { getTransport } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import { useRunOutput } from "../providers/RunOutputContext";
import type { Crash, CasrReport } from "../types";
import { Button } from "../components/ui";
import { Bug, ChevronRight, FileDown, FileText } from "lucide-react";

// The report preview pulls in react-markdown + mermaid (heavy); load it only
// when the user opens a report, keeping it out of the initial bundle.
const ReportPreview = lazy(() =>
  import("../components/ReportPreview").then((m) => ({ default: m.ReportPreview })),
);

// CASR exploitability badge styling, keyed by the serialized CrashSeverity.
const SEVERITY_STYLE: Record<string, { label: string; bg: string; fg: string }> = {
  Exploitable: { label: "EXPLOITABLE", bg: "var(--error-subtle)", fg: "var(--error)" },
  ProbablyExploitable: { label: "PROBABLY EXPL.", bg: "rgba(217,119,6,0.16)", fg: "#d97706" },
  NotExploitable: { label: "NOT EXPL.", bg: "var(--surface-active)", fg: "var(--text-secondary)" },
  Undefined: { label: "UNCLASSIFIED", bg: "var(--surface-active)", fg: "var(--text-muted)" },
};

function SeverityBadge({ casr }: { casr: CasrReport }) {
  const s = SEVERITY_STYLE[casr.severity] ?? SEVERITY_STYLE.Undefined;
  return (
    <span
      className="text-xs px-1.5 py-0.5 rounded-sm font-semibold shrink-0"
      style={{ background: s.bg, color: s.fg, letterSpacing: "0.03em" }}
      title={casr.severity_short || casr.severity}
    >
      {s.label}
    </span>
  );
}

export function TriageView({ embedded = false }: { embedded?: boolean }) {
  const { activeProject } = useProject();
  const { markDone, markSkipped } = usePipeline();
  // The target + crash count from the most recent run, so triage scans the
  // right workspace and we know whether there is anything to triage.
  const { lastTarget, summary } = useRunOutput();
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [reporting, setReporting] = useState(false);
  const [reportMsg, setReportMsg] = useState<string | null>(null);
  const [reportMd, setReportMd] = useState<string | null>(null);

  // Whether the last run produced crashes (null = no run yet this session).
  const ranWithCrashes = summary ? summary.crashes > 0 : null;

  const triage = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getTransport().invoke<Crash[]>("triage", {
        project: activeProject || ".",
        target: lastTarget,
      });
      setCrashes(result);
      if (result.length > 0) markDone("triage");
      else markSkipped("triage");
    } catch {
      setCrashes([]);
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

  // Compose the report (AI-authored when a provider is configured) and open the
  // preview pane with the rendered Markdown + graphs.
  const previewReport = useCallback(async () => {
    setReporting(true);
    setReportMsg(null);
    try {
      const md = await getTransport().invoke<string>("generate_report", reportArgs());
      if (md) {
        setReportMd(md);
      } else {
        setReportMsg("Report generation is only available in the desktop app.");
      }
    } catch (e) {
      setReportMsg(`Report failed: ${e}`);
    } finally {
      setReporting(false);
    }
  }, [reportArgs]);

  // Save the report to disk: native dialog in the desktop app, blob download in
  // web mode. Uses the already-composed Markdown when previewing.
  const saveReport = useCallback(async () => {
    setReportMsg(null);
    try {
      const saved = await getTransport().invoke<string | null>("save_report", reportArgs());
      if (saved) {
        setReportMsg(`Saved to ${saved}`);
      } else if (reportMd) {
        // save_report unavailable (web) or cancelled: fall back to a download of
        // the report we already have.
        browserDownload(reportMd);
        setReportMsg("Report downloaded.");
      } else {
        const md = await getTransport().invoke<string>("generate_report", reportArgs());
        if (md) {
          browserDownload(md);
          setReportMsg("Report downloaded.");
        }
      }
    } catch (e) {
      setReportMsg(`Report failed: ${e}`);
    }
  }, [reportArgs, reportMd, browserDownload]);

  // Auto-triage: once a run completes with crashes, ingest + dedup them
  // automatically (once per run) so the user doesn't have to click Scan. The
  // button remains for manual re-scans.
  const autoTriagedRef = useRef<typeof summary>(null);
  useEffect(() => {
    if (summary && summary.crashes > 0 && autoTriagedRef.current !== summary) {
      autoTriagedRef.current = summary;
      void triage();
    }
  }, [summary, triage]);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        {embedded ? (
          <span />
        ) : (
          <div>
            <h1 className="text-xl font-semibold">Crash Triage</h1>
            <p className="text-sm text-text-secondary mt-0.5">
              Ingest, classify, and deduplicate crash artifacts from fuzz runs.
            </p>
          </div>
        )}
        <div className="flex items-center gap-2">
          {/* Compose a full report of the campaign (AI-authored when a provider
              is configured) and open it in a preview pane with rendered graphs.
              Enabled once a run has happened (a target is known). */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => void previewReport()}
            disabled={reporting || !lastTarget}
            loading={reporting}
            title="Compose a detailed report and preview it"
          >
            {!reporting && <FileText size={14} />}
            {reporting ? "Composing..." : "View Report"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void saveReport()}
            disabled={reporting || !lastTarget}
            title="Compose and download the report as Markdown"
          >
            <FileDown size={14} />
          </Button>
          <Button
            variant="primary"
            onClick={triage}
            disabled={loading}
            loading={loading}
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

      {/* Context from the last run, so the user knows what to expect. */}
      {summary && crashes.length === 0 && (
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

      {crashes.length === 0 && !loading && (
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
                {c.casr && <SeverityBadge casr={c.casr} />}
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
            onDownload={() => void saveReport()}
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
        {crash.casr && <SeverityBadge casr={crash.casr} />}
        <span className="text-xs text-text-muted font-mono">{crash.input_path.split("/").pop()}</span>
      </div>
      {crash.summary && <p className="text-sm text-text-secondary">{crash.summary}</p>}
      {crash.casr && (
        <div className="border-t border-border pt-3">
          <div className="text-xs text-text-muted uppercase mb-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            CASR Analysis
          </div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <SeverityBadge casr={crash.casr} />
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