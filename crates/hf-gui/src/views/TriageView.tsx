import { useState, useEffect, useRef, useCallback } from "react";
import { getTransport } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import { useRunOutput } from "../providers/RunOutputContext";
import type { Crash, CasrReport } from "../types";
import { Bug, Loader2, ChevronRight } from "lucide-react";

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
        <button
          onClick={triage}
          disabled={loading}
          className="inline-flex items-center justify-center gap-1 px-4 py-2 text-xs font-medium rounded-md border border-solid transition-all duration-150 outline-none disabled:opacity-55"
          style={{
            background: "var(--accent)",
            color: "var(--accent-contrast)",
            borderColor: "transparent",
          }}
          onMouseEnter={(e) => !loading && (e.currentTarget.style.opacity = "0.85")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Bug size={14} />}
          {loading ? "Scanning..." : "Scan for Crashes"}
        </button>
      </div>

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