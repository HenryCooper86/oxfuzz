import { useState } from "react";
import { getTransport } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import type { Crash } from "../types";
import { Bug, Loader2, ChevronRight } from "lucide-react";

export function TriageView() {
  const { activeProject } = useProject();
  const { markDone } = usePipeline();
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);

  async function triage() {
    setLoading(true);
    try {
      const result = await getTransport().invoke<Crash[]>("triage", {
        project: activeProject || ".",
        target: "",
      });
      setCrashes(result);
      if (result.length > 0) markDone("triage");
    } catch {
      setCrashes([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Crash Triage</h1>
          <p className="text-sm text-text-secondary mt-0.5">
            Ingest, classify, and deduplicate crash artifacts from fuzz runs.
          </p>
        </div>
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

      {crashes.length === 0 && !loading && (
        <div
          className="surface-card flex flex-col items-center justify-center"
          style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}
        >
          <Bug size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} />
          <p className="text-sm text-text-muted">No crash artifacts found.</p>
          <p className="text-xs text-text-muted mt-1">Run a fuzz campaign first, then scan the output directory.</p>
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
        <span className="text-xs text-text-muted font-mono">{crash.input_path.split("/").pop()}</span>
      </div>
      {crash.summary && <p className="text-sm text-text-secondary">{crash.summary}</p>}
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