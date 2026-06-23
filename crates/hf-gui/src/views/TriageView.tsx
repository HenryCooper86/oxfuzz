import { useState } from "react";
import { getTransport } from "../lib";
import type { Crash } from "../types";
import { Bug } from "lucide-react";

export function TriageView() {
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [loading, setLoading] = useState(false);

  async function triage() {
    setLoading(true);
    try {
      const result = await getTransport().invoke<Crash[]>("triage", {
        project: ".",
        target: "",
      });
      setCrashes(result);
    } catch {
      setCrashes([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Crash Triage</h1>
        <button
          onClick={triage}
          disabled={loading}
          className="px-4 py-2 bg-accent text-surface-tertiary rounded-DEFAULT hover:bg-accent-hover disabled:opacity-50"
        >
          {loading ? "Scanning..." : "Scan for Crashes"}
        </button>
      </div>
      {crashes.length === 0 ? (
        <p className="text-text-muted">No crash artifacts found.</p>
      ) : (
        <div className="flex flex-col gap-2">
          {crashes.map((c) => (
            <div key={c.id} className="surface-card p-3">
              <div className="flex items-center gap-2">
                <Bug size={16} className="text-error shrink-0" />
                <span className="font-mono text-sm">{c.kind}</span>
                <span className="text-xs text-text-muted">{c.input_path.split("/").pop()}</span>
              </div>
              {c.summary && <p className="text-xs text-text-secondary mt-1">{c.summary}</p>}
              {c.bug_report && (
                <div className="mt-2 text-xs">
                  <p className="text-accent font-semibold">{c.bug_report.title}</p>
                  <p className="text-text-secondary">{c.bug_report.summary}</p>
                  <p className="text-text-muted">Severity: {c.bug_report.severity_guess}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}