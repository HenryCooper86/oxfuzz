import { useCallback, useEffect, useState } from "react";
import { getTransport, onDataChanged } from "../lib";
import { useProject } from "../providers/ProjectContext";
import type { RunHistoryItem } from "../types";
import { ViewHeader, EmptyState, Button, Input } from "../components/ui";
import { Play, Bug, Clock, GitCompare, X, Search } from "lucide-react";

function fmtDuration(secs: number | null): string {
  if (secs == null) return "—";
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return s ? `${m}m ${s}s` : `${m}m`;
}

const STATUS_COLOR: Record<string, string> = {
  Done: "var(--success)",
  Running: "var(--accent)",
  Pending: "var(--warning, #d9a441)",
  Cancelled: "var(--text-muted)",
  Failed: "var(--error)",
};

// A history of every fuzz run for the active project (all projects when none
// selected), with crash counts and durations, plus a two-run compare. Runs are
// read from the persisted store, so the history survives restarts.
export function RunsView() {
  const { activeProject } = useProject();
  const [runs, setRuns] = useState<RunHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [filter, setFilter] = useState("");

  const load = useCallback(async () => {
    setError(null);
    try {
      const list = await getTransport().invoke<RunHistoryItem[]>("run_history", {
        project: activeProject || undefined,
      });
      setRuns(list);
    } catch (e) {
      setError(String(e));
      setRuns([]);
    } finally {
      setLoading(false);
    }
  }, [activeProject]);

  useEffect(() => {
    queueMicrotask(() => void load());
    return onDataChanged(() => void load());
  }, [load]);

  const toggle = (id: string) =>
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2),
    );

  const compareRuns = selected
    .map((id) => runs.find((r) => r.id === id))
    .filter((r): r is RunHistoryItem => !!r);

  const q = filter.trim().toLowerCase();
  const shownRuns = q ? runs.filter((r) => `${r.engine} ${r.status}`.toLowerCase().includes(q)) : runs;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader
        title="Run History"
        description="Every fuzz run for this project, with crashes and duration. Select two runs to compare."
      />

      {error && (
        <div className="surface-card flex items-center justify-between gap-3" style={{ padding: "var(--space-sm) var(--space-md)", borderColor: "var(--error)" }}>
          <span className="text-xs min-w-0 truncate" style={{ color: "var(--error)" }}>Failed to load run history: {error}</span>
          <Button variant="outline" size="sm" onClick={() => void load()}>Retry</Button>
        </div>
      )}

      {compareRuns.length === 2 && (
        <section className="surface-card flex flex-col gap-3 min-w-0" style={{ padding: "var(--space-md)" }}>
          <div className="flex items-center gap-2">
            <GitCompare size={15} style={{ color: "var(--accent)" }} />
            <span className="text-sm font-semibold">Compare</span>
            <button className="ml-auto text-text-muted hover:text-text-primary" onClick={() => setSelected([])} title="Clear comparison" aria-label="Clear comparison">
              <X size={14} />
            </button>
          </div>
          <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 200px), 1fr))" }}>
            {compareRuns.map((r) => (
              <div key={r.id} className="rounded-md border border-border min-w-0" style={{ padding: "var(--space-md)", background: "var(--surface-secondary)" }}>
                <div className="text-sm font-semibold truncate">{r.engine}</div>
                <div className="text-xs text-text-muted mb-2">{new Date(r.started_at).toLocaleString()}</div>
                <CompareRow label="Status" value={r.status} />
                <CompareRow label="Crashes" value={String(r.crashes)} />
                <CompareRow label="Duration" value={fmtDuration(r.duration_secs)} />
              </div>
            ))}
          </div>
        </section>
      )}

      {loading ? (
        <p className="text-sm text-text-muted">Loading runs…</p>
      ) : runs.length === 0 ? (
        <EmptyState icon={<Play size={20} />} title="No runs yet" hint="Start a fuzz campaign from the Run view; each run is recorded here." />
      ) : (
        <div className="flex flex-col gap-1.5">
          {runs.length > 4 && (
            <div className="flex items-center gap-2 mb-1">
              <Search size={14} className="text-text-muted shrink-0" />
              <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by engine or status..." className="flex-1" />
            </div>
          )}
          {shownRuns.map((r) => {
            const isSel = selected.includes(r.id);
            return (
              <button
                key={r.id}
                onClick={() => toggle(r.id)}
                className="surface-card flex items-center gap-3 text-left transition-colors"
                style={{ padding: "var(--space-sm) var(--space-md)", borderColor: isSel ? "var(--accent)" : undefined }}
                title="Select to compare (up to 2)"
              >
                <Play size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
                <span className="text-sm font-medium truncate" style={{ minWidth: 90 }}>{r.engine}</span>
                <span className="text-xs shrink-0" style={{ color: STATUS_COLOR[r.status] ?? "var(--text-muted)" }}>{r.status}</span>
                <span className="flex-1" />
                <span className="text-xs text-text-muted flex items-center gap-1 shrink-0" title="Crashes">
                  <Bug size={12} style={{ color: r.crashes > 0 ? "var(--error)" : "var(--text-muted)" }} />
                  {r.crashes}
                </span>
                <span className="text-xs text-text-muted flex items-center gap-1 shrink-0" title="Duration">
                  <Clock size={12} />
                  {fmtDuration(r.duration_secs)}
                </span>
                <span className="text-xs text-text-muted shrink-0 hidden sm:inline">{new Date(r.started_at).toLocaleString()}</span>
              </button>
            );
          })}
        </div>
      )}

      {runs.length > 0 && (
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <Button variant="outline" size="sm" onClick={() => void load()}>Refresh</Button>
          {selected.length === 1 && <span>Select one more run to compare.</span>}
        </div>
      )}
    </div>
  );
}

function CompareRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2 text-xs py-0.5">
      <span className="text-text-muted">{label}</span>
      <span className="text-text-secondary font-medium truncate">{value}</span>
    </div>
  );
}
