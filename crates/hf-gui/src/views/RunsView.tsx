import { useCallback, useEffect, useState } from "react";
import { getTransport, onDataChanged, emitDataChanged } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useToast } from "../components/ui/Toast";
import { useConfirm } from "../providers/ConfirmContext";
import type { RunHistoryItem, CoverageSample } from "../types";
import { ViewHeader, EmptyState, Button, Input } from "../components/ui";
import { Play, Bug, Clock, GitCompare, X, Search, Activity, Zap, TrendingUp, LineChart, AlertTriangle, RotateCcw } from "lucide-react";
import { DiffView } from "../components/DiffView";

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
  const [expanded, setExpanded] = useState<string | null>(null);
  // Per-run coverage curve cache: undefined = not fetched, "loading", or samples.
  const [series, setSeries] = useState<Record<string, CoverageSample[] | "loading">>({});
  const { toast } = useToast();
  const confirm = useConfirm();
  // The harness diff modal opened from a coverage-trend change marker.
  const [diff, setDiff] = useState<
    | { from: string; to: string; fromId: string; toId: string; oldText: string; newText: string }
    | "loading"
    | null
  >(null);
  const [reverting, setReverting] = useState(false);

  const toggleCurve = useCallback(async (id: string) => {
    setExpanded((cur) => (cur === id ? null : id));
    if (series[id] !== undefined) return;
    setSeries((s) => ({ ...s, [id]: "loading" }));
    try {
      const samples = await getTransport().invoke<CoverageSample[]>("run_coverage_series", { run_id: id });
      setSeries((s) => ({ ...s, [id]: samples }));
    } catch {
      setSeries((s) => ({ ...s, [id]: [] }));
    }
  }, [series]);

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

  // Chronological (oldest->newest) finished runs with recorded coverage, for the
  // trend charts. Capped so a long history stays readable.
  const trend = runs
    .filter((r) => r.edges != null)
    .slice(0, 24)
    .reverse();

  // Label each distinct harness revision in chronological order of first use,
  // so a coverage jump can be tied to the harness change that produced it.
  const revOrder: string[] = [];
  for (let i = runs.length - 1; i >= 0; i--) {
    const h = runs[i].harness_rev;
    if (h && !revOrder.includes(h)) revOrder.push(h);
  }
  const revLabel = (h: string | null): string | null =>
    h ? `rev ${revOrder.indexOf(h) + 1}` : null;
  // Per trend bar: did the harness change vs the previous run?
  const changeAt = trend.map(
    (r, i) => i > 0 && r.harness_rev != null && r.harness_rev !== trend[i - 1].harness_rev,
  );
  const anyRevChange = changeAt.some(Boolean);
  // A regression: the harness changed AND coverage dropped vs the previous run,
  // so the new revision is worse -- flag it so bad harness changes stand out.
  const regressAt = trend.map(
    (r, i) => changeAt[i] && (r.edges ?? 0) < (trend[i - 1].edges ?? 0),
  );
  const regressedIds = new Set(trend.filter((_, i) => regressAt[i]).map((r) => r.id));
  const regressCount = regressAt.filter(Boolean).length;

  // Open the harness diff between a run and the one before it, from a marker.
  async function openRevDiff(i: number) {
    const cur = trend[i];
    const prev = trend[i - 1];
    if (!cur || !prev) return;
    setDiff("loading");
    try {
      const [oldText, newText] = await Promise.all([
        getTransport().invoke<string>("run_harness_source", { run_id: prev.id }),
        getTransport().invoke<string>("run_harness_source", { run_id: cur.id }),
      ]);
      setDiff({
        from: revLabel(prev.harness_rev) ?? "previous",
        to: revLabel(cur.harness_rev) ?? "current",
        fromId: prev.id,
        toId: cur.id,
        oldText,
        newText,
      });
    } catch {
      setDiff(null);
    }
  }

  // Revert the target's harness to the revision a given run used (recompiles).
  async function revertTo(runId: string, label: string) {
    if (
      !(await confirm({
        title: `Revert harness to ${label}?`,
        message: "This restores that revision's harness source and recompiles it in the sandbox, making it the current harness for the target.",
        confirmLabel: "Revert & recompile",
      }))
    ) {
      return;
    }
    setReverting(true);
    try {
      const res = await getTransport().invoke<{ status: string; message: string }>("revert_harness_from_run", { run_id: runId });
      const ok = res?.status === "Compiled";
      toast({
        title: ok ? `Reverted to ${label}` : "Revert finished with a compile issue",
        description: res?.message,
        variant: ok ? "success" : "error",
      });
      setDiff(null);
      emitDataChanged();
    } catch (e) {
      toast({ title: "Revert failed", description: String(e), variant: "error" });
    } finally {
      setReverting(false);
    }
  }

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

      <AutoRevertPolicyCard />

      {trend.length >= 2 && (
        <section className="surface-card flex flex-col gap-3 min-w-0" style={{ padding: "var(--space-md)" }}>
          <div className="flex items-center gap-2">
            <TrendingUp size={15} style={{ color: "var(--accent)" }} />
            <span className="text-sm font-semibold">Trends</span>
            <span className="text-xs text-text-muted">last {trend.length} runs</span>
          </div>
          <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 220px), 1fr))" }}>
            <MiniTrend
              title="Coverage (edges)"
              icon={<Activity size={13} />}
              runs={trend}
              value={(r) => r.edges ?? 0}
              color="var(--success)"
              marks={changeAt}
              warn={regressAt}
              onMark={(i) => void openRevDiff(i)}
            />
            <MiniTrend
              title="Throughput (execs/sec)"
              icon={<Zap size={13} />}
              runs={trend}
              value={(r) => Math.round(r.execs ?? 0)}
              color="var(--accent)"
            />
            <MiniTrend
              title="Crashes"
              icon={<Bug size={13} />}
              runs={trend}
              value={(r) => r.crashes}
              color="var(--error)"
            />
          </div>
          {regressCount > 0 && (
            <div
              className="rounded-md flex items-start gap-2 text-xs"
              style={{ padding: "var(--space-sm) var(--space-md)", background: "var(--error-subtle)", border: "1px solid var(--error)" }}
            >
              <AlertTriangle size={14} style={{ color: "var(--error)", flexShrink: 0, marginTop: 1 }} />
              <span style={{ color: "var(--error)" }}>
                {regressCount} harness revision{regressCount === 1 ? "" : "s"} reduced coverage. Click a{" "}
                <span style={{ fontWeight: 600 }}>red ▲</span> to see the change that regressed it.
              </span>
            </div>
          )}
          {anyRevChange && (
            <p className="text-xs text-text-muted flex items-center gap-1">
              <span style={{ color: "var(--accent)" }}>▲</span>
              marks a run where the harness revision changed{regressCount > 0 ? " (red = coverage dropped)" : ""} — click it to see exactly what changed in the harness.
            </p>
          )}
        </section>
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
                <CompareRow label="Harness" value={revLabel(r.harness_rev) ?? "—"} />
                <CompareRow label="Coverage (edges)" value={r.edges != null ? r.edges.toLocaleString() : "—"} />
                <CompareRow label="Execs/sec (peak)" value={r.execs != null ? Math.round(r.execs).toLocaleString() : "—"} />
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
            const isOpen = expanded === r.id;
            const data = series[r.id];
            return (
              <div key={r.id} className="flex flex-col">
                <div
                  className="surface-card flex items-center gap-3 transition-colors"
                  style={{ padding: "var(--space-sm) var(--space-md)", borderColor: isSel || isOpen ? "var(--accent)" : undefined }}
                >
                  <button
                    onClick={() => toggle(r.id)}
                    className="flex items-center gap-3 flex-1 min-w-0 text-left bg-transparent"
                    style={{ border: "none", cursor: "pointer" }}
                    title="Select to compare (up to 2)"
                  >
                    <Play size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
                    <span className="text-sm font-medium truncate" style={{ minWidth: 90 }}>{r.engine}</span>
                    <span className="text-xs shrink-0" style={{ color: STATUS_COLOR[r.status] ?? "var(--text-muted)" }}>{r.status}</span>
                    {r.harness_rev && (
                      <span
                        className="text-xs shrink-0 px-1.5 py-0.5 rounded-sm hidden md:inline"
                        style={{ background: "var(--surface-active)", color: "var(--text-muted)" }}
                        title={`Harness revision ${r.harness_rev}`}
                      >
                        {revLabel(r.harness_rev)}
                      </span>
                    )}
                    {regressedIds.has(r.id) && (
                      <span
                        className="text-xs shrink-0 px-1.5 py-0.5 rounded-sm inline-flex items-center gap-1"
                        style={{ background: "var(--error-subtle)", color: "var(--error)" }}
                        title="Coverage dropped after this harness revision"
                      >
                        <AlertTriangle size={10} /> regressed
                      </span>
                    )}
                    <span className="flex-1" />
                    <span className="text-xs text-text-muted flex items-center gap-1 shrink-0 hidden sm:flex" title="Peak edge coverage">
                      <Activity size={12} />
                      {r.edges != null ? r.edges.toLocaleString() : "—"}
                    </span>
                    <span className="text-xs text-text-muted flex items-center gap-1 shrink-0 hidden sm:flex" title="Peak execs/sec">
                      <Zap size={12} />
                      {r.execs != null ? Math.round(r.execs).toLocaleString() : "—"}
                    </span>
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
                  <button
                    onClick={() => void toggleCurve(r.id)}
                    className="shrink-0 inline-flex items-center justify-center rounded p-1 transition-colors"
                    style={{ color: isOpen ? "var(--accent)" : "var(--text-muted)", border: "none", background: "transparent", cursor: "pointer" }}
                    title="Coverage-over-time curve"
                    aria-label="Toggle coverage curve"
                  >
                    <LineChart size={14} />
                  </button>
                </div>
                {isOpen && (
                  <div className="surface-card mt-1" style={{ padding: "var(--space-md)" }}>
                    {data === "loading" || data === undefined ? (
                      <p className="text-xs text-text-muted">Loading coverage curve…</p>
                    ) : data.length < 2 ? (
                      <p className="text-xs text-text-muted">No coverage samples were recorded for this run (older runs, very short runs, or engines that don't stream coverage).</p>
                    ) : (
                      <CoverageCurve samples={data} />
                    )}
                  </div>
                )}
              </div>
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

      {diff !== null && (
        <div
          className="fixed inset-0 z-9999 flex items-center justify-center"
          style={{ background: "rgba(0,0,0,0.5)", backdropFilter: "blur(2px)" }}
          onClick={() => setDiff(null)}
        >
          <div
            className="surface-card flex flex-col"
            style={{ width: "min(820px, 94vw)", maxHeight: "86vh", padding: 0, boxShadow: "var(--shadow-lg)", animation: "dialogContentIn 0.15s ease" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-border" style={{ padding: "var(--space-md)" }}>
              <span className="text-sm font-semibold flex items-center gap-2">
                <GitCompare size={15} style={{ color: "var(--accent)" }} />
                Harness diff{diff !== "loading" ? `: ${diff.from} → ${diff.to}` : ""}
              </span>
              <button onClick={() => setDiff(null)} className="hf-action-btn" title="Close" aria-label="Close">
                <X size={16} />
              </button>
            </div>
            <div className="overflow-auto" style={{ padding: "var(--space-md)" }}>
              {diff === "loading" ? (
                <p className="text-xs text-text-muted">Loading harness diff…</p>
              ) : diff.oldText === diff.newText ? (
                <p className="text-xs text-text-muted">The stored harness sources are identical.</p>
              ) : !diff.oldText && !diff.newText ? (
                <p className="text-xs text-text-muted">No harness source was recorded for these runs (older runs).</p>
              ) : (
                <DiffView oldText={diff.oldText} newText={diff.newText} />
              )}
            </div>
            {diff !== "loading" && (diff.oldText || diff.newText) && (
              <div className="flex items-center justify-end gap-2 border-t border-border" style={{ padding: "var(--space-md)" }}>
                <span className="text-xs text-text-muted mr-auto">Restore either revision as the current harness (recompiles):</span>
                {diff.oldText && (
                  <Button variant="primary" size="sm" onClick={() => void revertTo(diff.fromId, diff.from)} loading={reverting} disabled={reverting}>
                    <RotateCcw size={13} /> Revert to {diff.from}
                  </Button>
                )}
                {diff.newText && diff.newText !== diff.oldText && (
                  <Button variant="outline" size="sm" onClick={() => void revertTo(diff.toId, diff.to)} disabled={reverting}>
                    <RotateCcw size={13} /> Restore {diff.to}
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// The auto-revert policy control: arms the backend to automatically restore the
// previous (last-good) harness when a revision regresses coverage past the
// threshold. Backed by `hobot-fuzz.toml` via the config round-trip commands, so
// the setting is the same one the CLI/service read.
function AutoRevertPolicyCard() {
  const { toast } = useToast();
  const [enabled, setEnabled] = useState(false);
  const [threshold, setThreshold] = useState(20);
  const [notifyOnly, setNotifyOnly] = useState(false);
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const raw = await getTransport().invoke<string>("read_config", { name: "hobot-fuzz" });
        const val = await getTransport().invoke<Record<string, unknown>>("config_toml_to_value", { content: raw });
        if (cancelled) return;
        if (typeof val.auto_revert_enabled === "boolean") setEnabled(val.auto_revert_enabled);
        if (typeof val.auto_revert_threshold_pct === "number") setThreshold(val.auto_revert_threshold_pct);
        if (typeof val.auto_revert_notify_only === "boolean") setNotifyOnly(val.auto_revert_notify_only);
      } catch {
        // Keep the safe defaults (off, 20%, apply) if the config cannot be read.
      } finally {
        if (!cancelled) setReady(true);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const persist = useCallback(
    async (next: { enabled: boolean; threshold: number; notifyOnly: boolean }) => {
      setSaving(true);
      try {
        const raw = await getTransport().invoke<string>("read_config", { name: "hobot-fuzz" });
        const val = await getTransport().invoke<Record<string, unknown>>("config_toml_to_value", { content: raw });
        val.auto_revert_enabled = next.enabled;
        val.auto_revert_threshold_pct = next.threshold;
        val.auto_revert_notify_only = next.notifyOnly;
        const toml = await getTransport().invoke<string>("config_value_to_toml", { value: val });
        await getTransport().invoke("write_config", { name: "hobot-fuzz", content: toml });
        toast({
          title: next.enabled
            ? `Auto-revert armed (>${next.threshold}% drop${next.notifyOnly ? ", notify-only" : ""})`
            : "Auto-revert disabled",
          variant: "success",
        });
      } catch (e) {
        toast({ title: "Could not save the auto-revert policy", description: String(e), variant: "error" });
      } finally {
        setSaving(false);
      }
    },
    [toast],
  );

  const toggle = () => {
    const next = !enabled;
    setEnabled(next);
    void persist({ enabled: next, threshold, notifyOnly });
  };

  const commitThreshold = () => {
    const clamped = Math.min(100, Math.max(1, Math.round(threshold)));
    setThreshold(clamped);
    if (enabled) void persist({ enabled, threshold: clamped, notifyOnly });
  };

  const toggleNotifyOnly = () => {
    const next = !notifyOnly;
    setNotifyOnly(next);
    if (enabled) void persist({ enabled, threshold, notifyOnly: next });
  };

  return (
    <section className="surface-card flex flex-col gap-2 min-w-0" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <RotateCcw size={15} style={{ color: "var(--accent)", flexShrink: 0 }} />
          <span className="text-sm font-semibold">Auto-revert policy</span>
          <span
            className="text-xs rounded-full"
            style={{
              padding: "1px 8px",
              background: enabled ? "var(--success-subtle, var(--surface-secondary))" : "var(--surface-secondary)",
              color: enabled ? "var(--success)" : "var(--text-muted)",
              fontWeight: 600,
            }}
          >
            {enabled ? "On" : "Off"}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-text-muted">
            drop &gt;
            <Input
              type="number"
              min={1}
              max={100}
              value={String(threshold)}
              disabled={!ready || saving}
              onChange={(e) => setThreshold(Number(e.target.value))}
              onBlur={commitThreshold}
              style={{ width: 68 }}
              aria-label="Coverage-drop threshold percent"
            />
            %
          </label>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label="Enable auto-revert"
            disabled={!ready || saving}
            onClick={toggle}
            className="relative rounded-full transition-colors"
            style={{
              width: 40,
              height: 22,
              background: enabled ? "var(--accent)" : "var(--surface-secondary)",
              border: "1px solid var(--border)",
              cursor: ready && !saving ? "pointer" : "default",
            }}
          >
            <span
              className="absolute rounded-full transition-all"
              style={{
                width: 16,
                height: 16,
                top: 2,
                left: enabled ? 20 : 2,
                background: enabled ? "#fff" : "var(--text-muted)",
              }}
            />
          </button>
        </div>
      </div>
      {enabled && (
        <label
          className="flex items-center gap-2 text-xs"
          style={{ cursor: ready && !saving ? "pointer" : "default", color: "var(--text-secondary)" }}
        >
          <input
            type="checkbox"
            checked={notifyOnly}
            disabled={!ready || saving}
            onChange={toggleNotifyOnly}
            aria-label="Notify only, do not restore automatically"
          />
          Notify-only &mdash; flag the regression but don&apos;t restore automatically (recommended for
          scheduled campaigns)
        </label>
      )}
      <p className="text-xs text-text-muted" style={{ lineHeight: 1.5 }}>
        When a run&apos;s harness revision changes and its edge coverage drops by at least this much
        versus the previous run for the same target,{" "}
        {notifyOnly ? (
          <>the regression is flagged in run history and the campaign log, but the harness is left as-is.</>
        ) : (
          <>
            the previous (last-good) revision is restored and recompiled automatically. The recompile
            still requires the usual sandbox approval.
          </>
        )}{" "}
        Scheduled campaigns apply this same policy between refinement iterations.
      </p>
    </section>
  );
}

// A compact bar chart of a metric across successive runs (oldest -> newest).
function MiniTrend({
  title,
  icon,
  runs,
  value,
  color,
  marks,
  warn,
  onMark,
}: {
  title: string;
  icon: React.ReactNode;
  runs: RunHistoryItem[];
  value: (r: RunHistoryItem) => number;
  color: string;
  /** Per-bar flag: a harness revision change occurred at this run. */
  marks?: boolean[];
  /** Per-bar flag: this run regressed coverage (drop after a harness change). */
  warn?: boolean[];
  /** Clicking a change marker opens the harness diff for that run. */
  onMark?: (index: number) => void;
}) {
  const values = runs.map(value);
  const max = Math.max(1, ...values);
  const latest = values[values.length - 1] ?? 0;
  const prev = values[values.length - 2] ?? latest;
  const delta = latest - prev;
  return (
    <div className="rounded-md border border-border min-w-0" style={{ padding: "var(--space-sm) var(--space-md)", background: "var(--surface-secondary)" }}>
      <div className="flex items-center gap-1.5 text-xs text-text-muted">
        {icon}
        <span className="truncate">{title}</span>
      </div>
      <div className="flex items-baseline gap-2 mt-1">
        <span className="text-lg font-semibold" style={{ color }}>{latest.toLocaleString()}</span>
        {delta !== 0 && (
          <span className="text-xs" style={{ color: delta > 0 ? "var(--success)" : "var(--text-muted)" }}>
            {delta > 0 ? "+" : ""}
            {delta.toLocaleString()} vs prev
          </span>
        )}
      </div>
      <div className="flex items-end gap-0.5 mt-2" style={{ height: 40 }}>
        {values.map((v, i) => {
          const changed = marks?.[i];
          const regressed = warn?.[i];
          const markColor = regressed ? "var(--error)" : "var(--accent)";
          const barColor = regressed
            ? "var(--error)"
            : changed
              ? "var(--accent)"
              : i === values.length - 1
                ? color
                : "var(--border)";
          return (
            <div key={i} className="flex flex-col items-center justify-end" style={{ flex: 1, minWidth: 2, height: "100%" }}>
              {changed && onMark ? (
                <button
                  onClick={() => onMark(i)}
                  title={regressed ? "Coverage dropped here — view the harness diff" : "View the harness diff that caused this"}
                  aria-label="View harness diff"
                  style={{ height: 8, lineHeight: "8px", fontSize: 8, color: markColor, background: "transparent", border: "none", cursor: "pointer", padding: 0 }}
                >
                  ▲
                </button>
              ) : (
                <span style={{ height: 8, lineHeight: "8px", fontSize: 8, color: markColor }}>
                  {changed ? "▲" : ""}
                </span>
              )}
              <div
                title={`${new Date(runs[i].started_at).toLocaleString()}: ${v.toLocaleString()}${regressed ? " (coverage regressed after harness change)" : changed ? " (harness changed)" : ""}`}
                style={{
                  width: "100%",
                  height: `${Math.max(3, (v / max) * 100)}%`,
                  background: barColor,
                  borderRadius: 1,
                }}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

// The intra-run coverage curve: edges over elapsed time, drawn as an area chart.
function CoverageCurve({ samples }: { samples: CoverageSample[] }) {
  const W = 600;
  const H = 150;
  const padL = 6;
  const padR = 6;
  const padT = 10;
  const padB = 16;
  const tMax = Math.max(1, ...samples.map((s) => s.t));
  const eMax = Math.max(1, ...samples.map((s) => s.edges));
  const x = (t: number) => padL + (t / tMax) * (W - padL - padR);
  const y = (e: number) => H - padB - (e / eMax) * (H - padT - padB);
  const pts = samples.map((s) => `${x(s.t).toFixed(1)},${y(s.edges).toFixed(1)}`);
  const line = `M${pts.join(" L")}`;
  const area = `M${x(samples[0].t).toFixed(1)},${H - padB} L${pts.join(" L")} L${x(
    samples[samples.length - 1].t,
  ).toFixed(1)},${H - padB} Z`;
  const peakEdges = Math.max(...samples.map((s) => s.edges));
  const duration = samples[samples.length - 1].t;
  return (
    <div className="min-w-0">
      <div className="flex items-center justify-between text-xs text-text-muted mb-2 gap-2">
        <span className="flex items-center gap-1">
          <Activity size={12} /> Coverage over time
        </span>
        <span className="truncate">
          peak {peakEdges.toLocaleString()} edges · {Math.round(duration)}s · {samples.length} samples
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" style={{ display: "block" }}>
        <path d={area} fill="var(--success)" opacity={0.14} />
        <path d={line} fill="none" stroke="var(--success)" strokeWidth={1.5} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        <line x1={padL} y1={H - padB} x2={W - padR} y2={H - padB} stroke="var(--border)" strokeWidth={1} vectorEffect="non-scaling-stroke" />
      </svg>
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
