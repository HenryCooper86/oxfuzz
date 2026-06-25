import { useEffect, useRef, useState, type ReactNode } from "react";
import { Puzzle, BookOpen, Zap, Target, FileCode, Activity, Bug, Crosshair, Play, Loader2, Plus, Trash2, RotateCw, Square } from "lucide-react";
import { getTransport } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useTarget } from "../providers/TargetContext";
import { usePrefs } from "../providers/PrefsContext";

// ---------------------------------------------------------------------------
// Shared scaffolding
// ---------------------------------------------------------------------------

function ViewHeader({ title, description }: { title: string; description: string }) {
  return (
    <div>
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-sm text-text-secondary mt-0.5">{description}</p>
    </div>
  );
}

function EmptyState({ icon, hint }: { icon: ReactNode; hint: string }) {
  return (
    <div
      className="surface-card flex flex-col items-center justify-center text-center"
      style={{ padding: "var(--space-xl) var(--space-md)" }}
    >
      <div
        className="flex items-center justify-center mb-3 rounded-full"
        style={{ width: "48px", height: "48px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}
      >
        <span style={{ color: "var(--accent)" }}>{icon}</span>
      </div>
      <p className="text-sm text-text-secondary max-w-sm">{hint}</p>
      <span
        className="text-xs mt-3 px-2 py-0.5 rounded-sm"
        style={{ background: "var(--surface-active)", color: "var(--text-muted)" }}
      >
        Coming soon
      </span>
    </div>
  );
}

function Card({ icon, title, subtitle }: { icon: ReactNode; title: string; subtitle: string }) {
  return (
    <div className="surface-card flex items-start gap-3" style={{ padding: "var(--space-md)" }}>
      <div
        className="flex items-center justify-center shrink-0 rounded-md"
        style={{ width: "34px", height: "34px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}
      >
        <span style={{ color: "var(--accent)" }}>{icon}</span>
      </div>
      <div className="flex flex-col min-w-0">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-xs text-text-secondary mt-0.5">{subtitle}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

const AGENTS = [
  { icon: <Target size={16} />, title: "Discovery", subtitle: "Scans projects and ranks fuzzing targets." },
  { icon: <FileCode size={16} />, title: "Harness", subtitle: "Authors and compiles harnesses per target." },
  { icon: <Activity size={16} />, title: "Coverage", subtitle: "Grows corpora and tracks coverage deltas." },
  { icon: <Bug size={16} />, title: "Triage", subtitle: "Dedupes crashes and drafts bug reports." },
];

export function AgentsView() {
  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Agents" description="Specialized sub-agents that discover targets, write harnesses, and triage crashes." />
      <div className="grid grid-cols-2 gap-3">
        {AGENTS.map((a) => (
          <Card key={a.title} icon={a.icon} title={a.title} subtitle={a.subtitle} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skills
// ---------------------------------------------------------------------------

const SKILLS = [
  { title: "harness-author", subtitle: "Generates compile-validated fuzz harnesses for a target." },
  { title: "crash-triage", subtitle: "Classifies and minimizes crashes by stack signature." },
  { title: "target-triage", subtitle: "Heuristics for ranking functions worth fuzzing." },
];

export function SkillsView() {
  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Skills" description="Reusable, self-evolving skills the agent applies across runs." />
      <div className="flex flex-col gap-2">
        {SKILLS.map((s) => (
          <Card key={s.title} icon={<Puzzle size={16} />} title={s.title} subtitle={s.subtitle} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Knowledge
// ---------------------------------------------------------------------------

interface KnowledgeTarget {
  symbol: string;
  kind: string;
  fit_score: number;
  project: string;
  location: string;
}
interface KnowledgeRun {
  id: string;
  project: string;
  engine: string;
  status: string;
  started_at: string;
}
interface KnowledgeCrash {
  kind: string;
  summary: string;
  signature: string;
}
interface KnowledgeSummary {
  db_configured: boolean;
  targets: KnowledgeTarget[];
  runs: KnowledgeRun[];
  crashes: KnowledgeCrash[];
}

const shortProject = (p: string) => p.split("/").filter(Boolean).pop() || p;

export function KnowledgeView() {
  const [data, setData] = useState<KnowledgeSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    getTransport()
      .invoke<KnowledgeSummary>("knowledge_summary")
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  };

  // Initial load (no synchronous setState in the effect body).
  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<KnowledgeSummary>("knowledge_summary")
      .then((d) => !cancelled && setData(d))
      .catch(() => !cancelled && setData(null))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  const empty = data && data.targets.length === 0 && data.runs.length === 0 && data.crashes.length === 0;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <ViewHeader title="Knowledge" description="What hobot_fuzz has learned about your projects — discovered targets, fuzz runs, and crashes found." />
        <button
          onClick={load}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary"
        >
          {loading ? <Loader2 size={13} className="animate-spin" /> : <RotateCw size={13} />}
          Refresh
        </button>
      </div>

      {data && !data.db_configured && (
        <EmptyState icon={<BookOpen size={20} />} hint="No database configured (HF_DB_PATH). Run `hobot-fuzz init` or run a campaign to start accumulating knowledge." />
      )}
      {empty && data?.db_configured && (
        <EmptyState icon={<BookOpen size={20} />} hint="Nothing learned yet. Discover targets and run a fuzz campaign — what hobot_fuzz finds is recorded here." />
      )}

      {data && !empty && (
        <>
          <KnowledgeSection title="Targets" count={data.targets.length} icon={<Crosshair size={14} />}>
            {data.targets.slice(0, 40).map((t, i) => (
              <Row key={i} left={t.symbol} mid={`${t.kind} · fit ${t.fit_score.toFixed(2)}`} right={`${shortProject(t.project)} · ${t.location.split("/").pop()}`} />
            ))}
          </KnowledgeSection>

          <KnowledgeSection title="Runs" count={data.runs.length} icon={<Play size={14} />}>
            {data.runs.slice(0, 40).map((r) => (
              <Row key={r.id} left={r.engine} mid={r.status} right={`${shortProject(r.project)} · ${new Date(r.started_at).toLocaleString()}`} />
            ))}
          </KnowledgeSection>

          <KnowledgeSection title="Crashes" count={data.crashes.length} icon={<Bug size={14} />}>
            {data.crashes.slice(0, 40).map((c, i) => (
              <Row key={i} left={c.kind} mid={c.summary.length > 80 ? c.summary.slice(0, 80) + "…" : c.summary} right={c.signature ? c.signature.slice(0, 12) : ""} danger />
            ))}
          </KnowledgeSection>
        </>
      )}
    </div>
  );
}

function KnowledgeSection({ title, count, icon, children }: { title: string; count: number; icon: ReactNode; children: ReactNode }) {
  if (count === 0) return null;
  return (
    <div className="surface-card overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border">
        <span style={{ color: "var(--accent)" }}>{icon}</span>
        <span className="text-sm font-medium">{title}</span>
        <span className="text-xs text-text-muted">{count}</span>
      </div>
      <div className="flex flex-col">{children}</div>
    </div>
  );
}

function Row({ left, mid, right, danger }: { left: string; mid: string; right: string; danger?: boolean }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2 border-b border-border last:border-0 text-xs">
      <span className="font-mono shrink-0" style={{ color: danger ? "var(--error)" : "var(--text-primary)", minWidth: "120px" }}>{left}</span>
      <span className="text-text-secondary flex-1 truncate">{mid}</span>
      <span className="text-text-muted font-mono shrink-0 truncate" style={{ maxWidth: "240px" }}>{right}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Automation
// ---------------------------------------------------------------------------

interface Campaign {
  id: string;
  name: string;
  project: string;
  target: string;
  engine: string;
  duration: number;
}

const CAMPAIGNS_KEY = "hf_campaigns";

function loadCampaigns(): Campaign[] {
  try {
    return JSON.parse(localStorage.getItem(CAMPAIGNS_KEY) ?? "[]");
  } catch {
    return [];
  }
}

export function AutomationView() {
  const { activeProject } = useProject();
  const { target, engine } = useTarget();
  const { sandboxArch } = usePrefs();
  const [campaigns, setCampaigns] = useState<Campaign[]>(loadCampaigns);
  const [runningOnce, setRunningOnce] = useState<string | null>(null);
  const [activeIds, setActiveIds] = useState<string[]>([]);
  const activeRef = useRef<Set<string>>(new Set());

  // Stop any continuous loops when leaving the view.
  useEffect(() => () => activeRef.current.clear(), []);

  const persist = (next: Campaign[]) => {
    setCampaigns(next);
    localStorage.setItem(CAMPAIGNS_KEY, JSON.stringify(next));
  };

  const canSave = activeProject && target;
  function saveCurrent() {
    if (!canSave) return;
    const c: Campaign = {
      id: `${Date.now()}`,
      name: `${shortProject(activeProject)} / ${target}`,
      project: activeProject,
      target,
      engine: engine || "libfuzzer",
      duration: 60,
    };
    persist([c, ...campaigns]);
  }
  function remove(id: string) {
    activeRef.current.delete(id);
    setActiveIds([...activeRef.current]);
    persist(campaigns.filter((c) => c.id !== id));
  }

  const runOne = (c: Campaign) =>
    getTransport().invoke("run_fuzzer", {
      project: c.project,
      target: c.target,
      engine: c.engine,
      duration: c.duration,
      arch: sandboxArch,
    });

  async function runOnce(c: Campaign) {
    setRunningOnce(c.id);
    try {
      await runOne(c);
    } catch {
      /* surfaced in Run view */
    } finally {
      setRunningOnce(null);
    }
  }

  async function loop(c: Campaign) {
    while (activeRef.current.has(c.id)) {
      try {
        await runOne(c);
      } catch {
        /* keep going */
      }
      if (!activeRef.current.has(c.id)) break;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  function toggleContinuous(c: Campaign) {
    if (activeRef.current.has(c.id)) {
      activeRef.current.delete(c.id);
    } else {
      activeRef.current.add(c.id);
      void loop(c);
    }
    setActiveIds([...activeRef.current]);
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <ViewHeader title="Automation" description="Save fuzz campaigns and re-run them — one-shot or continuously (re-runs while this view is open, growing the corpus each pass)." />
        <button
          onClick={saveCurrent}
          disabled={!canSave}
          title={canSave ? "Save the current project + target as a campaign" : "Pick a project and target first (Discover/Harness)"}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md disabled:opacity-50"
          style={{ background: "var(--accent)", color: "var(--accent-contrast)", border: "none" }}
        >
          <Plus size={13} />
          Save current
        </button>
      </div>

      {campaigns.length === 0 && (
        <EmptyState icon={<Zap size={20} />} hint="No saved campaigns. Pick a project + target (Discover/Harness), then 'Save current' to create a repeatable fuzz campaign." />
      )}

      <div className="flex flex-col gap-2">
        {campaigns.map((c) => {
          const continuous = activeIds.includes(c.id);
          return (
            <div key={c.id} className="surface-card flex items-center gap-3" style={{ padding: "var(--space-md)", borderLeft: continuous ? "3px solid var(--accent)" : "3px solid transparent" }}>
              <div className="flex flex-col min-w-0 flex-1">
                <span className="text-sm font-medium truncate">{c.name}</span>
                <span className="text-xs text-text-muted font-mono">{c.engine} · {c.duration}s{continuous ? " · running…" : ""}</span>
              </div>
              <button
                onClick={() => runOnce(c)}
                disabled={runningOnce === c.id || continuous}
                className="inline-flex items-center gap-1 px-3 py-1.5 text-xs rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary disabled:opacity-50"
              >
                {runningOnce === c.id ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
                Run
              </button>
              <button
                onClick={() => toggleContinuous(c)}
                className="inline-flex items-center gap-1 px-3 py-1.5 text-xs rounded-md border"
                style={continuous ? { background: "var(--accent)", color: "var(--accent-contrast)", borderColor: "transparent" } : { borderColor: "var(--border)", background: "var(--surface-primary)", color: "var(--text-secondary)" }}
                title="Continuously re-run while this view is open"
              >
                {continuous ? <Square size={13} /> : <RotateCw size={13} />}
                {continuous ? "Stop" : "Continuous"}
              </button>
              <button onClick={() => remove(c.id)} className="inline-flex items-center justify-center p-1.5 rounded-md text-text-muted hover:text-error hover:bg-surface-hover" title="Delete campaign">
                <Trash2 size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
