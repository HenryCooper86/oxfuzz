import { useEffect, useRef, useState, type ReactNode } from "react";
import { Puzzle, BookOpen, Zap, Target, FileCode, Activity, Bug, Crosshair, Play, Loader2, Plus, Trash2, RotateCw, Square, Bot, Shield, Database, Pencil, Save, X } from "lucide-react";
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

interface AgentInfo {
  model: string;
  provider_type: string;
  guardrails: string;
  tools: { name: string; description: string }[];
}

const TOOL_ICONS: Record<string, ReactNode> = {
  discover: <Crosshair size={16} />,
  harness: <FileCode size={16} />,
  run: <Play size={16} />,
  triage: <Bug size={16} />,
  corpus: <Database size={16} />,
};

// -- shared form primitives -------------------------------------------------

const INPUT_CLS =
  "w-full px-2.5 py-1.5 text-sm rounded-md border border-border bg-surface-primary text-text-primary outline-none font-mono";

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs text-text-muted">
        {label}
        {hint && <span className="text-text-muted opacity-70"> — {hint}</span>}
      </span>
      {children}
    </label>
  );
}

function PrimaryBtn({ onClick, disabled, icon, children }: { onClick: () => void; disabled?: boolean; icon: ReactNode; children: ReactNode }) {
  return (
    <button onClick={onClick} disabled={disabled} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md disabled:opacity-50" style={{ background: "var(--accent)", color: "var(--accent-contrast)", border: "none" }}>
      {icon}
      {children}
    </button>
  );
}
function GhostBtn({ onClick, icon, children, title }: { onClick: () => void; icon: ReactNode; children?: ReactNode; title?: string }) {
  return (
    <button onClick={onClick} title={title} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary">
      {icon}
      {children}
    </button>
  );
}
function IconBtn({ onClick, icon, danger, title }: { onClick: () => void; icon: ReactNode; danger?: boolean; title?: string }) {
  return (
    <button onClick={onClick} title={title} className={`inline-flex items-center justify-center p-1.5 rounded-md text-text-muted hover:bg-surface-hover ${danger ? "hover:text-error" : "hover:text-text-primary"}`}>
      {icon}
    </button>
  );
}
function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="text-xs rounded-md px-3 py-2" style={{ background: "var(--error-subtle, rgba(220,60,60,0.12))", color: "var(--error)", border: "1px solid var(--error)" }}>
      {message}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Agents (runtime agent + editable profiles)
// ---------------------------------------------------------------------------

interface AgentProfile {
  id: string;
  model_tags: string[];
  autonomy: string;
  max_iterations: number;
  tools: string[];
}
interface AgentDraft {
  id: string;
  model_tags: string;
  autonomy: string;
  max_iterations: number;
  tools: string;
  isNew: boolean;
}

const AUTONOMY_LEVELS = ["Manual", "Assist", "Auto"];
const AGENT_TOOL_OPTIONS = ["ProjectScan", "FileRead", "KnowledgeSearch", "ShellExec", "HarnessWrite", "CorpusManage"];

export function AgentsView() {
  const [info, setInfo] = useState<AgentInfo | null>(null);
  const [profiles, setProfiles] = useState<AgentProfile[]>([]);
  const [draft, setDraft] = useState<AgentDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = () => getTransport().invoke<AgentProfile[]>("list_agents").then(setProfiles).catch(() => {});
  useEffect(() => {
    let cancelled = false;
    getTransport().invoke<AgentInfo>("agent_info").then((d) => !cancelled && setInfo(d)).catch(() => {});
    getTransport().invoke<AgentProfile[]>("list_agents").then((d) => !cancelled && setProfiles(d)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  function startNew() {
    setError(null);
    setDraft({ id: "", model_tags: "reasoning, code", autonomy: "Assist", max_iterations: 5, tools: "ProjectScan, FileRead", isNew: true });
  }
  function startEdit(p: AgentProfile) {
    setError(null);
    setDraft({ id: p.id, model_tags: p.model_tags.join(", "), autonomy: p.autonomy, max_iterations: p.max_iterations, tools: p.tools.join(", "), isNew: false });
  }
  const splitList = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

  async function save() {
    if (!draft) return;
    const id = draft.id.trim();
    if (!id) {
      setError("Agent id is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await getTransport().invoke("save_agent", {
        id,
        modelTags: splitList(draft.model_tags),
        autonomy: draft.autonomy,
        maxIterations: draft.max_iterations,
        tools: splitList(draft.tools),
      });
      setDraft(null);
      reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function del(id: string) {
    if (!window.confirm(`Delete agent profile "${id}"?`)) return;
    try {
      await getTransport().invoke("delete_agent", { id });
      reload();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Agents" description="The autonomous fuzzing agent (model, policy, tools) and editable sub-agent profiles." />

      {info && (
        <>
          <div className="grid grid-cols-3 gap-3">
            <Tile icon={<Bot size={16} />} label="Model" value={info.model} />
            <Tile icon={<Activity size={16} />} label="Provider" value={info.provider_type || "—"} />
            <Tile icon={<Shield size={16} />} label="Guardrails" value={info.guardrails} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            {info.tools.map((t) => (
              <Card key={t.name} icon={TOOL_ICONS[t.name] ?? <Target size={16} />} title={t.name} subtitle={t.description} />
            ))}
          </div>
        </>
      )}

      <div className="flex items-center justify-between mt-2">
        <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.08em" }}>
          Agent Profiles ({profiles.length})
        </span>
        {!draft && <PrimaryBtn onClick={startNew} icon={<Plus size={13} />}>New profile</PrimaryBtn>}
      </div>

      {error && !draft && <ErrorBanner message={error} />}

      {draft ? (
        <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
          {error && <ErrorBanner message={error} />}
          <Field label="Agent id" hint="letters, digits, -, _">
            <input className={INPUT_CLS} value={draft.id} disabled={!draft.isNew} placeholder="my-agent" onChange={(e) => setDraft({ ...draft, id: e.target.value })} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Model tags" hint="comma-separated">
              <input className={INPUT_CLS} value={draft.model_tags} placeholder="reasoning, code" onChange={(e) => setDraft({ ...draft, model_tags: e.target.value })} />
            </Field>
            <Field label="Autonomy">
              <select className={INPUT_CLS} value={draft.autonomy} onChange={(e) => setDraft({ ...draft, autonomy: e.target.value })}>
                {AUTONOMY_LEVELS.map((a) => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </select>
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Max iterations">
              <input type="number" min={1} max={50} className={INPUT_CLS} value={draft.max_iterations} onChange={(e) => setDraft({ ...draft, max_iterations: Number(e.target.value) || 1 })} />
            </Field>
            <Field label="Tools" hint="comma-separated">
              <input className={INPUT_CLS} value={draft.tools} placeholder={AGENT_TOOL_OPTIONS.slice(0, 3).join(", ")} onChange={(e) => setDraft({ ...draft, tools: e.target.value })} />
            </Field>
          </div>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => { setDraft(null); setError(null); }} icon={<X size={13} />}>Cancel</GhostBtn>
            <PrimaryBtn onClick={save} disabled={busy} icon={busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}>Save</PrimaryBtn>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {profiles.map((p) => (
            <div key={p.id} className="surface-card flex items-center gap-3" style={{ padding: "var(--space-md)" }}>
              <div className="flex items-center justify-center shrink-0 rounded-md" style={{ width: "34px", height: "34px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}>
                <span style={{ color: "var(--accent)" }}><Bot size={16} /></span>
              </div>
              <div className="flex flex-col min-w-0 flex-1">
                <span className="text-sm font-medium">{p.id}</span>
                <span className="text-xs text-text-muted font-mono">
                  {p.autonomy} · {p.max_iterations} iters · tags [{p.model_tags.join(", ")}] · tools [{p.tools.join(", ")}]
                </span>
              </div>
              <IconBtn onClick={() => startEdit(p)} icon={<Pencil size={14} />} title="Edit" />
              <IconBtn onClick={() => del(p.id)} icon={<Trash2 size={14} />} danger title="Delete" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Tile({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="surface-card flex flex-col gap-1" style={{ padding: "var(--space-md)" }}>
      <span className="flex items-center gap-1.5 text-xs text-text-muted">
        <span style={{ color: "var(--accent)" }}>{icon}</span>
        {label}
      </span>
      <span className="text-sm font-medium font-mono truncate" title={value}>{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skills (editable)
// ---------------------------------------------------------------------------

interface SkillInfo {
  name: string;
  description: string;
  version: string;
  domain: string[];
}
interface SkillDraft {
  name: string;
  description: string;
  version: string;
  domain: string;
  content: string;
  isNew: boolean;
}

export function SkillsView() {
  const [skills, setSkills] = useState<SkillInfo[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [draft, setDraft] = useState<SkillDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = () => getTransport().invoke<SkillInfo[]>("list_skills").then(setSkills).catch(() => {});
  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<SkillInfo[]>("list_skills")
      .then((s) => {
        if (!cancelled) {
          setSkills(s);
          setLoaded(true);
        }
      })
      .catch(() => !cancelled && setLoaded(true));
    return () => {
      cancelled = true;
    };
  }, []);

  function startNew() {
    setError(null);
    setDraft({ name: "", description: "", version: "0.1.0", domain: "fuzzing", content: "# new-skill\n\nDescribe when to use this skill and the procedure to follow.\n", isNew: true });
  }
  async function startEdit(name: string) {
    setError(null);
    try {
      const d = await getTransport().invoke<SkillDraft & { domain: string[] }>("read_skill", { name });
      setDraft({ name: d.name, description: d.description, version: d.version, domain: (d.domain as unknown as string[]).join(", "), content: d.content, isNew: false });
    } catch (e) {
      setError(String(e));
    }
  }
  async function save() {
    if (!draft) return;
    const name = draft.name.trim();
    if (!name) {
      setError("Skill name is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await getTransport().invoke("save_skill", {
        name,
        description: draft.description,
        version: draft.version,
        domain: draft.domain.split(",").map((x) => x.trim()).filter(Boolean),
        content: draft.content,
      });
      setDraft(null);
      reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function del(name: string) {
    if (!window.confirm(`Delete skill "${name}"? This removes skills/${name}/.`)) return;
    try {
      await getTransport().invoke("delete_skill", { name });
      reload();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <ViewHeader title="Skills" description="Reusable, file-backed skills the agent applies across runs (skills/ registry) — add, edit, or remove them." />
        {!draft && <PrimaryBtn onClick={startNew} icon={<Plus size={13} />}>New skill</PrimaryBtn>}
      </div>

      {error && !draft && <ErrorBanner message={error} />}

      {draft ? (
        <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
          {error && <ErrorBanner message={error} />}
          <div className="grid grid-cols-2 gap-3">
            <Field label="Name" hint="letters, digits, -, _">
              <input className={INPUT_CLS} value={draft.name} disabled={!draft.isNew} placeholder="my-skill" onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </Field>
            <Field label="Version">
              <input className={INPUT_CLS} value={draft.version} placeholder="0.1.0" onChange={(e) => setDraft({ ...draft, version: e.target.value })} />
            </Field>
          </div>
          <Field label="Description">
            <input className={INPUT_CLS} value={draft.description} placeholder="What this skill does" onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
          </Field>
          <Field label="Domain" hint="comma-separated tags">
            <input className={INPUT_CLS} value={draft.domain} placeholder="fuzzing, harness-generation" onChange={(e) => setDraft({ ...draft, domain: e.target.value })} />
          </Field>
          <Field label="Content (root.md)">
            <textarea className={`${INPUT_CLS} resize-y`} rows={12} value={draft.content} onChange={(e) => setDraft({ ...draft, content: e.target.value })} />
          </Field>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => { setDraft(null); setError(null); }} icon={<X size={13} />}>Cancel</GhostBtn>
            <PrimaryBtn onClick={save} disabled={busy} icon={busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}>Save</PrimaryBtn>
          </div>
        </div>
      ) : (
        <>
          {loaded && skills.length === 0 && (
            <EmptyState icon={<Puzzle size={20} />} hint="No skills yet. Click 'New skill' to author one — it's written to skills/<name>/." />
          )}
          <div className="flex flex-col gap-2">
            {skills.map((s) => (
              <div key={s.name} className="surface-card flex items-start gap-3" style={{ padding: "var(--space-md)" }}>
                <div className="flex items-center justify-center shrink-0 rounded-md" style={{ width: "34px", height: "34px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}>
                  <span style={{ color: "var(--accent)" }}><Puzzle size={16} /></span>
                </div>
                <div className="flex flex-col min-w-0 flex-1">
                  <span className="text-sm font-medium flex items-center gap-2">
                    {s.name}
                    <span className="text-xs text-text-muted font-mono">v{s.version}</span>
                  </span>
                  <span className="text-xs text-text-secondary mt-0.5">{s.description}</span>
                  {s.domain.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {s.domain.map((d) => (
                        <span key={d} className="text-xs px-1.5 py-0.5 rounded-sm" style={{ background: "var(--surface-active)", color: "var(--text-muted)" }}>
                          {d}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <IconBtn onClick={() => startEdit(s.name)} icon={<Pencil size={14} />} title="Edit" />
                <IconBtn onClick={() => del(s.name)} icon={<Trash2 size={14} />} danger title="Delete" />
              </div>
            ))}
          </div>
        </>
      )}
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
