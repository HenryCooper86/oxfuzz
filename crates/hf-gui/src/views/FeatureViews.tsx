import { useEffect, useRef, useState, type ReactNode } from "react";
import { Puzzle, BookOpen, Zap, Target, FileCode, Activity, Bug, Crosshair, Play, Loader2, Plus, Trash2, RotateCw, RotateCcw, Copy, Square, Bot, Shield, Database, Pencil, Save, X } from "lucide-react";
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
// Agents (real AgentDefinitions that drive the runtime)
// ---------------------------------------------------------------------------

type AgentRole = "orchestrator" | "discovery" | "harness-author" | "run-operator" | "triage" | "coverage" | "corpus";
type Autonomy = "manual" | "assist" | "auto";
type TrustTier = "built-in" | "user-defined";

interface AgentDefinition {
  id: string;
  name: string;
  description: string;
  role: AgentRole;
  icon: string | null;
  system_prompt: string;
  allowed_tools: string[];
  model_tags: string[];
  temperature: number | null;
  max_iterations: number;
  autonomy: Autonomy;
  capabilities: string[];
  user_callable: boolean;
  skills: string[];
  trust_tier: TrustTier;
}

// Editable form state. Numeric/array fields are kept as strings while editing.
interface AgentDraft {
  id: string;
  name: string;
  description: string;
  role: AgentRole;
  system_prompt: string;
  allowed_tools: string[];
  model_tags: string; // comma-separated while editing
  temperature: string; // empty -> null
  max_iterations: number;
  autonomy: Autonomy;
  capabilities: string[];
  user_callable: boolean;
  skills: string[];
  icon: string | null;
  isNew: boolean;
}

const ROLES: AgentRole[] = ["orchestrator", "discovery", "harness-author", "run-operator", "triage", "coverage", "corpus"];
const AUTONOMY_LEVELS: Autonomy[] = ["manual", "assist", "auto"];

const ROLE_ICONS: Record<AgentRole, ReactNode> = {
  orchestrator: <Bot size={16} />,
  discovery: <Crosshair size={16} />,
  "harness-author": <FileCode size={16} />,
  "run-operator": <Play size={16} />,
  triage: <Bug size={16} />,
  coverage: <Activity size={16} />,
  corpus: <Database size={16} />,
};

const splitList = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

// kebab-case slug from a name: ascii alnum, '-' and '_' only.
function slugify(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-_]+|[-_]+$/g, "");
}

const isSafeSlug = (s: string) => /^[a-z0-9][a-z0-9_-]*$/.test(s);

function emptyDraft(): AgentDraft {
  return {
    id: "",
    name: "",
    description: "",
    role: "orchestrator",
    system_prompt: "",
    allowed_tools: [],
    model_tags: "",
    temperature: "",
    max_iterations: 12,
    autonomy: "assist",
    capabilities: [],
    user_callable: true,
    skills: [],
    icon: null,
    isNew: true,
  };
}

function draftFrom(a: AgentDefinition, opts: { duplicate?: boolean } = {}): AgentDraft {
  const dup = !!opts.duplicate;
  return {
    id: dup ? slugify(`${a.id}-copy`) : a.id,
    name: dup ? `${a.name} (copy)` : a.name,
    description: a.description,
    role: a.role,
    system_prompt: a.system_prompt,
    allowed_tools: [...a.allowed_tools],
    model_tags: a.model_tags.join(", "),
    temperature: a.temperature == null ? "" : String(a.temperature),
    max_iterations: a.max_iterations,
    autonomy: a.autonomy,
    capabilities: [...a.capabilities],
    user_callable: a.user_callable,
    skills: [...a.skills],
    icon: a.icon,
    isNew: dup,
  };
}

export function AgentsView() {
  const [info, setInfo] = useState<AgentInfo | null>(null);
  const [agents, setAgents] = useState<AgentDefinition[]>([]);
  const [tools, setTools] = useState<{ name: string; description: string }[]>([]);
  const [skills, setSkills] = useState<SkillDefinition[]>([]);
  const [draft, setDraft] = useState<AgentDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = () => getTransport().invoke<AgentDefinition[]>("list_agents").then(setAgents).catch(() => {});
  useEffect(() => {
    let cancelled = false;
    getTransport().invoke<AgentInfo>("agent_info").then((d) => !cancelled && setInfo(d)).catch(() => {});
    getTransport().invoke<AgentDefinition[]>("list_agents").then((d) => !cancelled && setAgents(d)).catch(() => {});
    getTransport().invoke<{ name: string; description: string }[]>("agent_tools").then((d) => !cancelled && setTools(d)).catch(() => {});
    getTransport().invoke<SkillDefinition[]>("list_skills").then((d) => !cancelled && setSkills(d)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  function startNew() {
    setError(null);
    setDraft(emptyDraft());
  }
  function startEdit(a: AgentDefinition) {
    setError(null);
    setDraft(draftFrom(a));
  }
  function startDuplicate(a: AgentDefinition) {
    setError(null);
    setDraft(draftFrom(a, { duplicate: true }));
  }

  function setField<K extends keyof AgentDraft>(key: K, value: AgentDraft[K]) {
    setDraft((d) => (d ? { ...d, [key]: value } : d));
  }
  function toggleTool(name: string) {
    setDraft((d) => {
      if (!d) return d;
      const has = d.allowed_tools.includes(name);
      return { ...d, allowed_tools: has ? d.allowed_tools.filter((t) => t !== name) : [...d.allowed_tools, name] };
    });
  }
  function toggleSkill(name: string) {
    setDraft((d) => {
      if (!d) return d;
      const has = d.skills.includes(name);
      return { ...d, skills: has ? d.skills.filter((s) => s !== name) : [...d.skills, name] };
    });
  }

  async function save() {
    if (!draft) return;
    const name = draft.name.trim();
    const id = draft.isNew ? slugify(draft.id.trim() || name) : draft.id;
    if (!name) {
      setError("Name is required.");
      return;
    }
    if (!draft.system_prompt.trim()) {
      setError("System prompt is required.");
      return;
    }
    if (!isSafeSlug(id)) {
      setError("Id must be a safe slug (lowercase letters, digits, '-' or '_').");
      return;
    }
    let temperature: number | null = null;
    if (draft.temperature.trim() !== "") {
      const t = Number(draft.temperature);
      if (Number.isNaN(t)) {
        setError("Temperature must be a number or empty.");
        return;
      }
      temperature = t;
    }
    const def = {
      id,
      name,
      description: draft.description.trim(),
      role: draft.role,
      icon: draft.icon,
      system_prompt: draft.system_prompt,
      allowed_tools: draft.allowed_tools,
      model_tags: splitList(draft.model_tags),
      temperature,
      max_iterations: Math.max(1, Math.min(50, draft.max_iterations || 1)),
      autonomy: draft.autonomy,
      capabilities: draft.capabilities,
      user_callable: draft.user_callable,
      skills: draft.skills,
    };
    setBusy(true);
    setError(null);
    try {
      await getTransport().invoke("save_agent", { def });
      setDraft(null);
      reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function del(a: AgentDefinition) {
    const builtIn = a.trust_tier === "built-in";
    const prompt = builtIn
      ? `Reset built-in agent "${a.name}" to its shipped version?`
      : `Delete agent "${a.name}"?`;
    if (!window.confirm(prompt)) return;
    try {
      await getTransport().invoke("delete_agent", { id: a.id });
      reload();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Agents" description="Fuzzing agents that drive the runtime — their role, tools, and system prompt. Built-ins ship with hobot_fuzz; add your own." />

      {info && (
        <div className="grid grid-cols-3 gap-3">
          <Tile icon={<Bot size={16} />} label="Model" value={info.model} />
          <Tile icon={<Activity size={16} />} label="Provider" value={info.provider_type || "—"} />
          <Tile icon={<Shield size={16} />} label="Guardrails" value={info.guardrails} />
        </div>
      )}

      <div className="flex items-center justify-between mt-1">
        <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.08em" }}>
          Agents ({agents.length})
        </span>
        {!draft && <PrimaryBtn onClick={startNew} icon={<Plus size={13} />}>New agent</PrimaryBtn>}
      </div>

      {error && !draft && <ErrorBanner message={error} />}

      {draft ? (
        <AgentEditor
          draft={draft}
          tools={tools}
          skills={skills}
          busy={busy}
          error={error}
          onField={setField}
          onToggleTool={toggleTool}
          onToggleSkill={toggleSkill}
          onCancel={() => { setDraft(null); setError(null); }}
          onSave={save}
        />
      ) : (
        <div className="flex flex-col gap-2">
          {agents.length === 0 && (
            <EmptyState icon={<Bot size={20} />} hint="No agents found. Click 'New agent' to author a fuzzing agent." />
          )}
          {agents.map((a) => (
            <AgentRow key={a.id} agent={a} onEdit={() => startEdit(a)} onDuplicate={() => startDuplicate(a)} onDelete={() => del(a)} />
          ))}
        </div>
      )}
    </div>
  );
}

function AgentRow({ agent, onEdit, onDuplicate, onDelete }: { agent: AgentDefinition; onEdit: () => void; onDuplicate: () => void; onDelete: () => void }) {
  const builtIn = agent.trust_tier === "built-in";
  return (
    <div className="surface-card flex items-start gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-center shrink-0 rounded-md" style={{ width: "34px", height: "34px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}>
        <span style={{ color: "var(--accent)" }}>{ROLE_ICONS[agent.role] ?? <Bot size={16} />}</span>
      </div>
      <div className="flex flex-col min-w-0 flex-1">
        <span className="text-sm font-medium flex items-center gap-2">
          {agent.name}
          <span className="text-xs px-1.5 py-0.5 rounded-sm" style={builtIn ? { background: "var(--accent-subtle)", color: "var(--accent)" } : { background: "var(--surface-active)", color: "var(--text-muted)" }}>
            {builtIn ? "Built-in" : "Custom"}
          </span>
        </span>
        <span className="text-xs text-text-secondary mt-0.5">{agent.description}</span>
        <span className="text-xs text-text-muted font-mono mt-1">
          {agent.role} · {agent.autonomy} · {agent.allowed_tools.length ? agent.allowed_tools.join(", ") : "no tools"}
          {agent.skills.length > 0 && ` · ${agent.skills.length} skill${agent.skills.length === 1 ? "" : "s"}`}
        </span>
      </div>
      <div className="flex items-center shrink-0">
        <IconBtn onClick={onEdit} icon={<Pencil size={14} />} title="Edit" />
        <IconBtn onClick={onDuplicate} icon={<Copy size={14} />} title="Duplicate into a new agent" />
        {builtIn ? (
          <IconBtn onClick={onDelete} icon={<RotateCcw size={14} />} title="Reset to shipped version" />
        ) : (
          <IconBtn onClick={onDelete} icon={<Trash2 size={14} />} danger title="Delete" />
        )}
      </div>
    </div>
  );
}

function AgentEditor({
  draft,
  tools,
  skills,
  busy,
  error,
  onField,
  onToggleTool,
  onToggleSkill,
  onCancel,
  onSave,
}: {
  draft: AgentDraft;
  tools: { name: string; description: string }[];
  skills: SkillDefinition[];
  busy: boolean;
  error: string | null;
  onField: <K extends keyof AgentDraft>(key: K, value: AgentDraft[K]) => void;
  onToggleTool: (name: string) => void;
  onToggleSkill: (name: string) => void;
  onCancel: () => void;
  onSave: () => void;
}) {
  // For a new agent, the id auto-derives from the name unless the user edits it.
  const derivedId = draft.isNew ? slugify(draft.id.trim() || draft.name) : draft.id;
  return (
    <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      {error && <ErrorBanner message={error} />}
      <div className="grid grid-cols-2 gap-3">
        <Field label="Name">
          <input
            className={INPUT_CLS}
            value={draft.name}
            placeholder="Discovery Scout"
            onChange={(e) => {
              const name = e.target.value;
              onField("name", name);
            }}
          />
        </Field>
        <Field label="Id" hint={draft.isNew ? "auto from name; editable" : "locked"}>
          <input
            className={INPUT_CLS}
            value={derivedId}
            disabled={!draft.isNew}
            placeholder="discovery-scout"
            onChange={(e) => onField("id", e.target.value)}
          />
        </Field>
      </div>

      <Field label="Description">
        <input className={INPUT_CLS} value={draft.description} placeholder="What this agent does" onChange={(e) => onField("description", e.target.value)} />
      </Field>

      <div className="grid grid-cols-2 gap-3">
        <Field label="Role">
          <select className={INPUT_CLS} value={draft.role} onChange={(e) => onField("role", e.target.value as AgentRole)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </Field>
        <Field label="Autonomy">
          <select className={INPUT_CLS} value={draft.autonomy} onChange={(e) => onField("autonomy", e.target.value as Autonomy)}>
            {AUTONOMY_LEVELS.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </Field>
      </div>

      <Field label="System prompt" hint="the agent's instructions">
        <textarea
          className={`${INPUT_CLS} resize-y`}
          rows={14}
          value={draft.system_prompt}
          placeholder="You are a fuzzing agent. Your job is to…"
          onChange={(e) => onField("system_prompt", e.target.value)}
        />
      </Field>

      <Field label="Allowed tools" hint="what this agent may call">
        {tools.length === 0 ? (
          <span className="text-xs text-text-muted">No tools available.</span>
        ) : (
          <div className="grid grid-cols-2 gap-1.5">
            {tools.map((t) => {
              const checked = draft.allowed_tools.includes(t.name);
              return (
                <label
                  key={t.name}
                  className="flex items-start gap-2 rounded-md px-2 py-1.5 cursor-pointer border"
                  style={{ borderColor: checked ? "var(--accent)" : "var(--border)", background: checked ? "var(--accent-subtle)" : "var(--surface-primary)" }}
                  title={t.description}
                >
                  <input type="checkbox" checked={checked} onChange={() => onToggleTool(t.name)} className="mt-0.5" />
                  <span className="flex items-center gap-1.5 min-w-0">
                    <span style={{ color: "var(--accent)" }}>{TOOL_ICONS[t.name] ?? <Target size={14} />}</span>
                    <span className="flex flex-col min-w-0">
                      <span className="text-xs font-medium">{t.name}</span>
                      <span className="text-xs text-text-muted truncate">{t.description}</span>
                    </span>
                  </span>
                </label>
              );
            })}
          </div>
        )}
      </Field>

      <Field label="Skills" hint="playbooks injected when the agent references them">
        {skills.length === 0 ? (
          <span className="text-xs text-text-muted">No skills available.</span>
        ) : (
          <div className="grid grid-cols-2 gap-1.5">
            {skills.map((s) => {
              const checked = draft.skills.includes(s.name);
              return (
                <label
                  key={s.name}
                  className="flex items-start gap-2 rounded-md px-2 py-1.5 cursor-pointer border"
                  style={{ borderColor: checked ? "var(--accent)" : "var(--border)", background: checked ? "var(--accent-subtle)" : "var(--surface-primary)" }}
                  title={s.description}
                >
                  <input type="checkbox" checked={checked} onChange={() => onToggleSkill(s.name)} className="mt-0.5" />
                  <span className="flex items-center gap-1.5 min-w-0">
                    <span style={{ color: "var(--accent)" }}><Puzzle size={14} /></span>
                    <span className="flex flex-col min-w-0">
                      <span className="text-xs font-medium">{s.name}</span>
                      <span className="text-xs text-text-muted truncate">{s.description}</span>
                    </span>
                  </span>
                </label>
              );
            })}
          </div>
        )}
      </Field>

      <div className="grid grid-cols-3 gap-3">
        <Field label="Model tags" hint="comma-separated">
          <input className={INPUT_CLS} value={draft.model_tags} placeholder="reasoning, code" onChange={(e) => onField("model_tags", e.target.value)} />
        </Field>
        <Field label="Temperature" hint="optional">
          <input className={INPUT_CLS} value={draft.temperature} placeholder="(default)" onChange={(e) => onField("temperature", e.target.value)} />
        </Field>
        <Field label="Max iterations" hint="1-50">
          <input type="number" min={1} max={50} className={INPUT_CLS} value={draft.max_iterations} onChange={(e) => onField("max_iterations", Number(e.target.value) || 1)} />
        </Field>
      </div>

      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onCancel} icon={<X size={13} />}>Cancel</GhostBtn>
        <PrimaryBtn onClick={onSave} disabled={busy} icon={busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}>Save</PrimaryBtn>
      </div>
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

interface SkillDefinition {
  name: string;
  version: string;
  description: string;
  domain: string[];
  body: string;
  max_input_tokens: number;
  trust_tier: TrustTier;
}
// Editable form state. The markdown body is bound here and sent as `content` on save.
interface SkillDraft {
  name: string;
  description: string;
  version: string;
  domain: string; // comma-separated while editing
  body: string;
  isNew: boolean; // creating a brand-new user skill (name not yet locked)
}

function skillDraftFrom(s: SkillDefinition, opts: { duplicate?: boolean } = {}): SkillDraft {
  const dup = !!opts.duplicate;
  return {
    name: dup ? slugify(`${s.name}-copy`) : s.name,
    description: s.description,
    version: s.version,
    domain: s.domain.join(", "),
    body: s.body,
    isNew: dup,
  };
}

export function SkillsView() {
  const [skills, setSkills] = useState<SkillDefinition[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [draft, setDraft] = useState<SkillDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = () => getTransport().invoke<SkillDefinition[]>("list_skills").then(setSkills).catch(() => {});
  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<SkillDefinition[]>("list_skills")
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
    setDraft({ name: "", description: "", version: "0.1.0", domain: "fuzzing", body: "# new-skill\n\nDescribe when to use this skill and the procedure to follow.\n", isNew: true });
  }
  async function startEdit(name: string) {
    setError(null);
    try {
      const s = await getTransport().invoke<SkillDefinition | null>("read_skill", { name });
      if (!s) {
        setError(`Skill "${name}" not found.`);
        return;
      }
      setDraft(skillDraftFrom(s));
    } catch (e) {
      setError(String(e));
    }
  }
  function startDuplicate(s: SkillDefinition) {
    setError(null);
    setDraft(skillDraftFrom(s, { duplicate: true }));
  }
  async function save() {
    if (!draft) return;
    const name = draft.isNew ? slugify(draft.name.trim()) : draft.name;
    if (!name) {
      setError("Skill name is required.");
      return;
    }
    if (draft.isNew && !isSafeSlug(name)) {
      setError("Name must be a safe slug (lowercase letters, digits, '-' or '_').");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await getTransport().invoke("save_skill", {
        name,
        description: draft.description,
        version: draft.version,
        domain: splitList(draft.domain),
        content: draft.body,
      });
      setDraft(null);
      reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function del(s: SkillDefinition) {
    const builtIn = s.trust_tier === "built-in";
    const prompt = builtIn
      ? `Reset built-in skill "${s.name}" to its shipped version?`
      : `Delete skill "${s.name}"?`;
    if (!window.confirm(prompt)) return;
    try {
      await getTransport().invoke("delete_skill", { name: s.name });
      reload();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Skills" description="Reusable playbooks injected into an agent's context when the agent references them. Built-ins ship with hobot_fuzz; add your own." />

      <div className="flex items-center justify-between mt-1">
        <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.08em" }}>
          Skills ({skills.length})
        </span>
        {!draft && <PrimaryBtn onClick={startNew} icon={<Plus size={13} />}>New skill</PrimaryBtn>}
      </div>

      {error && !draft && <ErrorBanner message={error} />}

      {draft ? (
        <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
          {error && <ErrorBanner message={error} />}
          <div className="grid grid-cols-2 gap-3">
            <Field label="Name" hint={draft.isNew ? "letters, digits, -, _" : "locked"}>
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
          <Field label="Body (root.md)" hint="the playbook injected into the agent's context">
            <textarea className={`${INPUT_CLS} resize-y`} rows={16} value={draft.body} onChange={(e) => setDraft({ ...draft, body: e.target.value })} />
          </Field>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => { setDraft(null); setError(null); }} icon={<X size={13} />}>Cancel</GhostBtn>
            <PrimaryBtn onClick={save} disabled={busy} icon={busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}>Save</PrimaryBtn>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {loaded && skills.length === 0 && (
            <EmptyState icon={<Puzzle size={20} />} hint="No skills yet. Click 'New skill' to author a reusable playbook." />
          )}
          {skills.map((s) => (
            <SkillRow key={s.name} skill={s} onEdit={() => startEdit(s.name)} onDuplicate={() => startDuplicate(s)} onDelete={() => del(s)} />
          ))}
        </div>
      )}
    </div>
  );
}

function SkillRow({ skill, onEdit, onDuplicate, onDelete }: { skill: SkillDefinition; onEdit: () => void; onDuplicate: () => void; onDelete: () => void }) {
  const builtIn = skill.trust_tier === "built-in";
  return (
    <div className="surface-card flex items-start gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-center shrink-0 rounded-md" style={{ width: "34px", height: "34px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}>
        <span style={{ color: "var(--accent)" }}><Puzzle size={16} /></span>
      </div>
      <div className="flex flex-col min-w-0 flex-1">
        <span className="text-sm font-medium flex items-center gap-2">
          {skill.name}
          <span className="text-xs text-text-muted font-mono">v{skill.version}</span>
          <span className="text-xs px-1.5 py-0.5 rounded-sm" style={builtIn ? { background: "var(--accent-subtle)", color: "var(--accent)" } : { background: "var(--surface-active)", color: "var(--text-muted)" }}>
            {builtIn ? "Built-in" : "Custom"}
          </span>
        </span>
        <span className="text-xs text-text-secondary mt-0.5">{skill.description}</span>
        {skill.domain.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {skill.domain.map((d) => (
              <span key={d} className="text-xs px-1.5 py-0.5 rounded-sm" style={{ background: "var(--surface-active)", color: "var(--text-muted)" }}>
                {d}
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center shrink-0">
        <IconBtn onClick={onEdit} icon={<Pencil size={14} />} title="Edit" />
        <IconBtn onClick={onDuplicate} icon={<Copy size={14} />} title="Duplicate into a new skill" />
        {builtIn ? (
          <IconBtn onClick={onDelete} icon={<RotateCcw size={14} />} title="Reset to shipped version" />
        ) : (
          <IconBtn onClick={onDelete} icon={<Trash2 size={14} />} danger title="Delete" />
        )}
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
