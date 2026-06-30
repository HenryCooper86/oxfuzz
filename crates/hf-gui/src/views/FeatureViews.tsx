import { useEffect, useState, type ReactNode } from "react";
import { Button, EmptyState, Input, LoadingState, Select, Textarea, ViewHeader } from "../components/ui";
import { Puzzle, BookOpen, Zap, Target, FileCode, Activity, Bug, Crosshair, Play, Loader2, Plus, Trash2, RotateCw, RotateCcw, Copy, Square, Bot, Shield, Database, Pencil, Save, X, Search, FilePlus } from "lucide-react";
import { getTransport, pickFile } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useTarget } from "../providers/TargetContext";

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

// Thin wrappers over the shared ui/Button so the library views' actions share
// one consistent button look, spacing, and hover/disabled/focus behavior.
function PrimaryBtn({ onClick, disabled, icon, children }: { onClick: () => void; disabled?: boolean; icon: ReactNode; children: ReactNode }) {
  return (
    <Button variant="primary" size="sm" onClick={onClick} disabled={disabled}>
      {icon}
      {children}
    </Button>
  );
}
function GhostBtn({ onClick, icon, children, title }: { onClick: () => void; icon: ReactNode; children?: ReactNode; title?: string }) {
  return (
    <Button variant="outline" size="sm" onClick={onClick} title={title}>
      {icon}
      {children}
    </Button>
  );
}
function IconBtn({ onClick, icon, danger, title }: { onClick: () => void; icon: ReactNode; danger?: boolean; title?: string }) {
  return (
    <button onClick={onClick} title={title} aria-label={title} className={`hf-action-btn${danger ? " danger" : ""}`}>
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
          <Input
            mono
            value={draft.name}
            placeholder="Discovery Scout"
            onChange={(e) => {
              const name = e.target.value;
              onField("name", name);
            }}
          />
        </Field>
        <Field label="Id" hint={draft.isNew ? "auto from name; editable" : "locked"}>
          <Input
            mono
            value={derivedId}
            disabled={!draft.isNew}
            placeholder="discovery-scout"
            onChange={(e) => onField("id", e.target.value)}
          />
        </Field>
      </div>

      <Field label="Description">
        <Input mono value={draft.description} placeholder="What this agent does" onChange={(e) => onField("description", e.target.value)} />
      </Field>

      <div className="grid grid-cols-2 gap-3">
        <Field label="Role">
          <Select
            mono
            className="w-full"
            value={draft.role}
            onChange={(v) => onField("role", v as AgentRole)}
            options={ROLES.map((r) => ({ value: r, label: r }))}
          />
        </Field>
        <Field label="Autonomy">
          <Select
            mono
            className="w-full"
            value={draft.autonomy}
            onChange={(v) => onField("autonomy", v as Autonomy)}
            options={AUTONOMY_LEVELS.map((a) => ({ value: a, label: a }))}
          />
        </Field>
      </div>

      <Field label="System prompt" hint="the agent's instructions">
        <Textarea
          mono
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
          <Input mono value={draft.model_tags} placeholder="reasoning, code" onChange={(e) => onField("model_tags", e.target.value)} />
        </Field>
        <Field label="Temperature" hint="optional">
          <Input mono value={draft.temperature} placeholder="(default)" onChange={(e) => onField("temperature", e.target.value)} />
        </Field>
        <Field label="Max iterations" hint="1-50">
          <Input mono type="number" min={1} max={50} value={draft.max_iterations} onChange={(e) => onField("max_iterations", Number(e.target.value) || 1)} />
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
              <Input mono value={draft.name} disabled={!draft.isNew} placeholder="my-skill" onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </Field>
            <Field label="Version">
              <Input mono value={draft.version} placeholder="0.1.0" onChange={(e) => setDraft({ ...draft, version: e.target.value })} />
            </Field>
          </div>
          <Field label="Description">
            <Input mono value={draft.description} placeholder="What this skill does" onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
          </Field>
          <Field label="Domain" hint="comma-separated tags">
            <Input mono value={draft.domain} placeholder="fuzzing, harness-generation" onChange={(e) => setDraft({ ...draft, domain: e.target.value })} />
          </Field>
          <Field label="Body (root.md)" hint="the playbook injected into the agent's context">
            <Textarea mono rows={16} value={draft.body} onChange={(e) => setDraft({ ...draft, body: e.target.value })} />
          </Field>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => { setDraft(null); setError(null); }} icon={<X size={13} />}>Cancel</GhostBtn>
            <PrimaryBtn onClick={save} disabled={busy} icon={busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}>Save</PrimaryBtn>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {!loaded && <LoadingState label="Loading skills…" />}
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
  severity?: string | null;
}
interface KnowledgeSummary {
  db_configured: boolean;
  targets: KnowledgeTarget[];
  runs: KnowledgeRun[];
  crashes: KnowledgeCrash[];
}

const shortProject = (p: string) => p.split("/").filter(Boolean).pop() || p;

interface KnowledgeHit {
  file: string;
  score: number;
  snippet: string;
}
interface KnowledgeStats {
  files: number;
  chunks: number;
}

// BM25 search over the active project's source, backed by hf-knowledge.
function KnowledgeBaseSearch() {
  const { activeProject } = useProject();
  const [stats, setStats] = useState<KnowledgeStats | null>(null);
  const [indexing, setIndexing] = useState(false);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<KnowledgeHit[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [ingesting, setIngesting] = useState(false);

  // Convert a document (PDF/Office/HTML/...) to Markdown via markitdown in the
  // sandbox and add it to this project's knowledge base.
  async function ingest() {
    if (!activeProject || ingesting) return;
    const file = await pickFile("Select a document to ingest (PDF, Office, HTML, ...)");
    if (!file) return;
    setIngesting(true);
    setHits(null);
    try {
      setStats(await getTransport().invoke<KnowledgeStats>("knowledge_ingest", { project: activeProject, file }));
    } catch {
      /* surfaced by the empty state / stats not updating */
    } finally {
      setIngesting(false);
    }
  }

  async function index() {
    if (!activeProject) return;
    setIndexing(true);
    setHits(null);
    try {
      setStats(await getTransport().invoke<KnowledgeStats>("knowledge_index", { project: activeProject }));
    } catch {
      setStats(null);
    } finally {
      setIndexing(false);
    }
  }

  async function search() {
    if (!activeProject || !query.trim() || !stats) return;
    setSearching(true);
    try {
      setHits(await getTransport().invoke<KnowledgeHit[]>("knowledge_search", { project: activeProject, query, limit: 10 }));
    } catch {
      setHits([]);
    } finally {
      setSearching(false);
    }
  }

  return (
    <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Database size={14} style={{ color: "var(--accent)" }} />
          <span className="text-sm font-medium">Knowledge Base</span>
          {stats && (
            <span className="text-xs text-text-muted">
              indexed {stats.files} files · {stats.chunks} chunks
            </span>
          )}
        </div>
        <div className="shrink-0 flex items-center gap-2">
          <button
            onClick={ingest}
            disabled={ingesting || !activeProject}
            title="Convert a document (PDF/Office/HTML) to Markdown and index it"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary disabled:opacity-55"
          >
            {ingesting ? <Loader2 size={13} className="animate-spin" /> : <FilePlus size={13} />}
            {ingesting ? "Ingesting…" : "Add document"}
          </button>
          <button
            onClick={index}
            disabled={indexing || !activeProject}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary disabled:opacity-55"
          >
            {indexing ? <Loader2 size={13} className="animate-spin" /> : <RotateCw size={13} />}
            {indexing ? "Indexing…" : "Index project"}
          </button>
        </div>
      </div>
      <p className="text-xs text-text-muted">
        BM25 search over this project's source and ingested documents (specs, RFCs). Index or add a document, then search.
      </p>
      <div className="flex items-center gap-2">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void search()}
          placeholder={stats ? "Search the codebase…" : "Index the project to enable search"}
          disabled={!stats}
          className="flex-1 disabled:opacity-55"
        />
        <button
          onClick={search}
          disabled={searching || !stats || !query.trim()}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md disabled:opacity-55"
          style={{ background: "var(--accent)", color: "var(--accent-contrast)" }}
        >
          {searching ? <Loader2 size={13} className="animate-spin" /> : <Search size={13} />}
          Search
        </button>
      </div>
      {hits && hits.length === 0 && <p className="text-xs text-text-muted">No matches.</p>}
      {hits && hits.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {hits.map((h, i) => (
            <div key={i} className="rounded-md" style={{ padding: "var(--space-sm)", background: "var(--surface-code)" }}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono truncate" style={{ color: "var(--accent)" }}>{h.file}</span>
                <span className="text-xs text-text-muted shrink-0">score {h.score.toFixed(2)}</span>
              </div>
              <pre className="text-xs text-text-secondary mt-1 whitespace-pre-wrap font-mono" style={{ margin: 0 }}>{h.snippet}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function KnowledgeView() {
  const [data, setData] = useState<KnowledgeSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);

  const load = () => {
    setLoading(true);
    getTransport()
      .invoke<KnowledgeSummary>("knowledge_summary")
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  };

  const clear = async () => {
    const total =
      (data?.targets.length ?? 0) + (data?.runs.length ?? 0) + (data?.crashes.length ?? 0);
    if (
      !window.confirm(
        `Clear all learned knowledge (${total} entries: discovered targets, runs, and crashes)?\n\nCorpus inputs and configuration are not affected. This cannot be undone.`,
      )
    ) {
      return;
    }
    setClearing(true);
    try {
      await getTransport().invoke("clear_knowledge");
      load();
    } catch {
      /* surfaced by the empty state on reload */
    } finally {
      setClearing(false);
    }
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
        <div className="shrink-0 flex items-center gap-2">
          <button
            onClick={load}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary"
          >
            {loading ? <Loader2 size={13} className="animate-spin" /> : <RotateCw size={13} />}
            Refresh
          </button>
          <button
            onClick={() => void clear()}
            disabled={clearing || !!empty || !data?.db_configured}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-solid bg-surface-primary transition-colors disabled:opacity-45 disabled:cursor-not-allowed"
            style={{ borderColor: "var(--border)", color: "var(--error)" }}
            title="Delete all discovered targets, runs, and crashes"
          >
            {clearing ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
            Clear
          </button>
        </div>
      </div>

      <KnowledgeBaseSearch />

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
              <Row key={i} left={c.kind} mid={c.summary.length > 80 ? c.summary.slice(0, 80) + "…" : c.summary} right={c.signature ? c.signature.slice(0, 12) : ""} badge={c.severity ? <SeverityChip severity={c.severity} /> : undefined} danger />
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

function Row({ left, mid, right, danger, badge }: { left: string; mid: string; right: string; danger?: boolean; badge?: ReactNode }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2 border-b border-border last:border-0 text-xs">
      <span className="font-mono shrink-0" style={{ color: danger ? "var(--error)" : "var(--text-primary)", minWidth: "120px" }}>{left}</span>
      {badge}
      <span className="text-text-secondary flex-1 truncate">{mid}</span>
      <span className="text-text-muted font-mono shrink-0 truncate" style={{ maxWidth: "240px" }}>{right}</span>
    </div>
  );
}

// Compact CASR exploitability chip for the Knowledge crash rows.
const KNOWLEDGE_SEVERITY: Record<string, { label: string; bg: string; fg: string }> = {
  Exploitable: { label: "EXPLOITABLE", bg: "var(--error-subtle)", fg: "var(--error)" },
  ProbablyExploitable: { label: "PROBABLY", bg: "rgba(217,119,6,0.16)", fg: "#d97706" },
  NotExploitable: { label: "NOT EXPL.", bg: "var(--surface-active)", fg: "var(--text-secondary)" },
  Undefined: { label: "UNCLASSIFIED", bg: "var(--surface-active)", fg: "var(--text-muted)" },
};

function SeverityChip({ severity }: { severity: string }) {
  const s = KNOWLEDGE_SEVERITY[severity] ?? KNOWLEDGE_SEVERITY.Undefined;
  return (
    <span className="text-xs px-1.5 py-0.5 rounded-sm font-semibold shrink-0" style={{ background: s.bg, color: s.fg, letterSpacing: "0.03em" }}>
      {s.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Automation
// ---------------------------------------------------------------------------

interface CampaignView {
  id: string;
  name: string;
  enabled: boolean;
  trigger: string;
  project: string;
  target: string;
  engine: string;
  duration_secs: number;
  last_fire: string | null;
}

interface ExecutionView {
  execution_id: string;
  schedule_id: string;
  campaign: string;
  triggered_at: string;
  status: string;
  summary: string;
}

const EXEC_STATUS_COLOR: Record<string, string> = {
  completed: "var(--accent)",
  running: "#d97706",
  failed: "var(--error)",
  skipped: "var(--text-muted)",
  pending: "var(--text-muted)",
};

export function AutomationView() {
  const { activeProject } = useProject();
  const { target, engine } = useTarget();
  const [campaigns, setCampaigns] = useState<CampaignView[]>([]);
  const [history, setHistory] = useState<ExecutionView[]>([]);
  const [triggerKind, setTriggerKind] = useState<"interval" | "cron" | "once">("interval");
  const [triggerValue, setTriggerValue] = useState("3600");
  const [duration, setDuration] = useState(60);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load + light poll so last-run times and execution history update as
  // campaigns fire.
  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      const T = getTransport();
      T.invoke<CampaignView[]>("schedule_list")
        .then((c) => !cancelled && setCampaigns(c))
        .catch(() => !cancelled && setCampaigns([]));
      T.invoke<ExecutionView[]>("schedule_history", { limit: 20 })
        .then((h) => !cancelled && setHistory(h))
        .catch(() => !cancelled && setHistory([]));
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const canSave = !!activeProject && !!target;
  async function save() {
    if (!canSave) return;
    setBusy(true);
    setError(null);
    try {
      const next = await getTransport().invoke<CampaignView[]>("schedule_create", {
        name: `${shortProject(activeProject)} / ${target}`,
        project: activeProject,
        target,
        engine: engine || "libfuzzer",
        durationSecs: duration,
        triggerKind,
        triggerValue,
      });
      setCampaigns(next);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function remove(id: string) {
    setCampaigns(await getTransport().invoke<CampaignView[]>("schedule_delete", { id }));
  }
  async function toggle(id: string, enabled: boolean) {
    setCampaigns(await getTransport().invoke<CampaignView[]>("schedule_set_enabled", { id, enabled }));
  }

  const placeholder =
    triggerKind === "interval"
      ? "seconds, e.g. 3600"
      : triggerKind === "cron"
        ? "cron, e.g. 0 2 * * *"
        : "RFC3339, e.g. 2026-07-01T02:00:00Z";

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Automation" description="Schedule fuzz campaigns to run automatically — on an interval, a cron expression, or once at a set time. They run headlessly in the background and persist across restarts." />

      {/* New campaign form */}
      <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
        <div className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>New Campaign</div>
        <div className="text-xs text-text-secondary">
          {canSave ? (
            <>Target: <span className="font-mono text-text-primary">{shortProject(activeProject)} / {target}</span> · <span className="font-mono">{engine || "libfuzzer"}</span></>
          ) : (
            "Pick a project + target first (Discover/Harness)."
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={triggerKind}
            onChange={(v) => setTriggerKind(v as typeof triggerKind)}
            options={[
              { value: "interval", label: "Interval" },
              { value: "cron", label: "Cron" },
              { value: "once", label: "Once" },
            ]}
          />
          <Input mono value={triggerValue} onChange={(e) => setTriggerValue(e.target.value)} placeholder={placeholder}
            className="flex-1 min-w-[180px]" />
          <label className="text-xs text-text-muted flex items-center gap-1">
            run
            <Input mono type="number" min={10} value={duration} onChange={(e) => setDuration(Math.max(10, Number(e.target.value) || 60))}
              className="w-16" />
            s
          </label>
          <button onClick={save} disabled={!canSave || busy || !triggerValue.trim()}
            className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md disabled:opacity-50"
            style={{ background: "var(--accent)", color: "var(--accent-contrast)", border: "none" }}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
            Schedule
          </button>
        </div>
        {error && <span className="text-xs" style={{ color: "var(--error)" }}>{error}</span>}
      </div>

      {campaigns.length === 0 && (
        <EmptyState icon={<Zap size={20} />} hint="No scheduled campaigns yet. Pick a project + target, choose a trigger, and Schedule it to fuzz on autopilot." />
      )}

      <div className="flex flex-col gap-2">
        {campaigns.map((c) => (
          <div key={c.id} className="surface-card flex items-center gap-3" style={{ padding: "var(--space-md)", borderLeft: c.enabled ? "3px solid var(--accent)" : "3px solid transparent", opacity: c.enabled ? 1 : 0.6 }}>
            <div className="flex flex-col min-w-0 flex-1">
              <span className="text-sm font-medium truncate">{c.name}</span>
              <span className="text-xs text-text-muted font-mono">
                {c.trigger} · {c.engine} · {c.duration_secs}s
                {c.last_fire ? ` · last ${new Date(c.last_fire).toLocaleString()}` : " · never run"}
              </span>
            </div>
            <button onClick={() => toggle(c.id, !c.enabled)}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-xs rounded-md border"
              style={c.enabled ? { borderColor: "var(--border)", background: "var(--surface-primary)", color: "var(--text-secondary)" } : { background: "var(--accent)", color: "var(--accent-contrast)", borderColor: "transparent" }}
              title={c.enabled ? "Pause this campaign" : "Resume this campaign"}>
              {c.enabled ? <Square size={13} /> : <Play size={13} />}
              {c.enabled ? "Pause" : "Resume"}
            </button>
            <button onClick={() => remove(c.id)} className="inline-flex items-center justify-center p-1.5 rounded-md text-text-muted hover:text-error hover:bg-surface-hover" title="Delete campaign" aria-label="Delete campaign">
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </div>

      {/* Execution history */}
      {history.length > 0 && (
        <div className="surface-card flex flex-col" style={{ padding: "var(--space-md)" }}>
          <div className="text-xs text-text-muted uppercase mb-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            Recent Runs
          </div>
          <div className="flex flex-col">
            {history.map((h) => (
              <div key={h.execution_id} className="flex items-center gap-3 py-1.5 border-b border-border last:border-0 text-xs">
                <span className="font-semibold shrink-0" style={{ color: EXEC_STATUS_COLOR[h.status] ?? "var(--text-muted)", minWidth: "72px", textTransform: "uppercase", letterSpacing: "0.03em" }}>
                  {h.status}
                </span>
                <span className="font-mono truncate" style={{ minWidth: "120px" }}>{h.campaign}</span>
                <span className="text-text-secondary flex-1 truncate">{h.summary}</span>
                <span className="text-text-muted font-mono shrink-0">{new Date(h.triggered_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
