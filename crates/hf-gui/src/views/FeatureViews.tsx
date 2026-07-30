import { useCallback, useEffect, useMemo, useReducer, useState, type ReactNode } from "react";
import { Button, IconButton, EmptyState, Input, LoadingState, Select, SeverityBadge, Textarea, ViewHeader } from "../components/ui";
import { Puzzle, BookOpen, Zap, Target, FileCode, Activity, Bug, Crosshair, Play, Loader2, Plus, Trash2, RotateCw, RotateCcw, Copy, Square, Bot, Shield, Database, Pencil, Save, X, Search, FilePlus, FolderOpen, Layers } from "lucide-react";
import { getTransport, pickFile, pickFolder, emitDataChanged } from "../lib";
import { useI18n } from "../i18nContext";
import { useConfirm } from "../providers/confirm";
import { useProject } from "../providers/project";
import { useTarget } from "../providers/target";
import { useFuzzingSettings } from "../hooks/useFuzzingSettings";
import { FuzzingPolicyNotice } from "../components/FuzzingPolicyNotice";
import {
  campaignConcurrencyHierarchy,
  parseCampaignConcurrencyLimits,
  type CampaignConcurrencyLimits,
} from "../lib/schedulerLimits";
import {
  ScheduleRecoveryPanel,
  type OneTimeRecoveryView,
} from "../components/ScheduleRecoveryPanel";
import {
  acknowledgeRecoveryWithRefresh,
  createLatestRefresh,
  initialRecoveryLoadState,
  recoveryLoadReducer,
} from "../lib/scheduleRecovery";

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
    <IconButton onClick={onClick} title={title} aria-label={title} danger={danger}>
      {icon}
    </IconButton>
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
  const { t } = useI18n();
  const confirm = useConfirm();
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
      setError(t("agents.errNameRequired"));
      return;
    }
    if (!draft.system_prompt.trim()) {
      setError(t("agents.errSystemPromptRequired"));
      return;
    }
    if (!isSafeSlug(id)) {
      setError(t("agents.errIdSlug"));
      return;
    }
    let temperature: number | null = null;
    if (draft.temperature.trim() !== "") {
      const temp = Number(draft.temperature);
      if (Number.isNaN(temp)) {
        setError(t("agents.errTemperature"));
        return;
      }
      temperature = temp;
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
      await getTransport().invoke("save_agent", { definition: def });
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
      ? t("agents.resetConfirm", { name: a.name })
      : t("agents.deleteConfirm", { name: a.name });
    if (!(await confirm({ title: builtIn ? t("agents.resetTitle") : t("common.delete"), message: prompt, danger: !builtIn, confirmLabel: builtIn ? t("common.reset") : t("common.delete") }))) return;
    try {
      await getTransport().invoke("delete_agent", { id: a.id });
      reload();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title={t("agents.title")} description={t("agents.description")} />

      {info && (
        <div className="grid grid-cols-3 gap-3">
          <Tile icon={<Bot size={16} />} label={t("agents.tileModel")} value={info.model} />
          <Tile icon={<Activity size={16} />} label={t("agents.tileProvider")} value={info.provider_type || "—"} />
          <Tile icon={<Shield size={16} />} label={t("agents.tileGuardrails")} value={info.guardrails} />
        </div>
      )}

      <div className="flex items-center justify-between mt-1">
        <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.08em" }}>
          {t("agents.countLabel", { n: agents.length })}
        </span>
        {!draft && <PrimaryBtn onClick={startNew} icon={<Plus size={13} />}>{t("agents.new")}</PrimaryBtn>}
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
            <EmptyState icon={<Bot size={20} />} hint={t("agents.empty")} />
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
  const { t } = useI18n();
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
            {builtIn ? t("agents.builtIn") : t("agents.custom")}
          </span>
        </span>
        <span className="text-xs text-text-secondary mt-0.5">{agent.description}</span>
        <span className="text-xs text-text-muted font-mono mt-1">
          {agent.role} · {agent.autonomy} · {agent.allowed_tools.length ? agent.allowed_tools.join(", ") : t("agents.noTools")}
          {agent.skills.length > 0 && ` · ${t("agents.skillsCount", { n: agent.skills.length })}`}
        </span>
      </div>
      <div className="flex items-center shrink-0">
        <IconBtn onClick={onEdit} icon={<Pencil size={14} />} title={t("common.edit")} />
        <IconBtn onClick={onDuplicate} icon={<Copy size={14} />} title={t("agents.duplicateTitle")} />
        {builtIn ? (
          <IconBtn onClick={onDelete} icon={<RotateCcw size={14} />} title={t("agents.resetTitle")} />
        ) : (
          <IconBtn onClick={onDelete} icon={<Trash2 size={14} />} danger title={t("common.delete")} />
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
  const { t } = useI18n();
  // For a new agent, the id auto-derives from the name unless the user edits it.
  const derivedId = draft.isNew ? slugify(draft.id.trim() || draft.name) : draft.id;
  return (
    <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      {error && <ErrorBanner message={error} />}
      <div className="grid grid-cols-2 gap-3">
        <Field label={t("agents.fieldName")}>
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
        <Field label={t("agents.fieldId")} hint={draft.isNew ? t("agents.fieldIdHintNew") : t("agents.fieldHintLocked")}>
          <Input
            mono
            value={derivedId}
            disabled={!draft.isNew}
            placeholder="discovery-scout"
            onChange={(e) => onField("id", e.target.value)}
          />
        </Field>
      </div>

      <Field label={t("agents.fieldDescription")}>
        <Input mono value={draft.description} placeholder={t("agents.fieldDescriptionPlaceholder")} onChange={(e) => onField("description", e.target.value)} />
      </Field>

      <div className="grid grid-cols-2 gap-3">
        <Field label={t("agents.fieldRole")}>
          <Select
            mono
            className="w-full"
            value={draft.role}
            onChange={(v) => onField("role", v as AgentRole)}
            options={ROLES.map((r) => ({ value: r, label: r }))}
          />
        </Field>
        <Field label={t("agents.fieldAutonomy")}>
          <Select
            mono
            className="w-full"
            value={draft.autonomy}
            onChange={(v) => onField("autonomy", v as Autonomy)}
            options={AUTONOMY_LEVELS.map((a) => ({ value: a, label: a }))}
          />
        </Field>
      </div>

      <Field label={t("agents.fieldSystemPrompt")} hint={t("agents.fieldSystemPromptHint")}>
        <Textarea
          mono
          rows={14}
          value={draft.system_prompt}
          placeholder={t("agents.fieldSystemPromptPlaceholder")}
          onChange={(e) => onField("system_prompt", e.target.value)}
        />
      </Field>

      <Field label={t("agents.fieldAllowedTools")} hint={t("agents.fieldAllowedToolsHint")}>
        {tools.length === 0 ? (
          <span className="text-xs text-text-muted">{t("agents.noToolsAvailable")}</span>
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

      <Field label={t("agents.fieldSkills")} hint={t("agents.fieldSkillsHint")}>
        {skills.length === 0 ? (
          <span className="text-xs text-text-muted">{t("agents.noSkillsAvailable")}</span>
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
        <Field label={t("agents.fieldModelTags")} hint={t("agents.fieldModelTagsHint")}>
          <Input mono value={draft.model_tags} placeholder="reasoning, code" onChange={(e) => onField("model_tags", e.target.value)} />
        </Field>
        <Field label={t("agents.fieldTemperature")} hint={t("agents.fieldTemperatureHint")}>
          <Input mono value={draft.temperature} placeholder={t("agents.fieldTemperaturePlaceholder")} onChange={(e) => onField("temperature", e.target.value)} />
        </Field>
        <Field label={t("agents.fieldMaxIterations")} hint={t("agents.fieldMaxIterationsHint")}>
          <Input mono type="number" min={1} max={50} value={draft.max_iterations} onChange={(e) => onField("max_iterations", Number(e.target.value) || 1)} />
        </Field>
      </div>

      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onCancel} icon={<X size={13} />}>{t("common.cancel")}</GhostBtn>
        <PrimaryBtn onClick={onSave} disabled={busy} icon={busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}>{t("common.save")}</PrimaryBtn>
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
// Editable form state. The markdown body is bound here and saved as part of a
// typed SkillDefinition through either transport.
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
  const { t } = useI18n();
  const confirm = useConfirm();
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
        setError(t("skills.errNotFound", { name }));
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
      setError(t("skills.errNameRequired"));
      return;
    }
    if (draft.isNew && !isSafeSlug(name)) {
      setError(t("skills.errNameSlug"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await getTransport().invoke("save_skill", {
        definition: {
          name,
          description: draft.description,
          version: draft.version,
          domain: splitList(draft.domain),
          body: draft.body,
          max_input_tokens: 0,
          trust_tier: "user-defined",
        },
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
      ? t("skills.resetConfirm", { name: s.name })
      : t("skills.deleteConfirm", { name: s.name });
    if (!(await confirm({ title: builtIn ? t("agents.resetTitle") : t("common.delete"), message: prompt, danger: !builtIn, confirmLabel: builtIn ? t("common.reset") : t("common.delete") }))) return;
    try {
      await getTransport().invoke("delete_skill", { name: s.name });
      reload();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title={t("skills.title")} description={t("skills.description")} />

      <div className="flex items-center justify-between mt-1">
        <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.08em" }}>
          {t("skills.countLabel", { n: skills.length })}
        </span>
        {!draft && <PrimaryBtn onClick={startNew} icon={<Plus size={13} />}>{t("skills.new")}</PrimaryBtn>}
      </div>

      {error && !draft && <ErrorBanner message={error} />}

      {draft ? (
        <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
          {error && <ErrorBanner message={error} />}
          <div className="grid grid-cols-2 gap-3">
            <Field label={t("skills.fieldName")} hint={draft.isNew ? t("skills.fieldNameHintNew") : t("skills.fieldHintLocked")}>
              <Input mono value={draft.name} disabled={!draft.isNew} placeholder="my-skill" onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </Field>
            <Field label={t("skills.fieldVersion")}>
              <Input mono value={draft.version} placeholder="0.1.0" onChange={(e) => setDraft({ ...draft, version: e.target.value })} />
            </Field>
          </div>
          <Field label={t("skills.fieldDescription")}>
            <Input mono value={draft.description} placeholder={t("skills.fieldDescriptionPlaceholder")} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
          </Field>
          <Field label={t("skills.fieldDomain")} hint={t("skills.fieldDomainHint")}>
            <Input mono value={draft.domain} placeholder="fuzzing, harness-generation" onChange={(e) => setDraft({ ...draft, domain: e.target.value })} />
          </Field>
          <Field label={t("skills.fieldBody")} hint={t("skills.fieldBodyHint")}>
            <Textarea mono rows={16} value={draft.body} onChange={(e) => setDraft({ ...draft, body: e.target.value })} />
          </Field>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => { setDraft(null); setError(null); }} icon={<X size={13} />}>{t("common.cancel")}</GhostBtn>
            <PrimaryBtn onClick={save} disabled={busy} icon={busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}>{t("common.save")}</PrimaryBtn>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {!loaded && <LoadingState label={t("skills.loading")} />}
          {loaded && skills.length === 0 && (
            <EmptyState icon={<Puzzle size={20} />} hint={t("skills.empty")} />
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
  const { t } = useI18n();
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
            {builtIn ? t("agents.builtIn") : t("agents.custom")}
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
        <IconBtn onClick={onEdit} icon={<Pencil size={14} />} title={t("common.edit")} />
        <IconBtn onClick={onDuplicate} icon={<Copy size={14} />} title={t("skills.duplicateTitle")} />
        {builtIn ? (
          <IconBtn onClick={onDelete} icon={<RotateCcw size={14} />} title={t("agents.resetTitle")} />
        ) : (
          <IconBtn onClick={onDelete} icon={<Trash2 size={14} />} danger title={t("common.delete")} />
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
// Read-only index status from `knowledge_stats` (never triggers a reindex).
interface KnowledgeIndexStatus {
  indexed: boolean;
  files: number;
  chunks: number;
  documents: number;
  indexed_at: string | null;
  retrieval_strategy: string;
  chunk_max_tokens: number;
}

// BM25 search over the active project's source, backed by hf-knowledge.
function KnowledgeBaseSearch() {
  const { t } = useI18n();
  const { activeProject } = useProject();
  // The status is keyed by project so a slow reply for a project the user has
  // already navigated away from cannot be rendered (same pattern as the
  // Automation view's schedulable-target load).
  const [status, setStatus] = useState<{ project: string; value: KnowledgeIndexStatus } | null>(null);
  const [indexing, setIndexing] = useState(false);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<KnowledgeHit[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [ingesting, setIngesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const current = activeProject && status?.project === activeProject ? status.value : null;
  const indexed = !!current?.indexed;

  // Load the index status for the active project so the card shows the real
  // index size/config on first render instead of only after a manual reindex.
  useEffect(() => {
    if (!activeProject) return undefined;
    let cancelled = false;
    getTransport()
      .invoke<KnowledgeIndexStatus>("knowledge_stats", { project: activeProject })
      .then((value) => !cancelled && setStatus({ project: activeProject, value }))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [activeProject]);

  async function refreshStatus() {
    if (!activeProject) return;
    try {
      const value = await getTransport().invoke<KnowledgeIndexStatus>("knowledge_stats", { project: activeProject });
      setStatus({ project: activeProject, value });
    } catch {
      /* a missing status only hides the stats line; index/search report their own errors */
    }
  }

  // Convert a document (PDF/Office/HTML/...) to Markdown via markitdown in the
  // sandbox and add it to this project's knowledge base.
  async function ingest() {
    if (!activeProject || ingesting) return;
    const file = await pickFile(t("knowledge.ingestPickTitle"));
    if (!file) return;
    setIngesting(true);
    setHits(null);
    setError(null);
    try {
      await getTransport().invoke<KnowledgeStats>("knowledge_ingest", { project: activeProject, file });
      await refreshStatus();
    } catch (e) {
      // Previously swallowed -- an ingest failure (missing markitdown, bad path
      // in browser mode, etc.) looked identical to "nothing happened".
      setError(t("knowledge.addDocFailed", { error: String(e) }));
    } finally {
      setIngesting(false);
    }
  }

  async function index() {
    if (!activeProject) return;
    setIndexing(true);
    setHits(null);
    setError(null);
    try {
      await getTransport().invoke<KnowledgeStats>("knowledge_index", { project: activeProject });
      await refreshStatus();
    } catch (e) {
      setError(t("knowledge.indexFailed", { error: String(e) }));
    } finally {
      setIndexing(false);
    }
  }

  async function search() {
    if (!activeProject || !query.trim() || !indexed) return;
    setSearching(true);
    setError(null);
    try {
      setHits(await getTransport().invoke<KnowledgeHit[]>("knowledge_search", { project: activeProject, query, limit: 10 }));
    } catch (e) {
      setHits(null);
      setError(t("knowledge.searchFailed", { error: String(e) }));
    } finally {
      setSearching(false);
    }
  }

  return (
    <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Database size={14} style={{ color: "var(--accent)" }} />
          <span className="text-sm font-medium">{t("knowledge.baseTitle")}</span>
          {current && (
            <span className="text-xs text-text-muted">
              {current.indexed
                ? t("knowledge.indexStats", { files: current.files, chunks: current.chunks })
                : t("knowledge.notIndexed")}
            </span>
          )}
        </div>
        <div className="shrink-0 flex items-center gap-2">
          <button
            onClick={ingest}
            disabled={ingesting || !activeProject}
            title={t("knowledge.addDocTitle")}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary disabled:opacity-55"
          >
            {ingesting ? <Loader2 size={13} className="animate-spin" /> : <FilePlus size={13} />}
            {ingesting ? t("knowledge.ingesting") : t("knowledge.addDoc")}
          </button>
          <button
            onClick={index}
            disabled={indexing || !activeProject}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary disabled:opacity-55"
          >
            {indexing ? <Loader2 size={13} className="animate-spin" /> : <RotateCw size={13} />}
            {indexing ? t("knowledge.indexing") : t("knowledge.indexProject")}
          </button>
        </div>
      </div>
      <p className="text-xs text-text-muted">
        {t("knowledge.baseHelp")}
      </p>
      {current && (
        <p className="text-xs text-text-muted">
          {t("knowledge.configSummary", { strategy: current.retrieval_strategy, tokens: current.chunk_max_tokens })}
          {current.documents > 0 && ` · ${t("knowledge.docsCount", { n: current.documents })}`}
          {current.indexed_at && ` · ${t("knowledge.lastIndexed", { time: new Date(current.indexed_at).toLocaleString() })}`}
        </p>
      )}
      {!activeProject && (
        <p className="text-xs" style={{ color: "var(--warning, #d9a441)" }}>
          {t("knowledge.selectProjectFirst")}
        </p>
      )}
      {error && (
        <div
          className="text-xs rounded-md"
          style={{ padding: "var(--space-sm)", background: "var(--surface-code)", color: "var(--danger, #e5484d)", border: "1px solid var(--danger, #e5484d)" }}
        >
          {error}
        </div>
      )}
      <div className="flex items-center gap-2">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void search()}
          placeholder={indexed ? t("knowledge.searchPlaceholder") : t("knowledge.searchPlaceholderNoIndex")}
          disabled={!indexed}
          className="flex-1 disabled:opacity-55"
        />
        <button
          onClick={search}
          disabled={searching || !indexed || !query.trim()}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md disabled:opacity-55"
          style={{ background: "var(--accent)", color: "var(--accent-contrast)" }}
        >
          {searching ? <Loader2 size={13} className="animate-spin" /> : <Search size={13} />}
          {t("common.search")}
        </button>
      </div>
      {hits && hits.length === 0 && <p className="text-xs text-text-muted">{t("knowledge.noMatches")}</p>}
      {hits && hits.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {hits.map((h, i) => (
            <div key={i} className="rounded-md" style={{ padding: "var(--space-sm)", background: "var(--surface-code)" }}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono truncate" style={{ color: "var(--accent)" }}>{h.file}</span>
                <span className="text-xs text-text-muted shrink-0">{t("knowledge.score", { score: h.score.toFixed(2) })}</span>
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
  const { t } = useI18n();
  const confirm = useConfirm();
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
      !(await confirm({
        title: t("knowledge.clearTitle"),
        message: t("knowledge.clearMessage", { total }),
        danger: true,
        confirmLabel: t("common.clear"),
      }))
    ) {
      return;
    }
    setClearing(true);
    try {
      await getTransport().invoke("clear_knowledge");
      load();
      // Other views (Workbench counts, corpus) reflect this wipe -- tell them.
      emitDataChanged();
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
        <ViewHeader title={t("knowledge.title")} description={t("knowledge.description")} />
        <div className="shrink-0 flex items-center gap-2">
          <button
            onClick={load}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary"
          >
            {loading ? <Loader2 size={13} className="animate-spin" /> : <RotateCw size={13} />}
            {t("common.refresh")}
          </button>
          <button
            onClick={() => void clear()}
            disabled={clearing || !!empty || !data?.db_configured}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-solid bg-surface-primary transition-colors disabled:opacity-45 disabled:cursor-not-allowed"
            style={{ borderColor: "var(--border)", color: "var(--error)" }}
            title={t("knowledge.clearBtnTitle")}
          >
            {clearing ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
            {t("common.clear")}
          </button>
        </div>
      </div>

      <KnowledgeBaseSearch />

      {data && !data.db_configured && (
        <EmptyState icon={<BookOpen size={20} />} hint={t("knowledge.emptyNoDb")} />
      )}
      {empty && data?.db_configured && (
        <EmptyState icon={<BookOpen size={20} />} hint={t("knowledge.emptyNothing")} />
      )}

      {data && !empty && (
        <>
          <KnowledgeSection title={t("knowledge.sectionTargets")} count={data.targets.length} icon={<Crosshair size={14} />}>
            {data.targets.slice(0, 40).map((tg, i) => (
              <Row key={i} left={tg.symbol} mid={`${tg.kind} · ${t("knowledge.fit", { score: tg.fit_score.toFixed(2) })}`} right={`${shortProject(tg.project)} · ${tg.location.split("/").pop()}`} />
            ))}
          </KnowledgeSection>

          <KnowledgeSection title={t("knowledge.sectionRuns")} count={data.runs.length} icon={<Play size={14} />}>
            {data.runs.slice(0, 40).map((r) => (
              <Row key={r.id} left={r.engine} mid={r.status} right={`${shortProject(r.project)} · ${new Date(r.started_at).toLocaleString()}`} />
            ))}
          </KnowledgeSection>

          <KnowledgeSection title={t("knowledge.sectionCrashes")} count={data.crashes.length} icon={<Bug size={14} />}>
            {data.crashes.slice(0, 40).map((c, i) => (
              <Row key={i} left={c.kind} mid={c.summary.length > 80 ? c.summary.slice(0, 80) + "…" : c.summary} right={c.signature ? c.signature.slice(0, 12) : ""} badge={c.severity ? <SeverityBadge severity={c.severity} /> : undefined} danger />
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

// ---------------------------------------------------------------------------
// Automation
// ---------------------------------------------------------------------------

interface CampaignView {
  id: string;
  name: string;
  enabled: boolean;
  trigger: string;
  project: string;
  /** null = portfolio campaign rotating through all promoted targets. */
  target: string | null;
  engine: string;
  lang: string;
  duration_secs: number;
  max_runs: number | null;
  max_total_secs: number | null;
  runs_done: number;
  secs_done: number;
  last_fire: string | null;
  durability_status: "ready" | "consumed" | "recovery_required";
}

interface ExecutionView {
  execution_id: string;
  schedule_id: string;
  campaign: string;
  triggered_at: string;
  status: string;
  summary: string;
}

/**
 * A target a campaign can actually be scheduled against: one with a promoted
 * harness. A campaign refuses to run anything else (generation, smoke and
 * promotion are deliberately human steps), so scheduling a target without one
 * only produces a failure at 3am -- the picker offers these and nothing else.
 */
interface SchedulableTarget {
  target: string;
  engine: string;
  language: string;
  fit_score: number;
}

const EXEC_STATUS_COLOR: Record<string, string> = {
  completed: "var(--accent)",
  running: "#d97706",
  failed: "var(--error)",
  skipped: "var(--text-muted)",
  pending: "var(--text-muted)",
};

export function AutomationView() {
  const { t } = useI18n();
  const confirm = useConfirm();
  const { activeProject, recentProjects, addRecent } = useProject();
  const { target: contextTarget } = useTarget();
  const { settings: fuzzingSettings, loaded: fuzzingPolicyLoaded, error: fuzzingPolicyError } = useFuzzingSettings();
  const [campaigns, setCampaigns] = useState<CampaignView[]>([]);
  const [history, setHistory] = useState<ExecutionView[]>([]);
  const [recoveries, setRecoveries] = useState<OneTimeRecoveryView[]>([]);
  const [recoveryLoad, dispatchRecoveryLoad] = useReducer(
    recoveryLoadReducer,
    initialRecoveryLoadState,
  );
  const [triggerKind, setTriggerKind] = useState<"interval" | "cron" | "once">("interval");
  const [triggerValue, setTriggerValue] = useState("3600");
  const [durationOverride, setDurationOverride] = useState<number | null>(null);
  const duration = durationOverride ?? fuzzingSettings?.default_duration_secs ?? 0;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A campaign is scoped to a project folder it picks itself (independent of the
  // open project), and either the whole project (all promoted targets, rotated)
  // or one target.
  const [project, setProject] = useState(activeProject);
  const [scopeAll, setScopeAll] = useState(true);
  const [loaded, setLoaded] = useState<{ project: string; items: SchedulableTarget[] } | null>(null);
  const [picked, setPicked] = useState("");
  // Budget (both optional): stop after N runs, or after M minutes of fuzzing.
  const [maxRuns, setMaxRuns] = useState("");
  const [maxMinutes, setMaxMinutes] = useState("");
  // The live fuzz-campaign cap is editable. The independent scheduler
  // workflow-dispatch cap is fixed at process startup, so both must remain
  // visible along with their effective minimum.
  const [concurrency, setConcurrency] = useState(1);
  const [concurrencyLimits, setConcurrencyLimits] =
    useState<CampaignConcurrencyLimits | null>(null);
  const [concurrencyLimitsLoaded, setConcurrencyLimitsLoaded] = useState(false);

  const projects = useMemo(() => {
    const all = [project, activeProject, ...recentProjects].filter(Boolean);
    return [...new Set(all)];
  }, [project, activeProject, recentProjects]);

  const automationRefresh = useMemo(
    () => createLatestRefresh({
      onStart: () => dispatchRecoveryLoad("start"),
      load: () => Promise.allSettled([
        getTransport().invoke<CampaignView[]>("schedule_list"),
        getTransport().invoke<ExecutionView[]>("schedule_history", { limit: 20 }),
        getTransport().invoke<OneTimeRecoveryView[]>("schedule_recovery_list"),
      ] as const),
      commit: ([nextCampaigns, nextHistory, nextRecoveries]) => {
        if (nextCampaigns.status === "fulfilled") {
          setCampaigns(nextCampaigns.value);
        } else {
          setError(String(nextCampaigns.reason));
        }
        if (nextHistory.status === "fulfilled") {
          setHistory(nextHistory.value);
        } else {
          setError(String(nextHistory.reason));
        }
        if (nextRecoveries.status === "fulfilled") {
          setRecoveries(nextRecoveries.value);
          dispatchRecoveryLoad("success");
        } else {
          setRecoveries([]);
          dispatchRecoveryLoad("error");
        }
      },
    }),
    [],
  );
  const refreshAutomation = useCallback(
    () => automationRefresh.refresh(),
    [automationRefresh],
  );

  // Load + light poll so campaign state, recoveries, and history stay aligned.
  useEffect(() => {
    automationRefresh.activate();
    void Promise.resolve()
      .then(refreshAutomation)
      .catch((cause: unknown) => setError(String(cause)));
    getTransport()
      .invoke<unknown>("schedule_concurrency_limits")
      .then((value) => {
        const limits = parseCampaignConcurrencyLimits(value);
        setConcurrencyLimits(limits);
        if (limits) setConcurrency(limits.active_fuzz_campaign_limit);
        setConcurrencyLimitsLoaded(true);
      })
      .catch(() => {
        setConcurrencyLimits(null);
        setConcurrencyLimitsLoaded(true);
      });
    const intervalId = window.setInterval(() => {
      void refreshAutomation().catch((cause: unknown) => setError(String(cause)));
    }, 10_000);
    return () => {
      window.clearInterval(intervalId);
      automationRefresh.deactivate();
    };
  }, [automationRefresh, refreshAutomation]);

  // Only promoted harnesses can be scheduled; ask the backend which those are.
  // The answer is stored with the project it belongs to, so a slow reply for a
  // project the user has already navigated away from cannot be rendered.
  useEffect(() => {
    if (!project) return undefined;
    let cancelled = false;
    getTransport()
      .invoke<SchedulableTarget[]>("schedule_targets", { project })
      .then((items) => !cancelled && setLoaded({ project, items }))
      .catch(() => !cancelled && setLoaded({ project, items: [] }));
    return () => {
      cancelled = true;
    };
  }, [project]);

  // `null` means "still loading", which is different from "this project has no
  // promoted harness" -- the empty-state text says so.
  const choices = useMemo(
    () => (project ? (loaded?.project === project ? loaded.items : null) : []),
    [project, loaded],
  );

  // The single-target selection is derived, not synced: the explicit pick when
  // still valid, else the target in focus elsewhere, else the highest-priority.
  const selected = useMemo(() => {
    if (!choices?.length) return null;
    const key = (t: SchedulableTarget) => `${t.target}::${t.engine}`;
    return (
      choices.find((t) => key(t) === picked) ??
      choices.find((t) => t.target === contextTarget) ??
      choices[0]
    );
  }, [choices, picked, contextTarget]);

  const promotedCount = choices?.length ?? 0;
  const canSave = !!fuzzingSettings && !!project && promotedCount > 0 && (scopeAll || !!selected);

  async function chooseFolder() {
    const path = await pickFolder();
    if (!path) return;
    addRecent(path);
    setProject(path);
  }

  async function applyConcurrency(n: number) {
    if (!concurrencyLimits) return;
    const clamped = Math.max(1, Math.min(16, n));
    setConcurrency(clamped);
    try {
      const applied = await getTransport().invoke<number>("schedule_concurrency_set", {
        maxConcurrent: clamped,
      });
      setConcurrency(applied);
      setConcurrencyLimits({
        active_fuzz_campaign_limit: applied,
        scheduler_workflow_dispatch_limit:
          concurrencyLimits.scheduler_workflow_dispatch_limit,
        effective_max_concurrent_fuzz_runs: Math.min(
          applied,
          concurrencyLimits.scheduler_workflow_dispatch_limit,
        ),
      });
    } catch (e) {
      setError(String(e));
      setConcurrency(concurrencyLimits.active_fuzz_campaign_limit);
    }
  }

  // Validate the trigger value client-side so a malformed schedule is rejected
  // with a clear message rather than failing opaquely on the backend.
  function validateTrigger(): string | null {
    const v = triggerValue.trim();
    if (!v) return t("automation.errTriggerEmpty");
    if (triggerKind === "interval") {
      const n = Number(v);
      if (!Number.isFinite(n) || n < 10) return t("automation.errInterval");
    } else if (triggerKind === "cron") {
      if (v.split(/\s+/).length < 5) return t("automation.errCron");
    } else if (triggerKind === "once") {
      if (Number.isNaN(Date.parse(v))) return t("automation.errOnce");
    }
    return null;
  }

  async function save() {
    if (!canSave || !fuzzingSettings) return;
    const invalid = validateTrigger();
    if (invalid) {
      setError(invalid);
      return;
    }
    const runs = maxRuns.trim() ? Math.max(1, Number(maxRuns)) : null;
    const totalSecs = maxMinutes.trim() ? Math.max(1, Math.round(Number(maxMinutes) * 60)) : null;
    const scopeLabel = scopeAll ? "all targets" : selected?.target ?? "";
    setBusy(true);
    setError(null);
    try {
      const next = await getTransport().invoke<CampaignView[]>("schedule_create", {
        name: `${shortProject(project)} / ${scopeLabel}`,
        project,
        // null = portfolio over all promoted targets; else the one target.
        target: scopeAll ? null : selected?.target ?? null,
        // Engine/lang come off the promoted harness for a single target; a
        // portfolio resolves them per target at run time.
        engine: scopeAll ? "" : selected?.engine ?? "",
        lang: scopeAll ? "c" : selected?.language ?? "c",
        durationSecs: duration,
        triggerKind,
        triggerValue,
        maxRuns: runs,
        maxTotalSecs: totalSecs,
      });
      setCampaigns(next);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function clearHistory() {
    if (
      !(await confirm({
        title: t("automation.clearHistoryTitle"),
        message: t("automation.clearHistoryMessage"),
        danger: true,
        confirmLabel: t("common.clear"),
      }))
    )
      return;
    setError(null);
    try {
      await getTransport().invoke<number>("schedule_history_clear");
      setHistory([]);
    } catch (e) {
      setError(String(e));
    }
  }

  async function acknowledgeRecovery(occurrenceId: string) {
    setError(null);
    try {
      await acknowledgeRecoveryWithRefresh({
        occurrenceId,
        confirm: () =>
          confirm({
            title: t("automation.recoveryAcknowledgeTitle"),
            message: t("automation.recoveryAcknowledgeMessage"),
            danger: true,
            confirmLabel: t("automation.recoveryAcknowledgeAction"),
          }),
        acknowledge: (id) =>
          getTransport().invoke<OneTimeRecoveryView>(
            "schedule_recovery_acknowledge",
            { occurrenceId: id },
          ),
        refresh: refreshAutomation,
      });
    } catch (cause) {
      setError(String(cause));
    }
  }

  async function remove(id: string) {
    if (!(await confirm({ title: t("automation.deleteCampaignTitle"), message: t("automation.deleteCampaignMessage"), danger: true, confirmLabel: t("common.delete") }))) return;
    setError(null);
    try {
      setCampaigns(await getTransport().invoke<CampaignView[]>("schedule_delete", { id }));
    } catch (e) {
      setError(String(e));
    }
  }
  async function toggle(id: string, enabled: boolean) {
    setError(null);
    try {
      setCampaigns(await getTransport().invoke<CampaignView[]>("schedule_set_enabled", { id, enabled }));
    } catch (e) {
      setError(String(e));
    }
  }

  const placeholder =
    triggerKind === "interval"
      ? t("automation.triggerPlaceholderInterval")
      : triggerKind === "cron"
        ? t("automation.triggerPlaceholderCron")
        : t("automation.triggerPlaceholderOnce");
  const limitHierarchy = concurrencyLimits
    ? campaignConcurrencyHierarchy(concurrencyLimits)
    : null;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <ViewHeader title={t("automation.title")} description={t("automation.description")} />
        <div className="surface-card flex items-stretch overflow-hidden" style={{ padding: 0 }}>
          {limitHierarchy ? (
            <>
              <div
                role="group"
                className="flex flex-col justify-center"
                style={{
                  padding: "var(--space-sm) var(--space-md)",
                  borderRight: "1px solid var(--border)",
                  minWidth: 138,
                }}
                title={t("automation.effectiveLimitTitle")}
                aria-label={t("automation.effectiveLimitTitle")}
              >
                <span className="text-xs text-text-secondary">
                  {t("automation.effectiveLimit")}
                </span>
                <strong className="text-lg font-semibold" style={{ color: "var(--accent)" }}>
                  {limitHierarchy.primary.value}
                </strong>
              </div>
              <div
                className="flex flex-col justify-center gap-1.5 text-xs text-text-muted"
                style={{ padding: "var(--space-sm) var(--space-md)" }}
              >
                <label
                  className="flex items-center justify-between gap-2"
                  title={t("automation.activeCampaignLimitTitle")}
                >
                  <span>{t("automation.activeCampaignLimit")}</span>
                  <Input
                    mono
                    type="number"
                    min={1}
                    max={16}
                    value={concurrency}
                    aria-label={t("automation.activeCampaignLimit")}
                    onChange={(e) => void applyConcurrency(Number(e.target.value) || 1)}
                    className="w-14"
                  />
                </label>
                <span title={t("automation.dispatchLimitTitle")}>
                  {t("automation.dispatchLimit")} {limitHierarchy.supporting[1].value}
                </span>
              </div>
            </>
          ) : (
            <span className="text-xs text-text-muted" style={{ padding: "var(--space-md)" }}>
              {concurrencyLimitsLoaded
                ? t("automation.concurrencyUnavailable")
                : t("common.loading")}
            </span>
          )}
        </div>
      </div>

      {!fuzzingSettings && (
        <FuzzingPolicyNotice
          state={fuzzingPolicyLoaded ? "unavailable" : "loading"}
          error={fuzzingPolicyError}
        />
      )}

      <ScheduleRecoveryPanel
        recoveries={recoveries}
        title={t("automation.recoveryTitle")}
        actionLabel={t("automation.recoveryAcknowledgeAction")}
        unknownScheduleLabel={t("automation.recoveryUnknownSchedule")}
        loading={recoveryLoad.loading}
        error={recoveryLoad.error}
        loadingLabel={t("automation.recoveryLoading")}
        errorLabel={t("automation.recoveryUnavailable")}
        onAcknowledge={(occurrenceId) => void acknowledgeRecovery(occurrenceId)}
      />

      {/* New campaign form */}
      <div className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
        <div className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("automation.newCampaign")}</div>

        {/* Project: a folder the campaign owns, independent of the open project. */}
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void chooseFolder()} className="shrink-0">
            <FolderOpen size={13} />
            {t("automation.chooseFolder")}
          </Button>
          <Select
            value={project}
            onChange={setProject}
            placeholder={t("automation.noProjectChosen")}
            options={projects.map((p) => ({ value: p, label: shortProject(p) }))}
            className="flex-1 min-w-[180px]"
          />
        </div>

        {/* Scope: the whole project (rotate) or one target. */}
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={scopeAll ? "all" : "one"}
            onChange={(v) => setScopeAll(v === "all")}
            options={[
              { value: "all", label: t("automation.scopeAll") },
              { value: "one", label: t("automation.scopeOne") },
            ]}
          />
          {scopeAll ? (
            <span className="text-xs text-text-secondary inline-flex items-center gap-1.5">
              <Layers size={13} />
              {choices === null
                ? t("automation.findingTargets")
                : promotedCount > 0
                  ? t("automation.rotatesThrough", { n: promotedCount })
                  : t("automation.noPromotedTarget")}
            </span>
          ) : (
            <Select
              value={selected ? `${selected.target}::${selected.engine}` : ""}
              onChange={setPicked}
              placeholder={choices === null ? t("automation.loadingTargets") : t("automation.noPromotedHarness")}
              options={(choices ?? []).map((tgt) => ({
                value: `${tgt.target}::${tgt.engine}`,
                label: `${tgt.target} · ${tgt.engine} · ${tgt.language}`,
              }))}
              className="flex-1 min-w-[180px]"
            />
          )}
        </div>

        {!canSave && project && choices !== null && promotedCount === 0 && (
          <div className="text-xs text-text-secondary">
            {t("automation.noPromotedHarnessHelp")}
          </div>
        )}
        {!project && (
          <div className="text-xs text-text-secondary">{t("automation.chooseFolderToBegin")}</div>
        )}

        {/* Trigger + per-run duration. */}
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={triggerKind}
            onChange={(v) => setTriggerKind(v as typeof triggerKind)}
            options={[
              { value: "interval", label: t("automation.triggerInterval") },
              { value: "cron", label: t("automation.triggerCron") },
              { value: "once", label: t("automation.triggerOnce") },
            ]}
          />
          <Input mono value={triggerValue} onChange={(e) => setTriggerValue(e.target.value)} placeholder={placeholder}
            className="flex-1 min-w-[180px]" />
          <label className="text-xs text-text-muted flex items-center gap-1">
            {t("automation.runLabel")}
            <Input mono type="number" min={1} max={fuzzingSettings?.sandbox.max_duration_secs} value={duration}
              disabled={!fuzzingSettings}
              onChange={(e) => setDurationOverride(Math.max(1, Number(e.target.value) || fuzzingSettings?.default_duration_secs || 1))}
              className="w-16" />
            s
          </label>
        </div>

        {/* Budget (optional): stop after N runs or M minutes of fuzzing. */}
        <div className="flex flex-wrap items-center gap-2 text-xs text-text-muted">
          <span>{t("automation.budget")}</span>
          <label className="flex items-center gap-1">
            <Input mono type="number" min={1} value={maxRuns} placeholder="∞" onChange={(e) => setMaxRuns(e.target.value)} className="w-16" />
            {t("automation.runsUnit")}
          </label>
          <span>{t("automation.or")}</span>
          <label className="flex items-center gap-1">
            <Input mono type="number" min={1} value={maxMinutes} placeholder="∞" onChange={(e) => setMaxMinutes(e.target.value)} className="w-16" />
            {t("automation.minTotal")}
          </label>
          <span className="opacity-70">{t("automation.blankUnbounded")}</span>
          <div className="flex-1" />
          <Button variant="primary" size="sm" onClick={save} loading={busy}
            disabled={!canSave || busy || !triggerValue.trim()} className="shrink-0">
            {!busy && <Plus size={13} />}
            {t("automation.schedule")}
          </Button>
        </div>
        {error && <span className="text-xs" style={{ color: "var(--error)" }}>{error}</span>}
      </div>

      {campaigns.length === 0 && (
        <EmptyState icon={<Zap size={20} />} hint={t("automation.emptyCampaigns")} />
      )}

      <div className="flex flex-col gap-2">
        {campaigns.map((c) => (
          <div key={c.id} className="surface-card flex items-center gap-3" style={{ padding: "var(--space-md)", borderLeft: c.enabled ? "3px solid var(--accent)" : "3px solid transparent", opacity: c.enabled ? 1 : 0.6 }}>
            <div className="flex flex-col min-w-0 flex-1">
              <span className="text-sm font-medium truncate">{c.name}</span>
              <span className="text-xs text-text-muted font-mono">
                {c.trigger} · {c.target ?? t("automation.allTargets")} · {c.engine || c.lang} · {c.duration_secs}s
                {c.max_runs != null ? ` · ${c.runs_done}/${c.max_runs} ${t("automation.runsUnit")}` : c.max_total_secs != null ? ` · ${c.secs_done}/${c.max_total_secs}s` : c.runs_done > 0 ? ` · ${c.runs_done} ${t("automation.runsUnit")}` : ""}
                {c.last_fire ? ` · ${t("automation.lastFire", { time: new Date(c.last_fire).toLocaleString() })}` : ` · ${t("automation.neverRun")}`}
              </span>
            </div>
            <Button variant={c.enabled ? "outline" : "primary"} size="sm"
              onClick={() => toggle(c.id, !c.enabled)}
              title={c.enabled ? t("automation.pauseTitle") : t("automation.resumeTitle")}>
              {c.enabled ? <Square size={13} /> : <Play size={13} />}
              {c.enabled ? t("common.pause") : t("common.resume")}
            </Button>
            <IconButton danger onClick={() => remove(c.id)} title={t("automation.deleteCampaignTitle")} aria-label={t("automation.deleteCampaignTitle")}>
              <Trash2 size={14} />
            </IconButton>
          </div>
        ))}
      </div>

      {/* Execution history. It outlives the schedule that produced it (a run's
          outcome is worth keeping after its campaign is deleted), so it needs a
          way to be cleared -- otherwise a campaign deleted months ago is still
          the only thing here. */}
      {history.length > 0 && (
        <div className="surface-card flex flex-col" style={{ padding: "var(--space-md)" }}>
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
              {t("automation.recentRuns")}
            </div>
            <Button variant="ghost" size="sm" onClick={() => void clearHistory()} title={t("automation.clearHistoryTitle")}>
              <Trash2 size={12} />
              {t("common.clear")}
            </Button>
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
