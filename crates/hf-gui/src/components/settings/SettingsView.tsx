// Full-window Settings takeover, modeled after y-agent's SettingsPanel.
//
// This is the orchestrator. For the ACTIVE config-backed section it owns the
// single source of truth: the parsed `value` (object / provider array), the
// `raw` TOML text, the `mode` (form | raw), and a `dirty` flag. FORM and RAW
// are two lossless views of the SAME file -- switching between them serializes
// or parses in memory, no disk round-trip. ONE header "Save Changes" button
// persists whichever view is active and clears dirty.

import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, Server, HardDrive, Crosshair, Shield, Database, Info, SlidersHorizontal, MessageSquare, Wrench, Share2, GitPullRequest } from "lucide-react";
import { getTransport } from "../../lib";
import { useI18n } from "../../i18n";
import { useToast } from "../ui/Toast";
import { useConfirm } from "../../providers/ConfirmContext";
import { Button } from "../ui/Button";
import { LoadingState } from "../ui";
import { GeneralTab } from "./GeneralTab";
import { ProvidersTab } from "./ProvidersTab";
import { normalizeProvider, type Provider } from "./providerTypes";
import { RuntimeTab } from "./RuntimeTab";
import { EnginesTab } from "./EnginesTab";
import { GuardrailsTab } from "./GuardrailsTab";
import { StorageTab } from "./StorageTab";
import { ObjectForm } from "./ObjectForm";
import { IntegrationsTab } from "./IntegrationsTab";
import { IssueTrackerTab } from "./IssueTrackerTab";
import { AboutTab } from "./AboutTab";

type SectionId =
  | "general"
  | "providers"
  | "session"
  | "runtime"
  | "engines"
  | "tools"
  | "guardrails"
  | "storage"
  | "integrations"
  | "issuetracker"
  | "about";

interface Section {
  id: SectionId;
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  /** Raw config section name, or null when the section has no config file. */
  config: string | null;
}

const SECTIONS: Section[] = [
  { id: "general", label: "General", icon: SlidersHorizontal, config: null },
  { id: "providers", label: "Providers", icon: Server, config: "providers" },
  { id: "session", label: "Session", icon: MessageSquare, config: "session" },
  { id: "runtime", label: "Runtime", icon: HardDrive, config: "runtime" },
  { id: "engines", label: "Engines", icon: Crosshair, config: "engines" },
  { id: "tools", label: "Tools", icon: Wrench, config: "tools" },
  { id: "guardrails", label: "Guardrails", icon: Shield, config: "guardrails" },
  { id: "storage", label: "Storage", icon: Database, config: "storage" },
  { id: "integrations", label: "Integrations", icon: Share2, config: "defectdojo" },
  { id: "issuetracker", label: "Issue Tracker", icon: GitPullRequest, config: "issue_tracker" },
  { id: "about", label: "About", icon: Info, config: null },
];

type Cfg = Record<string, unknown>;

function FormRawToggle({ mode, onChange }: { mode: "form" | "raw"; onChange: (m: "form" | "raw") => void }) {
  return (
    <div className="flex items-center gap-2 select-none" style={{ fontSize: "11px", letterSpacing: "0.06em" }}>
      <span style={{ color: mode === "form" ? "var(--accent)" : "var(--text-muted)", fontWeight: 600 }}>FORM</span>
      <button
        onClick={() => onChange(mode === "form" ? "raw" : "form")}
        className="relative outline-none"
        style={{
          width: "34px",
          height: "18px",
          borderRadius: "9px",
          border: "1px solid var(--border)",
          background: "var(--surface-tertiary)",
          cursor: "pointer",
        }}
        aria-label="Toggle form or raw editor"
      >
        <span
          style={{
            position: "absolute",
            top: "2px",
            left: mode === "raw" ? "17px" : "2px",
            width: "12px",
            height: "12px",
            borderRadius: "50%",
            background: "var(--accent)",
            transition: "left 0.18s ease",
          }}
        />
      </button>
      <span style={{ color: mode === "raw" ? "var(--accent)" : "var(--text-muted)", fontWeight: 600 }}>RAW</span>
    </div>
  );
}

export function SettingsView({ onBack, onRunWizard }: { onBack?: () => void; onRunWizard?: () => void }) {
  const { t } = useI18n();
  const [active, setActive] = useState<SectionId>("general");
  const [mode, setMode] = useState<"form" | "raw">("form");
  // The single source of truth for the active config-backed section.
  const [value, setValue] = useState<unknown>(null);
  const [raw, setRaw] = useState("");
  const [dirty, setDirty] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();
  const confirm = useConfirm();

  const section = SECTIONS.find((s) => s.id === active)!;
  const hasConfig = section.config !== null;
  const showRaw = hasConfig && mode === "raw";

  // Load a section's config from disk into both `value` (form) and `raw` (text).
  // Providers use the structured get_providers backend; everything else parses
  // its TOML via config_toml_to_value.
  const load = useCallback(
    async (s: Section) => {
      if (s.config === null) {
        setValue(null);
        setRaw("");
        setDirty(false);
        return;
      }
      setLoading(true);
      try {
        const T = getTransport();
        if (s.id === "providers") {
          const list = (await T.invoke<Provider[]>("get_providers")).map(normalizeProvider);
          setValue(list);
          setRaw(await T.invoke<string>("config_value_to_toml", { value: { providers: list } }));
        } else {
          const text = await T.invoke<string>("read_config", { name: s.config });
          setRaw(text);
          setValue(await T.invoke<Cfg>("config_toml_to_value", { content: text }));
        }
        setDirty(false);
      } catch (e) {
        toast({ title: "Failed to load config", description: String(e), variant: "error" });
      } finally {
        setLoading(false);
      }
    },
    [toast],
  );

  // Reload whenever the selected section changes (mode is reset to FORM by the
  // nav handler / initial state, so the effect only synchronizes with disk).
  useEffect(() => {
    // `load` sets loading state as it synchronizes the form with disk.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load(section);
  }, [section, load]);

  // Serialize the current form `value` to TOML text (provider arrays are wrapped
  // back into the [[providers]] table shape).
  async function serializeValue(v: unknown): Promise<string> {
    const T = getTransport();
    if (active === "providers") {
      return T.invoke<string>("config_value_to_toml", { value: { providers: v ?? [] } });
    }
    return T.invoke<string>("config_value_to_toml", { value: (v as Cfg) ?? {} });
  }

  // Parse raw TOML text back into a form `value`.
  async function parseToValue(text: string): Promise<unknown> {
    const T = getTransport();
    const parsed = await T.invoke<Cfg>("config_toml_to_value", { content: text });
    if (active === "providers") {
      const arr = (parsed as { providers?: Provider[] })?.providers;
      return Array.isArray(arr) ? arr : [];
    }
    return parsed ?? {};
  }

  // Lossless FORM <-> RAW switch: convert in memory, preserving unsaved edits.
  async function changeMode(m: "form" | "raw") {
    if (m === mode) return;
    try {
      if (m === "raw") {
        setRaw(await serializeValue(value));
      } else {
        setValue(await parseToValue(raw));
      }
      setMode(m);
    } catch (e) {
      toast({ title: "Conversion failed", description: String(e), variant: "error" });
    }
  }

  function onFormChange(next: unknown) {
    setValue(next);
    setDirty(true);
  }

  async function selectSection(id: SectionId) {
    if (id === active) return;
    if (dirty && !(await confirm({ title: "Discard unsaved changes?", message: "You have unsaved settings changes.", danger: true, confirmLabel: "Discard" }))) return;
    setMode("form");
    setActive(id);
  }

  async function save() {
    if (!section.config) return;
    setSaving(true);
    try {
      const T = getTransport();
      if (section.id === "providers") {
        const list = mode === "raw" ? await parseToValue(raw) : value;
        await T.invoke("set_providers", { providers: (list as Provider[]) ?? [] });
      } else {
        const content = mode === "raw" ? raw : await serializeValue(value);
        await T.invoke("write_config", { name: section.config, content });
      }
      toast({ title: "Settings saved", description: `${section.label} configuration written`, variant: "success" });
      await load(section);
    } catch (e) {
      toast({ title: "Save failed", description: String(e), variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  function renderForm() {
    const obj = value && typeof value === "object" && !Array.isArray(value) ? (value as Cfg) : {};
    switch (active) {
      case "general":
        return <GeneralTab onRunWizard={onRunWizard} />;
      case "about":
        return <AboutTab />;
      case "providers":
        return <ProvidersTab value={Array.isArray(value) ? (value as Provider[]) : []} onChange={onFormChange} />;
      case "runtime":
        return <RuntimeTab value={obj} onChange={onFormChange} />;
      case "engines":
        return <EnginesTab value={obj} onChange={onFormChange} />;
      case "guardrails":
        return <GuardrailsTab value={obj} onChange={onFormChange} />;
      case "storage":
        return <StorageTab value={obj} onChange={onFormChange} />;
      case "integrations":
        return <IntegrationsTab value={obj} onChange={onFormChange} />;
      case "issuetracker":
        return <IssueTrackerTab value={obj} onChange={onFormChange} />;
      case "session":
      case "tools":
        return <ObjectForm value={obj} onChange={onFormChange} />;
      default:
        return null;
    }
  }

  return (
    <div className="flex h-full w-full">
      {/* Left sub-nav */}
      <nav className="flex flex-col h-full bg-surface-secondary border-r border-border flex-shrink-0 select-none" style={{ width: "240px" }}>
        <div style={{ height: "28px", flexShrink: 0 }} />
        <div style={{ padding: "6px 8px 0" }}>
          <button
            onClick={onBack}
            className="flex items-center gap-2 w-full text-left rounded-md bg-transparent border border-transparent text-text-secondary hover:bg-accent-subtle hover:text-text-primary transition-all duration-150 outline-none"
            style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, cursor: "pointer" }}
          >
            <ArrowLeft size={16} />
            <span>{t("settings.back")}</span>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto" style={{ padding: "6px 8px" }}>
          {SECTIONS.map(({ id, icon: Icon }) => {
            const isActive = active === id;
            return (
              <button
                key={id}
                onClick={() => selectSection(id)}
                className={`flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none ${
                  isActive
                    ? "bg-surface-active text-text-primary border border-border"
                    : "bg-transparent text-text-secondary border border-transparent hover:bg-accent-subtle hover:text-text-primary"
                }`}
                style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, marginBottom: "2px" }}
              >
                <span style={{ color: isActive ? "var(--accent)" : "inherit", display: "flex" }}>
                  <Icon size={16} />
                </span>
                <span>{t(`settings.tab.${id}`)}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Right pane */}
      <div className="app-main flex flex-1 flex-col min-w-0">
        <header
          className="flex items-center justify-between flex-shrink-0 select-none"
          style={{ height: "52px", padding: "0 var(--space-lg)", borderBottom: "1px solid var(--border)" }}
        >
          <span
            style={{
              fontFamily: "var(--font-display)",
              fontSize: "17px",
              fontWeight: 400,
              fontStyle: "italic",
              letterSpacing: "0.01em",
              opacity: 0.9,
            }}
          >
            {t(`settings.tab.${section.id}`)}
          </span>
          <div className="flex items-center gap-4">
            {hasConfig && <FormRawToggle mode={mode} onChange={changeMode} />}
            {hasConfig && (
              <Button variant="primary" size="sm" onClick={save} disabled={!dirty || saving} loading={saving}>
                {t("settings.save")}
              </Button>
            )}
          </div>
        </header>

        <div className="flex-1 overflow-y-auto" style={{ padding: "var(--space-lg)" }}>
          {!hasConfig ? (
            renderForm()
          ) : loading ? (
            <LoadingState />
          ) : showRaw ? (
            <div className="flex flex-col h-full">
              <textarea
                value={raw}
                onChange={(e) => {
                  setRaw(e.target.value);
                  setDirty(true);
                }}
                spellCheck={false}
                className="flex-1 w-full outline-none resize-none"
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: "var(--text-primary)",
                  background: "var(--surface-code)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-md)",
                  padding: "var(--space-md)",
                  minHeight: "320px",
                  tabSize: 2,
                }}
              />
            </div>
          ) : (
            renderForm()
          )}
        </div>
      </div>
    </div>
  );
}
