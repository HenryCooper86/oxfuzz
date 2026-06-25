// Full-window Settings takeover, modeled after y-agent's SettingsPanel:
// a left sub-nav (with Back) and a right pane whose action bar carries the
// italic section title, a FORM/RAW toggle, and a gold Save Changes button.

import { useState } from "react";
import { ArrowLeft, Server, HardDrive, Crosshair, Shield, Database, Info, SlidersHorizontal, MessageSquare, Wrench } from "lucide-react";
import { getTransport } from "../../lib";
import { useToast } from "../ui/Toast";
import { Button } from "../ui/Button";
import { GeneralTab } from "./GeneralTab";
import { ProvidersTab } from "./ProvidersTab";
import { RuntimeTab } from "./RuntimeTab";
import { EnginesTab } from "./EnginesTab";
import { GuardrailsTab } from "./GuardrailsTab";
import { StorageTab } from "./StorageTab";
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
  | "about";

interface Section {
  id: SectionId;
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  /** Raw config section name, or null when the section has no config file. */
  config: string | null;
  /** Whether the section has a dedicated form view (else it is raw-only). */
  form: boolean;
}

const SECTIONS: Section[] = [
  { id: "general", label: "General", icon: SlidersHorizontal, config: null, form: true },
  { id: "providers", label: "Providers", icon: Server, config: "providers", form: true },
  { id: "session", label: "Session", icon: MessageSquare, config: "session", form: false },
  { id: "runtime", label: "Runtime", icon: HardDrive, config: "runtime", form: true },
  { id: "engines", label: "Engines", icon: Crosshair, config: "engines", form: true },
  { id: "tools", label: "Tools", icon: Wrench, config: "tools", form: false },
  { id: "guardrails", label: "Guardrails", icon: Shield, config: "guardrails", form: true },
  { id: "storage", label: "Storage", icon: Database, config: "storage", form: true },
  { id: "about", label: "About", icon: Info, config: null, form: true },
];

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

function renderForm(id: SectionId, onRunWizard?: () => void) {
  switch (id) {
    case "general":
      return <GeneralTab onRunWizard={onRunWizard} />;
    case "providers":
      return <ProvidersTab />;
    case "runtime":
      return <RuntimeTab />;
    case "engines":
      return <EnginesTab />;
    case "guardrails":
      return <GuardrailsTab />;
    case "storage":
      return <StorageTab />;
    case "about":
      return <AboutTab />;
    default:
      return null;
  }
}

export function SettingsView({ onBack, onRunWizard }: { onBack?: () => void; onRunWizard?: () => void }) {
  const [active, setActive] = useState<SectionId>("general");
  const [mode, setMode] = useState<"form" | "raw">("form");
  const [raw, setRaw] = useState("");
  const [rawDirty, setRawDirty] = useState(false);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const section = SECTIONS.find((s) => s.id === active)!;
  const hasConfig = section.config !== null;
  const hasForm = section.form;
  // Raw-only sections (config present but no form) always show the editor.
  const showRaw = hasConfig && (!hasForm || mode === "raw");

  // Load the raw TOML for a section. Called from the user actions that can
  // reveal the raw editor (toggling to RAW, or switching section while in
  // RAW) -- no effect needed since it is purely event-driven.
  async function loadRaw(configName: string) {
    setLoading(true);
    setRawDirty(false);
    try {
      setRaw(await getTransport().invoke<string>("read_config", { name: configName }));
    } catch (e) {
      toast({ title: "Failed to load config", description: String(e), variant: "error" });
    } finally {
      setLoading(false);
    }
  }

  function changeMode(m: "form" | "raw") {
    setMode(m);
    if (m === "raw" && section.config) void loadRaw(section.config);
  }

  async function saveRaw() {
    if (!section.config) return;
    try {
      await getTransport().invoke("write_config", { name: section.config, content: raw });
      setRawDirty(false);
      toast({ title: "Saved", description: `${section.label} config written`, variant: "success" });
    } catch (e) {
      toast({ title: "Save failed", description: String(e), variant: "error" });
    }
  }

  function selectSection(id: SectionId) {
    setActive(id);
    const next = SECTIONS.find((s) => s.id === id);
    if (!next) return;
    if (next.config === null) {
      // Form-only section (no config file).
      setMode("form");
    } else if (!next.form) {
      // Raw-only section -- load its TOML immediately.
      void loadRaw(next.config);
    } else if (mode === "raw") {
      void loadRaw(next.config);
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
            className="flex items-center gap-2 w-full text-left rounded-md text-text-secondary hover:bg-accent-subtle hover:text-text-primary transition-all duration-150 outline-none"
            style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500 }}
          >
            <ArrowLeft size={18} />
            <span>Back</span>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto" style={{ padding: "6px 8px" }}>
          {SECTIONS.map(({ id, label, icon: Icon }) => {
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
                <span>{label}</span>
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
            {section.label}
          </span>
          <div className="flex items-center gap-4">
            {hasForm && hasConfig && <FormRawToggle mode={mode} onChange={changeMode} />}
            {showRaw && (
              <Button variant="primary" size="sm" onClick={saveRaw} disabled={!rawDirty}>
                Save Changes
              </Button>
            )}
          </div>
        </header>

        <div className="flex-1 overflow-y-auto" style={{ padding: "var(--space-lg)" }}>
          {showRaw ? (
            <div className="flex flex-col h-full">
              {loading ? (
                <div className="text-text-muted text-sm" style={{ padding: "var(--space-md)" }}>
                  Loading…
                </div>
              ) : (
                <textarea
                  value={raw}
                  onChange={(e) => {
                    setRaw(e.target.value);
                    setRawDirty(true);
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
              )}
            </div>
          ) : (
            renderForm(active, onRunWizard)
          )}
        </div>
      </div>
    </div>
  );
}
