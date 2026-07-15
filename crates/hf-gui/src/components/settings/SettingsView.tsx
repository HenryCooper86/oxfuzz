// Full-window Settings takeover, modeled after y-agent's SettingsPanel.
//
// This is the orchestrator. For the ACTIVE config-backed section it owns the
// single source of truth: the typed `value`, optional `raw` TOML text, the
// `mode` (form | raw), and a `dirty` flag. Generic sections keep lossless
// FORM/RAW conversion. Secret-bearing integrations deliberately use only typed
// public DTOs and explicit patches, so hidden values cannot be round-tripped or
// erased accidentally. ONE header "Save Changes" button persists the draft.

import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, Server, Database, Info, SlidersHorizontal, Share2, GitPullRequest, Crosshair, CarFront } from "lucide-react";
import { getTransport } from "../../lib";
import { useI18n } from "../../i18nContext";
import { useToast } from "../ui/toastContext";
import { useConfirm } from "../../providers/confirm";
import { Button } from "../ui/Button";
import { LoadingState } from "../ui";
import { GeneralTab } from "./GeneralTab";
import { ProvidersTab } from "./ProvidersTab";
import { normalizeProvider, type Provider } from "./providerTypes";
import { StorageTab } from "./StorageTab";
import { IntegrationsTab } from "./IntegrationsTab";
import { IssueTrackerTab } from "./IssueTrackerTab";
import { AboutTab } from "./AboutTab";
import { FuzzingTab } from "./FuzzingTab";
import { AutomotiveSettingsTab } from "./AutomotiveSettingsTab";
import {
  getAutomotiveSettings,
  setAutomotiveSettings,
  type AutomotiveSettings,
} from "../../lib/automotive";
import { SETTINGS_SECTION_DEFINITIONS, type SectionId } from "./settingsSections";
import {
  defectDojoDraftFromPublic,
  defectDojoPatchFromDraft,
  issueTrackerDraftFromPublic,
  issueTrackerPatchFromDraft,
  type DefectDojoDraft,
  type DefectDojoPublicConfig,
  type IssueTrackerDraft,
  type IssueTrackerPublicConfig,
} from "../../lib/integrationSettings";
import {
  beginSettingsSectionLoad,
  completeSettingsSectionLoad,
  confirmSettingsNavigation,
  failSettingsSectionLoad,
  isMatchingSettingsLoad,
  isSettingsSectionReady,
  type SettingsLoadToken,
  type SettingsSectionState,
} from "../../lib/settingsViewState";

interface Section {
  id: SectionId;
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  /** Raw config section name, or null when the section has no config file. */
  config: string | null;
}

const SECTION_ICONS: Record<SectionId, React.ComponentType<{ size?: number }>> = {
  general: SlidersHorizontal,
  fuzzing: Crosshair,
  automotive: CarFront,
  providers: Server,
  storage: Database,
  integrations: Share2,
  issuetracker: GitPullRequest,
  about: Info,
};

const SETTINGS_SECTIONS: readonly Section[] = SETTINGS_SECTION_DEFINITIONS.map(
  (section) => ({ ...section, icon: SECTION_ICONS[section.id] }),
);

type Cfg = Record<string, unknown>;

function FormRawToggle({ mode, onChange, disabled }: { mode: "form" | "raw"; onChange: (m: "form" | "raw") => void; disabled: boolean }) {
  const { t } = useI18n();
  return (
    <div className="flex items-center gap-2 select-none" style={{ fontSize: "11px", letterSpacing: "0.06em" }}>
      <span style={{ color: mode === "form" ? "var(--accent)" : "var(--text-muted)", fontWeight: 600 }}>{t("settings.form")}</span>
      <button
        onClick={() => onChange(mode === "form" ? "raw" : "form")}
        disabled={disabled}
        className="relative outline-none"
        style={{
          width: "34px",
          height: "18px",
          borderRadius: "9px",
          border: "1px solid var(--border)",
          background: "var(--surface-tertiary)",
          cursor: disabled ? "not-allowed" : "pointer",
          opacity: disabled ? 0.55 : 1,
        }}
        aria-label={t("settings.toggleFormRaw")}
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
      <span style={{ color: mode === "raw" ? "var(--accent)" : "var(--text-muted)", fontWeight: 600 }}>{t("settings.raw")}</span>
    </div>
  );
}

export function SettingsView({ onBack, onRunWizard }: { onBack?: () => void; onRunWizard?: () => void }) {
  const { t } = useI18n();
  const [active, setActive] = useState<SectionId>("general");
  const [mode, setMode] = useState<"form" | "raw">("form");
  // The single source of truth for the active config-backed section. The
  // section identity and request ID travel with the draft so a late response
  // can never populate (or save through) a different section.
  const [draft, setDraft] = useState<SettingsSectionState>(() =>
    beginSettingsSectionLoad(0, "general"));
  const [saving, setSaving] = useState(false);
  const loadRequestRef = useRef(0);
  const activeSectionRef = useRef<SectionId>("general");
  const { toast } = useToast();
  const confirm = useConfirm();

  const section = SETTINGS_SECTIONS.find((s) => s.id === active)!;
  const hasConfig = section.config !== null;
  const supportsRaw = hasConfig
    && active !== "automotive"
    && active !== "integrations"
    && active !== "issuetracker";
  const sectionReady = isSettingsSectionReady(draft, active);
  const showRaw = supportsRaw && mode === "raw";
  const { value, raw, dirty, loading, error } = draft;

  const isCurrentRequest = useCallback((token: SettingsLoadToken): boolean =>
    loadRequestRef.current === token.requestId
      && activeSectionRef.current === token.sectionId, []);

  // Load a section into its form draft. Providers and integrations use typed
  // service DTOs; generic config sections keep lossless FORM/RAW conversion.
  const load = useCallback(
    async (s: Section) => {
      const token: SettingsLoadToken = {
        requestId: ++loadRequestRef.current,
        sectionId: s.id,
      };
      setDraft(beginSettingsSectionLoad(token.requestId, token.sectionId));

      if (s.config === null) {
        if (isCurrentRequest(token)) {
          setDraft((current) => completeSettingsSectionLoad(current, token, null, ""));
        }
        return;
      }

      try {
        const T = getTransport();
        let nextValue: unknown;
        let nextRaw: string;
        if (s.id === "automotive") {
          nextValue = await getAutomotiveSettings(T);
          nextRaw = "";
        } else if (s.id === "providers") {
          const list = (await T.invoke<Provider[]>("get_providers")).map(normalizeProvider);
          if (!isCurrentRequest(token)) return;
          nextValue = list;
          nextRaw = await T.invoke<string>("config_value_to_toml", { value: { providers: list } });
        } else if (s.id === "integrations") {
          const config = await T.invoke<DefectDojoPublicConfig>("get_defectdojo_config");
          if (!isCurrentRequest(token)) return;
          nextValue = defectDojoDraftFromPublic(config);
          nextRaw = "";
        } else if (s.id === "issuetracker") {
          const config = await T.invoke<IssueTrackerPublicConfig>("get_issue_tracker_config");
          if (!isCurrentRequest(token)) return;
          nextValue = issueTrackerDraftFromPublic(config);
          nextRaw = "";
        } else {
          const text = await T.invoke<string>("read_config", { name: s.config });
          if (!isCurrentRequest(token)) return;
          nextRaw = text;
          nextValue = await T.invoke<Cfg>("config_toml_to_value", { content: text });
        }
        if (isCurrentRequest(token)) {
          setDraft((current) =>
            completeSettingsSectionLoad(current, token, nextValue, nextRaw));
        }
      } catch (e) {
        if (!isCurrentRequest(token)) return;
        const message = String(e);
        setDraft((current) => failSettingsSectionLoad(current, token, message));
        toast({ title: t("settings.loadFailed"), description: message, variant: "error" });
      }
    },
    [isCurrentRequest, toast, t],
  );

  // Reload whenever the selected section changes (mode is reset to FORM by the
  // nav handler / initial state, so the effect only synchronizes with disk).
  useEffect(() => {
    activeSectionRef.current = section.id;
    void load(section);
    return () => {
      loadRequestRef.current += 1;
    };
  }, [section, load]);

  // Serialize the current form `value` to TOML text (provider arrays are wrapped
  // back into the [[providers]] table shape).
  async function serializeValue(v: unknown, sectionId: SectionId): Promise<string> {
    const T = getTransport();
    if (sectionId === "providers") {
      return T.invoke<string>("config_value_to_toml", { value: { providers: v ?? [] } });
    }
    return T.invoke<string>("config_value_to_toml", { value: (v as Cfg) ?? {} });
  }

  // Parse raw TOML text back into a form `value`.
  async function parseToValue(text: string, sectionId: SectionId): Promise<unknown> {
    const T = getTransport();
    const parsed = await T.invoke<Cfg>("config_toml_to_value", { content: text });
    if (sectionId === "providers") {
      const arr = (parsed as { providers?: Provider[] })?.providers;
      return Array.isArray(arr) ? arr : [];
    }
    return parsed ?? {};
  }

  // Lossless FORM <-> RAW switch: convert in memory, preserving unsaved edits.
  async function changeMode(m: "form" | "raw") {
    if (m === mode || !sectionReady || !supportsRaw) return;
    const token: SettingsLoadToken = {
      requestId: draft.requestId,
      sectionId: active,
    };
    try {
      if (m === "raw") {
        const nextRaw = await serializeValue(value, token.sectionId);
        if (!isCurrentRequest(token)) return;
        setDraft((current) => isMatchingSettingsLoad(current, token)
          && current.loadedSection === token.sectionId
          ? { ...current, raw: nextRaw }
          : current);
      } else {
        const nextValue = await parseToValue(raw, token.sectionId);
        if (!isCurrentRequest(token)) return;
        setDraft((current) => isMatchingSettingsLoad(current, token)
          && current.loadedSection === token.sectionId
          ? { ...current, value: nextValue }
          : current);
      }
      setMode(m);
    } catch (e) {
      toast({ title: t("settings.conversionFailed"), description: String(e), variant: "error" });
    }
  }

  function onFormChange(next: unknown) {
    setDraft((current) => current.loadedSection === active
      && current.requestedSection === active
      ? { ...current, value: next, dirty: true }
      : current);
  }

  const requestDiscardConfirmation = useCallback(() => confirm({
    title: t("settings.discardTitle"),
    message: t("settings.discardMessage"),
    danger: true,
    confirmLabel: t("settings.discardConfirm"),
  }), [confirm, t]);

  async function selectSection(id: SectionId) {
    if (id === active) return;
    if (!(await confirmSettingsNavigation(dirty, requestDiscardConfirmation))) return;
    activeSectionRef.current = id;
    const invalidationId = ++loadRequestRef.current;
    setDraft(beginSettingsSectionLoad(invalidationId, id));
    setMode("form");
    setActive(id);
  }

  async function goBack() {
    if (!(await confirmSettingsNavigation(dirty, requestDiscardConfirmation))) return;
    onBack?.();
  }

  async function save() {
    if (!section.config || !sectionReady || saving) return;
    const targetSection = section;
    const targetMode = mode;
    const targetValue = value;
    const targetRaw = raw;
    const token: SettingsLoadToken = {
      requestId: draft.requestId,
      sectionId: targetSection.id,
    };
    setSaving(true);
    try {
      const T = getTransport();
      if (targetSection.id === "automotive") {
        await setAutomotiveSettings(targetValue as AutomotiveSettings, T);
      } else if (targetSection.id === "providers") {
        const list = targetMode === "raw"
          ? await parseToValue(targetRaw, targetSection.id)
          : targetValue;
        await T.invoke("set_providers", { providers: (list as Provider[]) ?? [] });
      } else if (targetSection.id === "integrations") {
        await T.invoke("patch_defectdojo_config", {
          patch: defectDojoPatchFromDraft(targetValue as DefectDojoDraft),
        });
      } else if (targetSection.id === "issuetracker") {
        await T.invoke("patch_issue_tracker_config", {
          patch: issueTrackerPatchFromDraft(targetValue as IssueTrackerDraft),
        });
      } else {
        const content = targetMode === "raw"
          ? targetRaw
          : await serializeValue(targetValue, targetSection.id);
        await T.invoke("write_config", { name: targetSection.config, content });
      }
      toast({ title: t("settings.saved"), description: t("settings.savedDesc", { section: t(`settings.tab.${targetSection.id}`) }), variant: "success" });
      if (isCurrentRequest(token)) {
        await load(targetSection);
      }
    } catch (e) {
      toast({ title: t("settings.saveFailed"), description: String(e), variant: "error" });
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
      case "fuzzing":
        return <FuzzingTab value={obj} onChange={onFormChange} />;
      case "automotive":
        return (
          <AutomotiveSettingsTab
            value={value as AutomotiveSettings}
            onChange={onFormChange}
          />
        );
      case "storage":
        return <StorageTab />;
      case "integrations":
        return <IntegrationsTab value={value as DefectDojoDraft} onChange={onFormChange} />;
      case "issuetracker":
        return <IssueTrackerTab value={value as IssueTrackerDraft} onChange={onFormChange} />;
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
            onClick={() => void goBack()}
            className="flex items-center gap-2 w-full text-left rounded-md bg-transparent border border-transparent text-text-secondary hover:bg-accent-subtle hover:text-text-primary transition-all duration-150 outline-none"
            style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, cursor: "pointer" }}
          >
            <ArrowLeft size={16} />
            <span>{t("settings.back")}</span>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto" style={{ padding: "6px 8px" }}>
          {SETTINGS_SECTIONS.map(({ id, icon: Icon }) => {
            const isActive = active === id;
            return (
              <button
                key={id}
                onClick={() => void selectSection(id)}
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
            {supportsRaw && <FormRawToggle mode={mode} onChange={changeMode} disabled={!sectionReady || saving} />}
            {hasConfig && (
              <Button variant="primary" size="sm" onClick={save} disabled={!sectionReady || !dirty || saving} loading={saving}>
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
          ) : !sectionReady ? (
            <div role="alert" className="text-text-secondary" style={{ fontSize: "13px" }}>
              {error ?? t("settings.loadFailed")}
            </div>
          ) : showRaw ? (
            <div className="flex flex-col h-full">
              <textarea
                value={raw}
                onChange={(e) => {
                  const nextRaw = e.target.value;
                  setDraft((current) => current.loadedSection === active
                    && current.requestedSection === active
                    ? { ...current, raw: nextRaw, dirty: true }
                    : current);
                }}
                disabled={!sectionReady || saving}
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
