// ---------------------------------------------------------------------------
// GeneralTab -- Paths, Appearance, Behavior, Setup (modeled on y-agent).
// ---------------------------------------------------------------------------

import { useEffect, useState } from "react";
import { Copy, Wand2 } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../../lib";
import { usePrefs } from "../../providers/prefs";
import { LOCALES, useI18n } from "../../i18nContext";
import { useToast } from "../ui/toastContext";
import { Button, Input, Select, Switch } from "../ui";
import { SandboxSetup } from "../wizard/SandboxSetup";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";

export function GeneralTab({ onRunWizard }: { onRunWizard?: () => void }) {
  const {
    theme,
    setTheme,
    fontSize,
    setFontSize,
    sendOnEnter,
    setSendOnEnter,
    customDecorations,
    setCustomDecorations,
    sandboxArch,
    setSandboxArch,
  } = usePrefs();
  const [preparing, setPreparing] = useState(false);
  const desktop = isTauriEnvironment();
  const [pathError, setPathError] = useState(false);
  const { locale, setLocale, t } = useI18n();
  const { toast } = useToast();
  const [configPath, setConfigPath] = useState("");
  const [dataPath, setDataPath] = useState("");

  useEffect(() => {
    if (!desktop) return;
    getTransport()
      .invoke<{ config_dir: string; data_dir: string }>("app_paths")
      .then((p) => {
        setConfigPath(p.config_dir);
        setDataPath(p.data_dir);
      })
      .catch(() => {
        setPathError(true);
      });
  }, [desktop]);

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast({ title: t("settings.general.copiedToClipboard"), variant: "success" });
    } catch {
      toast({ title: t("gui.copyFailed"), variant: "error" });
    }
  }

  return (
    <div className="flex flex-col" style={{ animation: "fadeIn 0.2s ease" }}>
      {!desktop && <p className="text-sm text-text-secondary mb-4">{t("gui.serverSettings")}</p>}
      {pathError && <p role="alert">{t("gui.pathsFailed")}</p>}
      {desktop && <SettingsGroup title={t("settings.general.paths")}>
        <SettingsItem title={t("settings.general.configDir")} stacked>
          <PathField label={t("settings.general.configDir")} value={configPath} onCopy={() => copy(configPath)} />
        </SettingsItem>
        <SettingsItem title={t("settings.general.dataDir")} stacked>
          <PathField label={t("settings.general.dataDir")} value={dataPath} onCopy={() => copy(dataPath)} />
        </SettingsItem>
      </SettingsGroup>}

      <SettingsGroup title={t("settings.general.appearance")}>
        <SettingsItem title={t("settings.language")}>
          <Select
            ariaLabel={t("settings.language")}
            value={locale}
            onChange={(v) => setLocale(v === "zh" ? "zh" : "en")}
            options={LOCALES}
            className="w-[140px]"
          />
        </SettingsItem>
        <SettingsItem title={t("settings.general.theme")}>
          <Select
            ariaLabel={t("settings.general.theme")}
            value={theme}
            onChange={(v) => setTheme(v === "light" ? "light" : "dark")}
            options={[
              { value: "dark", label: t("settings.general.themeDark") },
              { value: "light", label: t("settings.general.themeLight") },
            ]}
            className="w-[140px]"
          />
        </SettingsItem>
        <SettingsItem title={t("settings.general.fontSize")}>
          <div className="flex items-center gap-3">
            <input
              aria-label={t("settings.general.fontSize")}
              type="range"
              min={12}
              max={20}
              value={fontSize}
              onChange={(e) => setFontSize(Number(e.target.value))}
              style={{ accentColor: "var(--accent)", width: "160px" }}
            />
            <span className="text-xs text-text-secondary" style={{ width: "34px", textAlign: "right" }}>
              {fontSize}px
            </span>
          </div>
        </SettingsItem>
        {desktop && <SettingsItem
          title={t("settings.general.customDecorations")}
          description={t("settings.general.customDecorationsDesc")}
        >
          <Switch ariaLabel={t("settings.general.customDecorations")} checked={customDecorations} onChange={setCustomDecorations} />
        </SettingsItem>}
      </SettingsGroup>

      <SettingsGroup title={t("settings.general.behavior")}>
        <SettingsItem
          title={t("settings.general.sendOnEnter")}
          description={t("settings.general.sendOnEnterDesc")}
        >
          <Switch ariaLabel={t("settings.general.sendOnEnter")} checked={sendOnEnter} onChange={setSendOnEnter} />
        </SettingsItem>
      </SettingsGroup>

      {desktop && <SettingsGroup
        title={t("settings.general.sandbox")}
        description={t("settings.general.sandboxDesc")}
      >
        <SettingsItem
          title={t("settings.general.arch")}
          description={t("gui.prepareHere")}
        >
          <Select
            disabled={preparing}
            ariaLabel={t("settings.general.arch")}
            value={sandboxArch}
            onChange={(v) => setSandboxArch(v === "linux/amd64" ? "linux/amd64" : "linux/arm64")}
            options={[
              { value: "linux/arm64", label: "linux/arm64" },
              { value: "linux/amd64", label: "linux/amd64 (x86)" },
            ]}
            className="w-[190px]"
          />
        </SettingsItem>
        <div className="p-3"><SandboxSetup key={sandboxArch} allowPrepareReady onBusyChange={setPreparing} /></div>
      </SettingsGroup>}

      <SettingsGroup
        title={t("settings.general.setup")}
        description={t("settings.general.setupDesc")}
      >
        <SettingsItem title={t("settings.general.setupWizard")}>
          <Button variant="outline" onClick={onRunWizard}>
            <Wand2 size={14} />
            {t("settings.general.runWizard")}
          </Button>
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}

function PathField({ value, onCopy, label }: { value: string; onCopy: () => void; label: string }) {
  const { t } = useI18n();
  return (
    <div className="relative flex items-center w-full">
      <Input aria-label={label} mono readOnly value={value} title={value} className="pr-9 text-text-secondary select-all" />
      <Button disabled={!value || value === "<redacted-path>"} variant="icon" size="sm" className="absolute right-1" onClick={onCopy} title={t("settings.general.copyPath")} aria-label={t("settings.general.copyPath")}>
        <Copy size={13} />
      </Button>
    </div>
  );
}
