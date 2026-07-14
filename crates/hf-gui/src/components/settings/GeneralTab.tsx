// ---------------------------------------------------------------------------
// GeneralTab -- Paths, Appearance, Behavior, Setup (modeled on y-agent).
// ---------------------------------------------------------------------------

import { useEffect, useState } from "react";
import { Copy, Wand2 } from "lucide-react";
import { getTransport } from "../../lib";
import { usePrefs } from "../../providers/PrefsContext";
import { useI18n, LOCALES } from "../../i18n";
import { useToast } from "../ui/Toast";
import { Button, Input, Select, Switch } from "../ui";
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
  const { locale, setLocale, t } = useI18n();
  const { toast } = useToast();
  const [configPath, setConfigPath] = useState("");
  const [dataPath, setDataPath] = useState("");

  useEffect(() => {
    getTransport()
      .invoke<{ config_dir: string; data_dir: string }>("app_paths")
      .then((p) => {
        setConfigPath(p.config_dir);
        setDataPath(p.data_dir);
      })
      .catch(() => {
        /* ignore */
      });
  }, []);

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast({ title: t("settings.general.copiedToClipboard"), variant: "success" });
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="flex flex-col" style={{ animation: "fadeIn 0.2s ease" }}>
      <SettingsGroup title={t("settings.general.paths")}>
        <SettingsItem title={t("settings.general.configDir")} stacked>
          <PathField value={configPath} onCopy={() => copy(configPath)} />
        </SettingsItem>
        <SettingsItem title={t("settings.general.dataDir")} stacked>
          <PathField value={dataPath} onCopy={() => copy(dataPath)} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.general.appearance")}>
        <SettingsItem title={t("settings.language")}>
          <Select
            value={locale}
            onChange={(v) => setLocale(v === "zh" ? "zh" : "en")}
            options={LOCALES}
            className="w-[140px]"
          />
        </SettingsItem>
        <SettingsItem title={t("settings.general.theme")}>
          <Select
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
        <SettingsItem
          title={t("settings.general.customDecorations")}
          description={t("settings.general.customDecorationsDesc")}
        >
          <Switch checked={customDecorations} onChange={setCustomDecorations} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.general.behavior")}>
        <SettingsItem
          title={t("settings.general.sendOnEnter")}
          description={t("settings.general.sendOnEnterDesc")}
        >
          <Switch checked={sendOnEnter} onChange={setSendOnEnter} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.general.sandbox")}
        description={t("settings.general.sandboxDesc")}
      >
        <SettingsItem
          title={t("settings.general.arch")}
          description={t("settings.general.archDesc")}
        >
          <Select
            value={sandboxArch}
            onChange={(v) => setSandboxArch(v === "linux/amd64" ? "linux/amd64" : "linux/arm64")}
            options={[
              { value: "linux/arm64", label: "linux/arm64" },
              { value: "linux/amd64", label: "linux/amd64 (x86)" },
            ]}
            className="w-[190px]"
          />
        </SettingsItem>
      </SettingsGroup>

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

function PathField({ value, onCopy }: { value: string; onCopy: () => void }) {
  const { t } = useI18n();
  return (
    <div className="relative flex items-center w-full">
      <Input mono readOnly value={value} title={value} className="pr-9 text-text-secondary select-all" />
      <Button variant="icon" size="sm" className="absolute right-1" onClick={onCopy} title={t("settings.general.copyPath")} aria-label={t("settings.general.copyPath")}>
        <Copy size={13} />
      </Button>
    </div>
  );
}
