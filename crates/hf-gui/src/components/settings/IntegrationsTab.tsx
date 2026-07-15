// Integrations settings -- external systems hobot_fuzz can push findings to.
//
// Currently DefectDojo: SettingsView loads a public typed DTO and saves an
// explicit typed patch, preserving protected values unless the operator chooses
// replace or clear. This tab also tests the saved URL/token against the live API.

import { useState } from "react";
import { AppWindow, ExternalLink } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../../lib";
import type { DefectDojoDraft } from "../../lib/integrationSettings";
import { useI18n } from "../../i18nContext";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Switch } from "../ui/Switch";
import { ProtectedValueEditor } from "./ProtectedValueEditor";

export function IntegrationsTab({ value, onChange }: { value: DefectDojoDraft; onChange: (next: DefectDojoDraft) => void }) {
  const { t } = useI18n();
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const url = value.url.trim();
  const hasUrl = url.length > 0 && !url.includes("example.com");

  async function testConnection() {
    setTesting(true);
    setResult(null);
    try {
      await getTransport().invoke("defectdojo_test_connection");
      setResult({ ok: true, msg: t("settings.integrations.connected") });
    } catch (e) {
      setResult({ ok: false, msg: String(e) });
    } finally {
      setTesting(false);
    }
  }

  // Open the DefectDojo web UI to log in / browse findings. In the desktop app,
  // inBrowser=false opens a dedicated in-app window; inBrowser=true (or web mode)
  // hands off to the external browser.
  async function openDojo(inBrowser: boolean) {
    if (!hasUrl) return;
    if (isTauriEnvironment()) {
      try {
        await getTransport().invoke("open_defectdojo", { inBrowser });
      } catch (e) {
        setResult({ ok: false, msg: String(e) });
      }
    } else {
      window.open(url, "_blank", "noopener");
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="text-text-secondary" style={{ fontSize: "13px", lineHeight: 1.6 }}>
        <p>
          {t("settings.integrations.p1a")}<strong>DefectDojo</strong>{t("settings.integrations.p1b")}
          <code>url</code>{t("settings.integrations.p1c")}
          <code>api_token</code>{t("settings.integrations.p1d")}
          <code>api_token_env</code>{t("settings.integrations.p1e")}
          <code>api_token</code>{t("settings.integrations.p1f")}
        </p>
      </div>

      <SettingsGroup title={t("settings.integrations.connection") }>
        <SettingsItem title={t("settings.integrations.url")}>
          <Input
            aria-label={t("settings.integrations.url")}
            className="w-[320px]"
            mono
            placeholder="https://defectdojo.example.test"
            value={value.url}
            onChange={(event) => onChange({ ...value, url: event.target.value })}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.apiToken")} description={t("settings.integrations.apiTokenDesc")}>
          <ProtectedValueEditor
            secret
            value={value.api_token}
            onChange={(apiToken) => onChange({ ...value, api_token: apiToken })}
            placeholder={t("settings.integrations.apiToken")}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.apiTokenEnv")} description={t("settings.integrations.apiTokenEnvDesc")}>
          <ProtectedValueEditor
            value={value.api_token_env}
            onChange={(apiTokenEnv) => onChange({ ...value, api_token_env: apiTokenEnv })}
            placeholder="DEFECTDOJO_API_TOKEN"
          />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.verifyTls")}>
          <Switch
            ariaLabel={t("settings.integrations.verifyTls")}
            checked={value.verify_tls}
            onChange={(verifyTls) => onChange({ ...value, verify_tls: verifyTls })}
          />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.integrations.destination")}>
        <SettingsItem title={t("settings.integrations.productName")}>
          <Input className="w-[260px]" value={value.product_name} onChange={(event) => onChange({ ...value, product_name: event.target.value })} />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.productTypeName")}>
          <Input className="w-[260px]" value={value.product_type_name} onChange={(event) => onChange({ ...value, product_type_name: event.target.value })} />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.engagementName")}>
          <Input className="w-[260px]" value={value.engagement_name} onChange={(event) => onChange({ ...value, engagement_name: event.target.value })} />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.autoCreate")}>
          <Switch ariaLabel={t("settings.integrations.autoCreate")} checked={value.auto_create} onChange={(autoCreate) => onChange({ ...value, auto_create: autoCreate })} />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.reimport")}>
          <Switch ariaLabel={t("settings.integrations.reimport")} checked={value.reimport} onChange={(reimport) => onChange({ ...value, reimport })} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.integrations.lifecycle")} description={t("settings.integrations.lifecycleDesc")}>
        <SettingsItem title={t("settings.integrations.autostart")}>
          <Switch
            ariaLabel={t("settings.integrations.autostart")}
            checked={value.lifecycle.autostart}
            onChange={(autostart) => onChange({ ...value, lifecycle: { ...value.lifecycle, autostart } })}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.composeProject")}>
          <ProtectedValueEditor
            value={value.lifecycle.compose_project}
            onChange={(composeProject) => onChange({
              ...value,
              lifecycle: { ...value.lifecycle, compose_project: composeProject },
            })}
            placeholder={t("settings.integrations.composeProject")}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.composeFiles")} description={t("settings.integrations.composeFilesDesc")}>
          <ProtectedValueEditor
            multiline
            value={value.lifecycle.compose_files}
            onChange={(composeFiles) => onChange({ ...value, lifecycle: { ...value.lifecycle, compose_files: composeFiles } })}
            placeholder={t("settings.integrations.composeFilesPlaceholder")}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.integrations.startupTimeout")}>
          <Input
            aria-label={t("settings.integrations.startupTimeout")}
            className="w-[120px]"
            min={1}
            type="number"
            value={value.lifecycle.startup_timeout_secs ?? ""}
            onChange={(event) => onChange({
              ...value,
              lifecycle: {
                ...value.lifecycle,
                startup_timeout_secs: event.target.value ? Number(event.target.value) : null,
              },
            })}
          />
        </SettingsItem>
      </SettingsGroup>

      <div className="flex items-center gap-3 flex-wrap">
        <Button
          variant="outline"
          size="sm"
          onClick={() => void testConnection()}
          loading={testing}
          disabled={testing}
        >
          {t("settings.testConnection")}
        </Button>
        <Button
          variant="primary"
          size="sm"
          onClick={() => void openDojo(false)}
          disabled={!hasUrl}
          title={hasUrl ? t("settings.integrations.openDojoTitle") : t("settings.integrations.setUrlFirst")}
        >
          <AppWindow size={14} />
          {t("settings.integrations.openDojo")}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void openDojo(true)}
          disabled={!hasUrl}
          title={t("settings.integrations.openDojoBrowserTitle")}
        >
          <ExternalLink size={14} />
          {t("common.openInBrowser")}
        </Button>
        {result && (
          <span
            role="status"
            style={{
              fontSize: "12px",
              color: result.ok ? "var(--success, #10b981)" : "var(--danger, #ef4444)",
            }}
          >
            {result.msg}
          </span>
        )}
      </div>
      <p className="text-text-muted" style={{ fontSize: "11px" }}>
        {t("settings.testNotePre")}<strong>{t("settings.testSaved")}</strong>{t("settings.testNotePost")}
      </p>
    </div>
  );
}
