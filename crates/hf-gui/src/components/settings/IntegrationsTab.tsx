// Integrations settings -- external systems hobot_fuzz can push findings to.
//
// Currently DefectDojo: the section is config-backed (config/defectdojo.toml),
// so the orchestrator handles load/save via the generic ObjectForm. This tab
// adds context plus a "Test connection" button that validates the *saved* URL +
// token against the live DefectDojo API.

import { useState } from "react";
import { AppWindow, ExternalLink } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../../lib";
import { useI18n } from "../../i18n";
import { Button } from "../ui/Button";
import { ObjectForm } from "./ObjectForm";

type Cfg = Record<string, unknown>;

export function IntegrationsTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const { t } = useI18n();
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const url = typeof value.url === "string" ? value.url.trim() : "";
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

      <ObjectForm value={value} onChange={onChange} />

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
