// Notifications settings -- webhook alerts for crashes found by unattended
// campaigns. Reads and writes the `notifications` config section through the
// generic config commands. The bearer token is write-only: the stored value is
// held outside the rendered draft and is written back only when left unchanged.

import { useCallback, useEffect, useRef, useState } from "react";
import { getTransport } from "../../lib";
import {
  notificationsConfigFromDraft,
  notificationsDraftFromConfig,
  type NotificationsConfig,
  type NotificationsDraft,
  type WebhookFormat,
} from "../../lib/paritySettings";
import { useI18n } from "../../i18nContext";
import { useProject } from "../../providers/project";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Select } from "../ui/Select";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Switch } from "../ui/Switch";
import { ProtectedValueEditor } from "./ProtectedValueEditor";

type Status = { ok: boolean; message: string } | null;

function StatusLine({ status }: { status: Status }) {
  if (!status) return null;
  return (
    <span role={status.ok ? "status" : "alert"} className="text-xs" style={{ color: status.ok ? "var(--success, #10b981)" : "var(--danger, #ef4444)" }}>
      {status.message}
    </span>
  );
}

export function NotificationsTab() {
  const { t } = useI18n();
  const { activeProject } = useProject();
  const [draft, setDraft] = useState<NotificationsDraft | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState<Status>(null);
  const [testing, setTesting] = useState(false);
  const [testStatus, setTestStatus] = useState<Status>(null);
  const [target, setTarget] = useState("");
  const [alerting, setAlerting] = useState(false);
  const [alertStatus, setAlertStatus] = useState<Status>(null);
  // The stored token, kept out of the rendered draft.
  const storedToken = useRef<string | undefined>(undefined);

  const load = useCallback(async () => {
    try {
      const T = getTransport();
      const text = await T.invoke<string>("read_config", { name: "notifications" });
      const config = await T.invoke<NotificationsConfig>("config_toml_to_value", { content: text });
      storedToken.current = typeof config?.bearer_token === "string" ? config.bearer_token : undefined;
      setDraft(notificationsDraftFromConfig(config ?? {}));
      setLoadError(null);
    } catch (e) {
      setLoadError(t("notif.loadFailed", { error: String(e) }));
    }
  }, [t]);

  useEffect(() => {
    queueMicrotask(() => void load());
  }, [load]);

  async function save() {
    if (!draft || saving) return;
    setSaving(true);
    setSaveStatus(null);
    try {
      const T = getTransport();
      const config = notificationsConfigFromDraft(draft, storedToken.current);
      const content = await T.invoke<string>("config_value_to_toml", { value: config });
      await T.invoke("write_config", { name: "notifications", content });
      setSaveStatus({ ok: true, message: t("notif.saved") });
      await load();
    } catch (e) {
      setSaveStatus({ ok: false, message: t("notif.saveFailed", { error: String(e) }) });
    } finally {
      setSaving(false);
    }
  }

  async function sendTest() {
    setTesting(true);
    setTestStatus(null);
    try {
      await getTransport().invoke("notifications_test");
      setTestStatus({ ok: true, message: t("notif.testSent") });
    } catch (e) {
      setTestStatus({ ok: false, message: String(e) });
    } finally {
      setTesting(false);
    }
  }

  async function sendAlert() {
    const name = target.trim();
    if (!activeProject || !name) return;
    setAlerting(true);
    setAlertStatus(null);
    try {
      const count = await getTransport().invoke<number>("notify_latest_run", { project: activeProject, target: name });
      setAlertStatus(count > 0
        ? { ok: true, message: t("notif.alertSent", { count }) }
        : { ok: true, message: t("notif.alertNone") });
    } catch (e) {
      setAlertStatus({ ok: false, message: String(e) });
    } finally {
      setAlerting(false);
    }
  }

  function update(patch: Partial<NotificationsDraft>) {
    setDraft((current) => (current ? { ...current, ...patch } : current));
    setSaveStatus(null);
  }

  if (loadError) {
    return <div role="alert" className="text-sm" style={{ color: "var(--danger, #ef4444)" }}>{loadError}</div>;
  }
  if (!draft) return <div className="text-xs text-text-muted">{t("common.loading")}</div>;

  return (
    <div className="flex flex-col gap-4">
      <p className="text-text-secondary" style={{ fontSize: "13px", lineHeight: 1.6 }}>{t("notif.intro")}</p>

      <SettingsGroup title={t("notif.connection")}>
        <SettingsItem title={t("notif.url")} description={t("notif.urlDesc")}>
          <Input
            aria-label={t("notif.url")}
            className="w-[320px]"
            mono
            placeholder="https://hooks.example.test/alerts"
            value={draft.webhook_url}
            onChange={(event) => update({ webhook_url: event.target.value })}
          />
        </SettingsItem>
        <SettingsItem title={t("notif.format")}>
          <Select
            ariaLabel={t("notif.format")}
            value={draft.format}
            onChange={(format) => update({ format: format as WebhookFormat })}
            options={[
              { value: "json", label: t("notif.formatJson") },
              { value: "slack", label: t("notif.formatSlack") },
            ]}
          />
        </SettingsItem>
        <SettingsItem title={t("notif.token")} description={t("notif.tokenDesc")}>
          <ProtectedValueEditor
            secret
            value={draft.bearer_token}
            onChange={(bearer_token) => update({ bearer_token })}
            placeholder={t("notif.token")}
          />
        </SettingsItem>
        <SettingsItem title={t("notif.tokenEnv")} description={t("notif.tokenEnvDesc")}>
          <Input
            aria-label={t("notif.tokenEnv")}
            className="w-[260px]"
            mono
            placeholder="OXFUZZ_WEBHOOK_TOKEN"
            value={draft.bearer_token_env}
            onChange={(event) => update({ bearer_token_env: event.target.value })}
          />
        </SettingsItem>
        <SettingsItem title={t("notif.verifyTls")}>
          <Switch ariaLabel={t("notif.verifyTls")} checked={draft.verify_tls} onChange={(verify_tls) => update({ verify_tls })} />
        </SettingsItem>
      </SettingsGroup>

      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="primary" size="sm" onClick={() => void save()} loading={saving} disabled={saving}>
          {t("notif.save")}
        </Button>
        <StatusLine status={saveStatus} />
      </div>

      <SettingsGroup title={t("notif.testTitle")} description={t("notif.testDesc")}>
        <SettingsItem title={t("notif.sendTest")}>
          <div className="flex items-center gap-3 flex-wrap">
            <Button variant="outline" size="sm" onClick={() => void sendTest()} loading={testing} disabled={testing}>
              {t("notif.sendTest")}
            </Button>
            <StatusLine status={testStatus} />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("notif.latestTitle")} description={activeProject ? t("notif.latestDesc") : t("notif.noProject")}>
        <SettingsItem title={t("notif.target")}>
          <div className="flex items-center gap-3 flex-wrap">
            <Input
              aria-label={t("notif.target")}
              className="w-[220px]"
              mono
              placeholder={t("notif.targetPlaceholder")}
              value={target}
              onChange={(event) => setTarget(event.target.value)}
            />
            <Button variant="outline" size="sm" onClick={() => void sendAlert()} loading={alerting} disabled={alerting || !activeProject || !target.trim()}>
              {t("notif.sendAlert")}
            </Button>
            <StatusLine status={alertStatus} />
          </div>
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}
