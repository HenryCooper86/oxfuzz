// Issue-tracker settings -- file crash issues into the FUZZED project's repo.
//
// SettingsView loads a public typed DTO and saves an explicit typed patch,
// preserving protected values unless the operator chooses replace or clear.
// This tab also tests the saved host/token and links to a safe visible repo.

import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { getTransport, openExternal } from "../../lib";
import type { IssueTrackerDraft } from "../../lib/integrationSettings";
import { useI18n } from "../../i18nContext";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Select } from "../ui/Select";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Switch } from "../ui/Switch";
import { ProtectedValueEditor } from "./ProtectedValueEditor";

export function IssueTrackerTab({ value, onChange }: { value: IssueTrackerDraft; onChange: (next: IssueTrackerDraft) => void }) {
  const { t } = useI18n();
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const provider = value.provider.trim().toLowerCase();
  const repo = (
    value.repo.change === "clear"
      ? ""
      : value.repo.change === "replace"
        ? value.repo.replacement
        : value.repo.current ?? ""
  ).trim();
  const host = value.host.trim();
  const configured = (provider === "github" || provider === "gitlab") && repo.length > 0;

  const providerLabel = provider === "github" ? "GitHub" : provider === "gitlab" ? "GitLab" : t("settings.issuetracker.theTracker");
  const defaultHost = provider === "github" ? "https://github.com" : "https://gitlab.com";
  const repoUrl = configured ? `${(host || defaultHost).replace(/\/$/, "")}/${repo.replace(/^\/|\/$/g, "")}` : "";

  async function testConnection() {
    setTesting(true);
    setResult(null);
    try {
      await getTransport().invoke("issue_tracker_test_connection");
      setResult({ ok: true, msg: t("settings.issuetracker.authenticated", { provider: providerLabel }) });
    } catch (e) {
      setResult({ ok: false, msg: String(e) });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="text-text-secondary" style={{ fontSize: "13px", lineHeight: 1.6 }}>
        <p>
          {t("settings.issuetracker.p1a")}<strong>{t("settings.issuetracker.fuzzedProject")}</strong>{t("settings.issuetracker.p1b")}
          <code>provider</code>{t("settings.issuetracker.p1c")}<code>github</code>{t("settings.issuetracker.p1d")}<code>gitlab</code>{t("settings.issuetracker.p1e")}
          <code>repo</code>{t("settings.issuetracker.p1f")}<code>owner/repo</code>{t("settings.issuetracker.p1g")}
          <code>group/project</code>{t("settings.issuetracker.p1h")}<code>host</code>{t("settings.issuetracker.p1i")}
        </p>
        <p style={{ marginTop: 8 }}>
          {t("settings.issuetracker.p2a")}<strong>{t("settings.issuetracker.pat")}</strong>{t("settings.issuetracker.p2b")}<code>api_token</code>
          {t("settings.issuetracker.p2c")}<code>api_token_env</code>
          {t("settings.issuetracker.p2d")}<code>repo</code>{t("settings.issuetracker.p2e")}<code>api</code>{t("settings.issuetracker.p2f")}
          <code>username</code>{t("settings.issuetracker.p2g")}
        </p>
      </div>

      <SettingsGroup title={t("settings.issuetracker.repository") }>
        <SettingsItem title={t("settings.issuetracker.provider")}>
          <Select
            className="w-[220px]"
            value={value.provider}
            onChange={(nextProvider) => onChange({ ...value, provider: nextProvider })}
            options={[
              { value: "none", label: t("settings.issuetracker.disabled") },
              { value: "github", label: "GitHub" },
              { value: "gitlab", label: "GitLab" },
            ]}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.issuetracker.host")} description={t("settings.issuetracker.hostDesc")}>
          <Input className="w-[320px]" mono value={value.host} onChange={(event) => onChange({ ...value, host: event.target.value })} placeholder={defaultHost} />
        </SettingsItem>
        <SettingsItem title={t("settings.issuetracker.repo")} description={t("settings.issuetracker.repoDesc")}>
          <ProtectedValueEditor
            value={value.repo}
            onChange={(repoDraft) => onChange({ ...value, repo: repoDraft })}
            placeholder="owner/repository"
          />
        </SettingsItem>
        <SettingsItem title={t("settings.issuetracker.username")} description={t("settings.issuetracker.usernameDesc")}>
          <Input className="w-[260px]" value={value.username} onChange={(event) => onChange({ ...value, username: event.target.value })} />
        </SettingsItem>
        <SettingsItem title={t("settings.issuetracker.labels")} description={t("settings.issuetracker.labelsDesc")}>
          <Input
            className="w-[320px]"
            mono
            value={value.labels.join(", ")}
            onChange={(event) => onChange({
              ...value,
              labels: event.target.value.split(",").map((label) => label.trim()).filter(Boolean),
            })}
          />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.issuetracker.authentication") }>
        <SettingsItem title={t("settings.issuetracker.apiToken")} description={t("settings.issuetracker.apiTokenDesc")}>
          <ProtectedValueEditor
            secret
            value={value.api_token}
            onChange={(apiToken) => onChange({ ...value, api_token: apiToken })}
            placeholder={t("settings.issuetracker.apiToken")}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.issuetracker.apiTokenEnv")} description={t("settings.issuetracker.apiTokenEnvDesc")}>
          <ProtectedValueEditor
            value={value.api_token_env}
            onChange={(apiTokenEnv) => onChange({ ...value, api_token_env: apiTokenEnv })}
            placeholder={provider === "github" ? "GITHUB_TOKEN" : "GITLAB_TOKEN"}
          />
        </SettingsItem>
        <SettingsItem title={t("settings.issuetracker.verifyTls")}>
          <Switch ariaLabel={t("settings.issuetracker.verifyTls")} checked={value.verify_tls} onChange={(verifyTls) => onChange({ ...value, verify_tls: verifyTls })} />
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
          variant="ghost"
          size="sm"
          onClick={() => void openExternal(repoUrl)}
          disabled={!configured}
          title={configured ? t("settings.issuetracker.openRepoTitle") : t("settings.issuetracker.setProviderFirst")}
        >
          <ExternalLink size={14} />
          {t("settings.issuetracker.openRepo")}
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
