// Issue-tracker settings -- file crash issues into the FUZZED project's repo.
//
// Config-backed (config/issue_tracker.toml), so the orchestrator handles
// load/save via the generic ObjectForm. This tab adds context plus a "Test
// connection" button that validates the *saved* host + token against the live
// GitHub/GitLab API, and a link to open the target repo.

import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { getTransport, openExternal } from "../../lib";
import { useI18n } from "../../i18n";
import { Button } from "../ui/Button";
import { ObjectForm } from "./ObjectForm";

type Cfg = Record<string, unknown>;

export function IssueTrackerTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const { t } = useI18n();
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const provider = typeof value.provider === "string" ? value.provider.trim().toLowerCase() : "";
  const repo = typeof value.repo === "string" ? value.repo.trim() : "";
  const host = typeof value.host === "string" ? value.host.trim() : "";
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
