// Issue-tracker settings -- file crash issues into the FUZZED project's repo.
//
// Config-backed (config/issue_tracker.toml), so the orchestrator handles
// load/save via the generic ObjectForm. This tab adds context plus a "Test
// connection" button that validates the *saved* host + token against the live
// GitHub/GitLab API, and a link to open the target repo.

import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { getTransport, openExternal } from "../../lib";
import { Button } from "../ui/Button";
import { ObjectForm } from "./ObjectForm";

type Cfg = Record<string, unknown>;

export function IssueTrackerTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const provider = typeof value.provider === "string" ? value.provider.trim().toLowerCase() : "";
  const repo = typeof value.repo === "string" ? value.repo.trim() : "";
  const host = typeof value.host === "string" ? value.host.trim() : "";
  const configured = (provider === "github" || provider === "gitlab") && repo.length > 0;

  const providerLabel = provider === "github" ? "GitHub" : provider === "gitlab" ? "GitLab" : "the tracker";
  const defaultHost = provider === "github" ? "https://github.com" : "https://gitlab.com";
  const repoUrl = configured ? `${(host || defaultHost).replace(/\/$/, "")}/${repo.replace(/^\/|\/$/g, "")}` : "";

  async function testConnection() {
    setTesting(true);
    setResult(null);
    try {
      await getTransport().invoke("issue_tracker_test_connection");
      setResult({ ok: true, msg: `Authenticated with ${providerLabel} successfully.` });
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
          File triaged crashes as issues in the <strong>fuzzed project's</strong> repository. Choose
          a <code>provider</code> (<code>github</code> or <code>gitlab</code>) and set{" "}
          <code>repo</code> to the target — GitHub <code>owner/repo</code> or GitLab{" "}
          <code>group/project</code>. Leave <code>host</code> blank for the public site, or set it for
          GitHub Enterprise / self-hosted GitLab.
        </p>
        <p style={{ marginTop: 8 }}>
          Auth is a <strong>Personal Access Token</strong> — paste it into <code>api_token</code>{" "}
          (stored with your desktop settings, like a provider key) or set <code>api_token_env</code>{" "}
          to the NAME of an environment variable holding it (preferred for CLI/CI). It needs the{" "}
          <code>repo</code> / Issues:write scope on GitHub, or the <code>api</code> scope on GitLab.
          There is no password field: GitHub and GitLab authenticate the API with tokens, and{" "}
          <code>username</code> is for attribution only. With a token, crashes are filed directly and
          you are linked to the issue; without one, a prefilled new-issue page opens in your browser.
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
          Test connection
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void openExternal(repoUrl)}
          disabled={!configured}
          title={configured ? "Open the target repository in your browser" : "Set provider + repo first"}
        >
          <ExternalLink size={14} />
          Open repository
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
        Test uses the last <strong>saved</strong> settings -- save your changes first.
      </p>
    </div>
  );
}
