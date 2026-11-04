import { useState } from "react";
import { AlertTriangle, Clipboard, ExternalLink, GitPullRequest } from "lucide-react";
import { getTransport, openExternal } from "../lib";
import { useI18n } from "../i18nContext";
import { useToast } from "./ui/toastContext";
import { Button, Textarea } from "./ui";
import type { CreatedIssue, IssueExport } from "../types";

/** A GitHub or GitLab issue draft for one crash: copy it, open the new-issue page, or file it. */
export function IssueDraft({ draft, project }: { draft: IssueExport; project: string }) {
  const { toast } = useToast();
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const [filing, setFiling] = useState(false);
  const providerLabel = draft.provider === "github" ? "GitHub" : "GitLab";

  async function copyBody() {
    await navigator.clipboard?.writeText(`${draft.title}\n\n${draft.description}`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  // File the issue directly via the provider API, then open the created issue.
  async function fileIssue() {
    setFiling(true);
    try {
      const created = await getTransport().invoke<CreatedIssue>("file_issue", {
        project,
        crashId: draft.crash_id,
      });
      toast({ title: t("dashboard.filedIssue", { provider: providerLabel }), description: created.url, variant: "success" });
      if (created.url) void openExternal(created.url);
    } catch (e) {
      toast({ title: t("dashboard.couldNotFileIssue", { provider: providerLabel }), description: String(e), variant: "error" });
    } finally {
      setFiling(false);
    }
  }

  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center gap-2 text-sm font-semibold">
        <span style={{ color: "var(--accent)", display: "flex" }}><GitPullRequest size={15} /></span>
        <span>{t("dashboard.issueDraft")}</span>
      </div>
      <div className="mt-3 flex flex-col gap-2">
        <div className="text-sm font-medium">{draft.title}</div>
        {draft.project_web_url && (
          <div className="text-xs text-text-muted truncate">
            {providerLabel} · <span className="font-mono">{draft.project_web_url.replace(/^https?:\/\//, "")}</span>
          </div>
        )}
        <div className="flex flex-wrap gap-1">
          {draft.labels.map((label) => (
            <span key={label} className="text-xs px-2 py-0.5 rounded-sm" style={{ background: "var(--surface-active)", color: "var(--text-secondary)" }}>{label}</span>
          ))}
        </div>
        <Textarea value={draft.description} readOnly rows={12} />
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="outline" size="sm" onClick={() => void copyBody()}>
            <Clipboard size={13} />
            {copied ? t("common.copied") : t("common.copy")}
          </Button>
          {draft.can_file && (
            <Button variant="primary" size="sm" onClick={() => void fileIssue()} loading={filing}>
              {!filing && <GitPullRequest size={13} />}
              {t("dashboard.fileIssue", { provider: providerLabel })}
            </Button>
          )}
          {draft.issue_url && (
            <Button variant={draft.can_file ? "outline" : "primary"} size="sm" onClick={() => void openExternal(draft.issue_url ?? "")}>
              <ExternalLink size={13} />
              {t("common.openInBrowser")}
            </Button>
          )}
        </div>
        {!draft.issue_url && (
          <div role="note" className="flex items-start gap-2 text-xs rounded-md" style={{ padding: "var(--space-sm)", background: "rgba(217,119,6,0.12)", color: "#d97706", border: "1px solid rgba(217,119,6,0.35)" }}>
            <AlertTriangle size={14} />
            <span>{t("dashboard.noIssueTracker")}</span>
          </div>
        )}
      </div>
    </section>
  );
}
