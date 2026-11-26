import "../../i18n.parityBinary";
import { useEffect, useState } from "react";
import { GitPullRequest, Sparkles } from "lucide-react";
import { PathActions } from "../PathActions";
import { Badge, Button, Textarea } from "../ui";
import { useI18n } from "../../i18nContext";
import { openExternal } from "../../lib";
import {
  binaryFileIssue,
  binaryFindingExplain,
  binaryFindingExplanation,
  binaryIssueExport,
  formatCount as count,
  reportPath,
  type BinaryExplanation,
  type BinaryFinding,
  type BinaryFuzzOutcome,
} from "../../lib/parityBinary";
import { formatDuration } from "../../lib/duration";
import { useConfirm } from "../../providers/confirm";
import type { CreatedIssue, IssueExport } from "../../types";

/** Draft and file issues for one finding, named by report and sha256. */
export function IssueActions({ project, report, finding }: { project: string; report: string; finding: string }) {
  const { t } = useI18n();
  const confirm = useConfirm();
  const [busy, setBusy] = useState<"draft" | "file" | null>(null);
  const [draft, setDraft] = useState<IssueExport | null>(null);
  const [created, setCreated] = useState<CreatedIssue | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function makeDraft() {
    setBusy("draft"); setError(null);
    try {
      setDraft(await binaryIssueExport(project, report, finding));
    } catch (e) {
      setError(`${t("binary.draftFailed")}: ${String(e)}`);
    } finally { setBusy(null); }
  }

  async function file() {
    const approved = await confirm({
      title: t("binary.confirmFileTitle"),
      message: t("binary.confirmFileMessage", { finding: finding.slice(0, 12) }),
      confirmLabel: t("binary.fileIssue"),
    });
    if (!approved) return;
    setBusy("file"); setError(null);
    try {
      setCreated(await binaryFileIssue(project, report, finding));
    } catch (e) {
      setError(`${t("binary.fileFailed")}: ${String(e)}`);
    } finally { setBusy(null); }
  }

  async function copy() {
    if (!draft) return;
    try {
      await navigator.clipboard.writeText(`${draft.title}\n\n${draft.description}`);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch { /* clipboard unavailable */ }
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-2 flex-wrap">
        <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => void makeDraft()}>
          {busy === "draft" ? t("binary.drafting") : t("binary.draftIssue")}
        </Button>
        <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => void file()}>
          {busy === "file" ? t("binary.filing") : t("binary.fileIssue")}
        </Button>
      </div>
      {error && <p role="alert" className="text-sm text-error">{error}</p>}
      {created && (
        <p role="status" className="text-sm">
          {t("binary.issueFiled")}:{" "}
          <button type="button" className="underline" onClick={() => void openExternal(created.url)}>{created.url}</button>
        </p>
      )}
      {draft && (
        <section className="hf-finding" aria-label={t("binary.issueDraft")}>
          <div className="flex items-center gap-2 text-sm font-semibold"><GitPullRequest size={15} />{t("binary.issueDraft")}</div>
          <div className="text-sm font-medium">{draft.title}</div>
          {draft.labels.length > 0 && (
            <div className="flex flex-wrap gap-1" aria-label={t("binary.labels")}>
              {draft.labels.map((label) => <Badge key={label}>{label}</Badge>)}
            </div>
          )}
          <Textarea readOnly rows={10} value={draft.description} aria-label={t("binary.issueDraft")} />
          <div className="flex gap-2 flex-wrap">
            <Button variant="outline" size="sm" onClick={() => void copy()}>{copied ? t("binary.copied") : t("binary.copyDraft")}</Button>
            {draft.issue_url && (
              <Button variant="outline" size="sm" onClick={() => void openExternal(draft.issue_url!)}>{t("binary.openNewIssue")}</Button>
            )}
          </div>
        </section>
      )}
    </div>
  );
}

/** The model's triage note for one finding: the stored one, or a new one on request. */
function Explanation({ project, session, finding }: { project: string; session: string; finding: string }) {
  const { t } = useI18n();
  const [note, setNote] = useState<BinaryExplanation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    binaryFindingExplanation(project, session, finding)
      .then((stored) => { if (live && stored && typeof stored.text === "string") setNote(stored); })
      .catch(() => undefined); // no stored note, or none can be read: the button still works
    return () => { live = false; };
  }, [project, session, finding]);

  async function explain() {
    setBusy(true); setError(null);
    try {
      setNote(await binaryFindingExplain(project, session, finding));
    } catch (e) {
      setError(`${t("binary.explainFailed")}: ${String(e)}`);
    } finally { setBusy(false); }
  }

  return (
    <div className="flex flex-col gap-2">
      <div>
        <Button variant="outline" size="sm" loading={busy} onClick={() => void explain()}>
          {!busy && <Sparkles size={14} />}
          {t(busy ? "binary.explaining" : note ? "binary.explainAgain" : "binary.explain")}
        </Button>
      </div>
      {error && <p role="alert" className="text-sm text-error">{error}</p>}
      {note && (
        <section className="hf-ai-note" aria-label={t("binary.explanation")}>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-text-primary">{t("binary.explanation")}</span>
            <Badge variant="accent">{t("binary.modelOutput")}</Badge>
          </div>
          <p className="hf-ai-note-text">{note.text}</p>
          {note.disassembly && (
            <details className="text-xs">
              <summary className="cursor-pointer text-text-secondary">{t("binary.disassemblySent")}</summary>
              <pre className="hf-disassembly" aria-label={t("binary.disassemblySent")}>{note.disassembly}</pre>
            </details>
          )}
          <p className="text-xs text-text-muted">{t("binary.explanationNote")}</p>
        </section>
      )}
    </div>
  );
}

/** Finding cards: facts at a glance, frames, the AI note and issue actions on demand. */
export function BinaryFindingList({ project, outcome }: { project: string; outcome: BinaryFuzzOutcome }) {
  const { t } = useI18n();
  const [open, setOpen] = useState<string | null>(null);
  const report = reportPath(outcome.workspace);
  const signal = (finding: BinaryFinding, value: number | null) =>
    value !== null ? String(value) : finding.replayed ? "-" : t("binary.notReplayed");
  if (outcome.findings.length === 0) return <p className="text-sm text-text-muted">{t("binary.noFindings")}</p>;
  return (
    <div className="flex flex-col gap-2">
      {outcome.findings.map((finding) => {
        const expanded = open === finding.sha256;
        const facts: [string, React.ReactNode][] = [
          ["size", finding.size],
          ["fuzzerSignal", finding.fuzzer_signal ?? "-"],
          ["replaySignal", signal(finding, finding.replay_signal)],
          ["confirmed", <Badge variant={finding.confirmed ? "error" : "default"}>{finding.confirmed ? t("binary.yes") : t("binary.no")}</Badge>],
          ["duplicateOf", finding.duplicate_of ? finding.duplicate_of.slice(0, 8) : "-"],
          ["minimized", finding.minimized ? finding.minimized.size : "-"],
        ];
        return (
          <article key={finding.sha256} className="hf-finding">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap text-sm">
                  <span className="font-mono text-text-primary" title={`${t("binary.col.sha")} ${finding.sha256}`}>{finding.sha256.slice(0, 8)}</span>
                  <span className="font-semibold text-text-primary">{finding.kind ?? "-"}</span>
                </div>
                <p className="text-xs text-text-secondary" style={{ marginTop: 2, overflowWrap: "anywhere" }}>{finding.summary || "-"}</p>
              </div>
              <Button variant="outline" size="sm" className="shrink-0 whitespace-nowrap" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : finding.sha256)}>
                {expanded ? t("binary.hideFrames") : t("binary.showFrames")}
              </Button>
            </div>
            <dl className="hf-finding-facts">
              {facts.map(([key, value]) => (
                <div key={key}><dt className="hf-field-label">{t(`binary.col.${key}`)}</dt><dd>{value}</dd></div>
              ))}
            </dl>
            {expanded && (
              <div className="flex flex-col gap-3">
                {finding.frames.length > 0 ? (
                  <ol className="hf-frames" aria-label={t("binary.showFrames")}>
                    {finding.frames.map((frame, index) => <li key={index}>{frame}</li>)}
                  </ol>
                ) : <p className="text-xs text-text-muted">{t("binary.noFrames")}</p>}
                <Explanation project={project} session={outcome.session} finding={finding.sha256} />
                <IssueActions project={project} report={report} finding={finding.sha256} />
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="hf-stat">
      <div className="hf-field-label">{label}</div>
      <div className="hf-stat-value">{value}</div>
    </div>
  );
}


/** A session's result: counters, workspace and findings. */
export function BinaryOutcome({ project, outcome }: { project: string; outcome: BinaryFuzzOutcome }) {
  const { t } = useI18n();
  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md) var(--space-lg)" }} aria-label={t("binary.result")}>
      <div className="flex flex-col gap-1">
        <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2 flex-wrap">
          {t("binary.result")}
          {outcome.stopped && <Badge variant="warning">{t("binary.stoppedEarly")}</Badge>}
          {outcome.compcov && <Badge variant="accent">{t("binary.compcovUsed")}</Badge>}
        </h2>
        <p className="text-xs text-text-muted font-mono">
          {outcome.binary_name} · {outcome.machine} · {outcome.input} · {formatDuration(outcome.duration_secs)} · {t("binary.session")} {outcome.session}
        </p>
      </div>
      <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))" }}>
        <Stat label={t("binary.stat.execs")} value={count(outcome.execs_done)} />
        <Stat label={t("binary.stat.execsPerSec")} value={outcome.execs_per_sec === null ? "-" : outcome.execs_per_sec.toFixed(1)} />
        <Stat label={t("binary.stat.edges")} value={count(outcome.edges_found)} />
        <Stat label={t("binary.stat.corpus")} value={count(outcome.corpus_count)} />
        <Stat label={t("binary.stat.hangs")} value={count(outcome.saved_hangs)} />
        <Stat label={t("binary.stat.distinct")} value={String(outcome.distinct_findings)} />
        <Stat label={t("binary.stat.omitted")} value={String(outcome.findings_omitted)} />
      </div>
      {outcome.findings_omitted > 0 && <p className="text-xs text-text-muted">{t("binary.omittedNote", { count: outcome.findings_omitted })}</p>}
      <div className="flex items-center gap-2 text-sm min-w-0">
        <span className="text-text-muted shrink-0">{t("binary.workspace")}</span>
        <span className="font-mono truncate min-w-0">{outcome.workspace}</span>
        <PathActions path={outcome.workspace} />
      </div>
      <h3 className="text-sm font-semibold text-text-primary border-t border-border" style={{ paddingTop: "var(--space-md)" }}>{t("binary.findings")}</h3>
      <BinaryFindingList project={project} outcome={outcome} />
    </section>
  );
}
