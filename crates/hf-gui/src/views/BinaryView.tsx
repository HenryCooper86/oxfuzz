import "../i18n.parityBinary";
import { useState } from "react";
import { Cpu, FileSearch, FolderOpen, GitPullRequest, Info, Play } from "lucide-react";
import { PathActions } from "../components/PathActions";
import { Badge, Button, EmptyState, Input, Textarea, ViewHeader } from "../components/ui";
import { DurationInput } from "../components/ui/DurationInput";
import { useI18n } from "../i18nContext";
import { openExternal, pickFile, pickFolder } from "../lib";
import {
  BINARY_INPUT_MODES,
  DEFAULT_BINARY_DURATION_SECS,
  DEFAULT_BINARY_TIMEOUT_MS,
  binaryFileIssue,
  binaryFuzz,
  binaryIssueExport,
  reportPath,
  validFindingId,
  type BinaryFinding,
  type BinaryFuzzOutcome,
  type BinaryInputMode,
} from "../lib/parityBinary";
import { formatDuration } from "../lib/duration";
import { useConfirm } from "../providers/confirm";
import { useProject } from "../providers/project";
import type { CreatedIssue, IssueExport } from "../types";

function Label({ htmlFor, children }: { htmlFor?: string; children: React.ReactNode }) {
  return <label htmlFor={htmlFor} className="hf-field-label">{children}</label>;
}

/** One divided band of the session form. */
function FormSection({ children }: { children: React.ReactNode }) {
  return <div className="hf-form-section flex flex-col gap-3">{children}</div>;
}

function PathField({ id, label, value, onChange, placeholder, pickLabel, pickIcon, onPick, help }: {
  id: string; label: string; value: string; onChange: (value: string) => void;
  placeholder?: string; pickLabel: string; pickIcon: React.ReactNode; onPick: () => Promise<string | null>; help?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5 min-w-0">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex gap-2 min-w-0">
        <Input id={id} mono className="h-8 min-w-0" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
        <Button variant="outline" className="shrink-0 whitespace-nowrap" onClick={() => void onPick().then((picked) => { if (picked) onChange(picked); })}>
          {pickIcon}
          {pickLabel}
        </Button>
      </div>
      {help && <p className="text-xs text-text-muted">{help}</p>}
    </div>
  );
}

/** Draft and file issues for one finding, named by report and sha256. */
function IssueActions({ project, report, finding, compact }: { project: string; report: string; finding: string; compact?: boolean }) {
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
    <div className={`flex flex-col gap-2 ${compact ? "" : "mt-2"}`}>
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
        <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }} aria-label={t("binary.issueDraft")}>
          <div className="flex items-center gap-2 text-sm font-semibold"><GitPullRequest size={15} />{t("binary.issueDraft")}</div>
          <div className="text-sm font-medium">{draft.title}</div>
          {draft.labels.length > 0 && (
            <div className="flex flex-wrap gap-1" aria-label={t("binary.labels")}>
              {draft.labels.map((label) => (
                <span key={label} className="text-xs px-2 py-0.5 rounded-sm" style={{ background: "var(--surface-active)", color: "var(--text-secondary)" }}>{label}</span>
              ))}
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

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="hf-stat">
      <div className="hf-field-label">{label}</div>
      <div className="hf-stat-value">{value}</div>
    </div>
  );
}

const count = (value: number | null) => (value === null ? "-" : value.toLocaleString());

function FindingsTable({ project, outcome }: { project: string; outcome: BinaryFuzzOutcome }) {
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
              <div>
                {finding.frames.length > 0 ? (
                  <ol className="hf-frames" aria-label={t("binary.showFrames")}>
                    {finding.frames.map((frame, index) => <li key={index}>{frame}</li>)}
                  </ol>
                ) : <p className="text-xs text-text-muted">{t("binary.noFrames")}</p>}
                <IssueActions project={project} report={report} finding={finding.sha256} />
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}

function Outcome({ project, outcome }: { project: string; outcome: BinaryFuzzOutcome }) {
  const { t } = useI18n();
  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md) var(--space-lg)" }} aria-label={t("binary.result")}>
      <div className="flex flex-col gap-1">
        <h2 className="text-sm font-semibold text-text-primary">{t("binary.result")}</h2>
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
      <div className="flex items-center gap-2 text-sm">
        <span className="text-text-muted">{t("binary.workspace")}</span>
        <span className="font-mono truncate">{outcome.workspace}</span>
        <PathActions path={outcome.workspace} />
      </div>
      <h3 className="text-sm font-semibold text-text-primary border-t border-border" style={{ paddingTop: "var(--space-md)" }}>{t("binary.findings")}</h3>
      <FindingsTable project={project} outcome={outcome} />
    </section>
  );
}

function EarlierReport({ project }: { project: string }) {
  const { t } = useI18n();
  const [report, setReport] = useState("");
  const [finding, setFinding] = useState("");
  const findingValid = validFindingId(finding);
  return (
    <section className="surface-card overflow-hidden">
      <div className="hf-form-section flex flex-col gap-1">
        <h2 className="text-sm font-semibold flex items-center gap-2 text-text-primary">
          <FileSearch size={16} className="text-text-muted" />
          {t("binary.earlier")}
        </h2>
        <p className="text-xs text-text-secondary">{t("binary.earlierHelp")}</p>
      </div>
      <div className="hf-form-section hf-grid-300 grid gap-4">
        <PathField
          id="binary-report" label={t("binary.reportPath")} value={report} onChange={setReport}
          placeholder={t("binary.reportPlaceholder")} pickLabel={t("binary.pickReport")} pickIcon={<FileSearch size={14} />}
          onPick={() => pickFile(t("binary.pickReport"))}
        />
        <div className="flex flex-col gap-1.5 min-w-0">
          <Label htmlFor="binary-finding">{t("binary.findingId")}</Label>
          <Input id="binary-finding" mono className="h-8" value={finding} onChange={(e) => setFinding(e.target.value.trim())} aria-invalid={finding !== "" && !findingValid} />
          {finding !== "" && !findingValid && <p role="alert" className="text-xs text-error">{t("binary.invalidFinding")}</p>}
        </div>
      </div>
      {report.trim() !== "" && findingValid && project && (
        <div className="hf-form-section">
          <IssueActions project={project} report={report.trim()} finding={finding} compact />
        </div>
      )}
    </section>
  );
}

export function BinaryView() {
  const { t } = useI18n();
  const { activeProject } = useProject();
  const project = activeProject || "";
  const [binary, setBinary] = useState("");
  const [input, setInput] = useState<BinaryInputMode>("file");
  const [seeds, setSeeds] = useState("");
  const [libraries, setLibraries] = useState("");
  const [duration, setDuration] = useState(String(DEFAULT_BINARY_DURATION_SECS));
  const [timeoutMs, setTimeoutMs] = useState(String(DEFAULT_BINARY_TIMEOUT_MS));
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<BinaryFuzzOutcome | null>(null);

  const durationSecs = Number(duration);
  const timeout = Number(timeoutMs);
  const validDuration = duration.trim() !== "" && Number.isSafeInteger(durationSecs) && durationSecs >= 1;
  const validTimeout = timeoutMs.trim() !== "" && Number.isSafeInteger(timeout) && timeout >= 1;
  const canStart = !running && !!project && binary.trim() !== "" && validDuration && validTimeout;

  async function start() {
    if (!canStart) return;
    setRunning(true); setError(null);
    try {
      setOutcome(await binaryFuzz({
        project,
        binary: binary.trim(),
        input,
        seeds: seeds.trim() || undefined,
        libraries: libraries.trim() || undefined,
        durationSecs,
        timeoutMs: timeout,
      }));
    } catch (e) {
      setError(String(e));
    } finally { setRunning(false); }
  }

  return (
    <div className="flex flex-col gap-4">
      <ViewHeader title={t("title.binary")} description={t("binary.subtitle")} />
      <p className="text-sm text-text-secondary">{t("binary.requirement")}</p>
      <section className="surface-card overflow-hidden">
        <FormSection>
          <PathField
            id="binary-path" label={t("binary.path")} value={binary} onChange={setBinary}
            placeholder={t("binary.pathPlaceholder")} pickLabel={t("binary.browse")} pickIcon={<FileSearch size={14} />}
            onPick={() => pickFile(t("binary.path"))}
          />
        </FormSection>
        <FormSection>
          <fieldset className="flex flex-col gap-2 min-w-0" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="hf-field-label" style={{ marginBottom: 8 }}>{t("binary.inputMode")}</legend>
            <div className="hf-grid-260 grid gap-2">
              {BINARY_INPUT_MODES.map((mode) => (
                <label key={mode} className="hf-choice">
                  <input type="radio" name="binary-input" value={mode} checked={input === mode} onChange={() => setInput(mode)} />
                  <span className="hf-choice-dot" aria-hidden="true" />
                  <span className="min-w-0">
                    <span className="block text-13px font-medium text-text-primary">{t(`binary.mode.${mode}`)}</span>
                    <span className="block text-xs text-text-secondary" style={{ marginTop: 2, lineHeight: 1.45 }}>{t(`binary.mode.${mode}.help`)}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
        </FormSection>
        <FormSection>
          <div className="hf-grid-300 grid gap-4">
            <PathField
              id="binary-seeds" label={t("binary.seeds")} value={seeds} onChange={setSeeds} help={t("binary.seedsHelp")}
              pickLabel={t("binary.pickFolder")} pickIcon={<FolderOpen size={14} />} onPick={() => pickFolder(t("binary.seeds"))}
            />
            <PathField
              id="binary-libraries" label={t("binary.libraries")} value={libraries} onChange={setLibraries} help={t("binary.librariesHelp")}
              pickLabel={t("binary.pickFolder")} pickIcon={<FolderOpen size={14} />} onPick={() => pickFolder(t("binary.libraries"))}
            />
          </div>
        </FormSection>
        <FormSection>
          <div className="flex gap-6 flex-wrap items-start">
            <div className="flex flex-col gap-1.5">
              <Label>{t("binary.duration")}</Label>
              <DurationInput ariaLabel={t("binary.duration")} seconds={duration} onChange={setDuration} invalid={!validDuration} />
              {!validDuration && <p role="alert" className="text-xs text-error">{t("binary.invalidDuration")}</p>}
            </div>
            <div className="flex flex-col gap-1.5" style={{ width: 180 }}>
              <Label htmlFor="binary-timeout">{t("binary.timeout")}</Label>
              <Input id="binary-timeout" type="number" min={1} className="h-8" value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)} aria-invalid={!validTimeout} />
              {!validTimeout && <p role="alert" className="text-xs text-error">{t("binary.invalidTimeout")}</p>}
            </div>
          </div>
        </FormSection>
        <div className="hf-form-footer flex items-center justify-between gap-3 flex-wrap">
          {project ? <span /> : (
            <p className="flex items-center gap-1.5 text-xs text-text-secondary">
              <Info size={14} />
              {t("binary.noProject")}
            </p>
          )}
          <Button variant="primary" disabled={!canStart} loading={running} onClick={() => void start()}>
            {!running && <Play size={14} />}
            {t("binary.start")}
          </Button>
        </div>
      </section>

      {running && (
        <div role="status" className="surface-card flex items-start gap-2" style={{ padding: "var(--space-md)" }}>
          <Cpu size={16} />
          <div>
            <div className="text-sm font-semibold">{t("binary.running")}</div>
            <div className="text-xs text-text-muted">{t("binary.runningBody")}</div>
          </div>
        </div>
      )}
      {error && (
        <div role="alert" className="hf-alert-error text-sm">
          <div className="font-semibold">{t("binary.failed")}</div>
          <div style={{ overflowWrap: "anywhere" }}>{error}</div>
        </div>
      )}
      {outcome ? (
        <Outcome project={project} outcome={outcome} />
      ) : !running && !error && (
        <EmptyState icon={<Cpu size={22} />} title={t("binary.emptyTitle")} hint={t("binary.emptyBody")} />
      )}
      <EarlierReport project={project} />
    </div>
  );
}
