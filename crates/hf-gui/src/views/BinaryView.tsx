import "../i18n.parityBinary";
import { Fragment, useState } from "react";
import { Cpu, FileSearch, GitPullRequest } from "lucide-react";
import { PathActions } from "../components/PathActions";
import { Button, Input, Textarea, ViewHeader } from "../components/ui";
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

const LABEL_STYLE = { color: "var(--text-secondary)" };

function Label({ htmlFor, children }: { htmlFor?: string; children: React.ReactNode }) {
  return <label htmlFor={htmlFor} className="text-xs font-medium" style={LABEL_STYLE}>{children}</label>;
}

function PathField({ id, label, value, onChange, placeholder, pickLabel, onPick, help }: {
  id: string; label: string; value: string; onChange: (value: string) => void;
  placeholder?: string; pickLabel: string; onPick: () => Promise<string | null>; help?: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex gap-2">
        <Input id={id} mono value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
        <Button variant="outline" size="sm" onClick={() => void onPick().then((picked) => { if (picked) onChange(picked); })}>{pickLabel}</Button>
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
    <div className="surface-card" style={{ padding: "var(--space-sm) var(--space-md)" }}>
      <div className="text-xs text-text-muted">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
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
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-text-muted">
            {["sha", "size", "fuzzerSignal", "replaySignal", "confirmed", "kind", "summary", "duplicateOf", "minimized"].map((col) => (
              <th key={col} scope="col" className="py-1 pr-3 font-medium">{t(`binary.col.${col}`)}</th>
            ))}
            <th scope="col" className="py-1 font-medium">{t("binary.col.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {outcome.findings.map((finding) => {
            const expanded = open === finding.sha256;
            return (
              <Fragment key={finding.sha256}>
                <tr className="align-top" style={{ borderTop: "1px solid var(--border)" }}>
                  <td className="py-2 pr-3 font-mono" title={finding.sha256}>{finding.sha256.slice(0, 8)}</td>
                  <td className="py-2 pr-3">{finding.size}</td>
                  <td className="py-2 pr-3">{finding.fuzzer_signal ?? "-"}</td>
                  <td className="py-2 pr-3">{signal(finding, finding.replay_signal)}</td>
                  <td className="py-2 pr-3">{finding.confirmed ? t("binary.yes") : t("binary.no")}</td>
                  <td className="py-2 pr-3">{finding.kind ?? "-"}</td>
                  <td className="py-2 pr-3">{finding.summary || "-"}</td>
                  <td className="py-2 pr-3 font-mono">{finding.duplicate_of ? finding.duplicate_of.slice(0, 8) : "-"}</td>
                  <td className="py-2 pr-3">{finding.minimized ? finding.minimized.size : "-"}</td>
                  <td className="py-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-expanded={expanded}
                      onClick={() => setOpen(expanded ? null : finding.sha256)}
                    >
                      {expanded ? t("binary.hideFrames") : t("binary.showFrames")}
                    </Button>
                  </td>
                </tr>
                {expanded && (
                  <tr>
                    <td colSpan={10} className="pb-3">
                      {finding.frames.length > 0 ? (
                        <ol className="font-mono text-xs list-decimal pl-5" aria-label={t("binary.showFrames")}>
                          {finding.frames.map((frame, index) => <li key={index}>{frame}</li>)}
                        </ol>
                      ) : <p className="text-xs text-text-muted">{t("binary.noFrames")}</p>}
                      <IssueActions project={project} report={report} finding={finding.sha256} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Outcome({ project, outcome }: { project: string; outcome: BinaryFuzzOutcome }) {
  const { t } = useI18n();
  return (
    <section className="flex flex-col gap-3" aria-label={t("binary.result")}>
      <h2 className="text-base font-semibold">{t("binary.result")}</h2>
      <p className="text-xs text-text-muted font-mono">
        {outcome.binary_name} · {outcome.machine} · {outcome.input} · {formatDuration(outcome.duration_secs)} · {t("binary.session")} {outcome.session}
      </p>
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
      <h3 className="text-sm font-semibold">{t("binary.findings")}</h3>
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
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <h2 className="text-base font-semibold flex items-center gap-2"><FileSearch size={16} />{t("binary.earlier")}</h2>
      <p className="text-xs text-text-muted">{t("binary.earlierHelp")}</p>
      <PathField
        id="binary-report" label={t("binary.reportPath")} value={report} onChange={setReport}
        placeholder={t("binary.reportPlaceholder")} pickLabel={t("binary.pickReport")} onPick={() => pickFile(t("binary.pickReport"))}
      />
      <div className="flex flex-col gap-1">
        <Label htmlFor="binary-finding">{t("binary.findingId")}</Label>
        <Input id="binary-finding" mono value={finding} onChange={(e) => setFinding(e.target.value.trim())} aria-invalid={finding !== "" && !findingValid} />
        {finding !== "" && !findingValid && <p role="alert" className="text-xs text-error">{t("binary.invalidFinding")}</p>}
      </div>
      {report.trim() !== "" && findingValid && project && (
        <IssueActions project={project} report={report.trim()} finding={finding} compact />
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
      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
        <PathField
          id="binary-path" label={t("binary.path")} value={binary} onChange={setBinary}
          placeholder={t("binary.pathPlaceholder")} pickLabel={t("binary.browse")} onPick={() => pickFile(t("binary.path"))}
        />
        <fieldset className="flex flex-col gap-2" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="text-xs font-medium mb-1" style={LABEL_STYLE}>{t("binary.inputMode")}</legend>
          {BINARY_INPUT_MODES.map((mode) => (
            <label key={mode} className="flex items-start gap-2 text-sm cursor-pointer">
              <input type="radio" name="binary-input" className="mt-1" value={mode} checked={input === mode} onChange={() => setInput(mode)} />
              <span>
                <span className="font-medium">{t(`binary.mode.${mode}`)}</span>
                <span className="block text-xs text-text-muted">{t(`binary.mode.${mode}.help`)}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <PathField
          id="binary-seeds" label={t("binary.seeds")} value={seeds} onChange={setSeeds} help={t("binary.seedsHelp")}
          pickLabel={t("binary.pickFolder")} onPick={() => pickFolder(t("binary.seeds"))}
        />
        <PathField
          id="binary-libraries" label={t("binary.libraries")} value={libraries} onChange={setLibraries} help={t("binary.librariesHelp")}
          pickLabel={t("binary.pickFolder")} onPick={() => pickFolder(t("binary.libraries"))}
        />
        <div className="flex gap-4 flex-wrap">
          <div className="flex flex-col gap-1">
            <Label>{t("binary.duration")}</Label>
            <DurationInput ariaLabel={t("binary.duration")} seconds={duration} onChange={setDuration} invalid={!validDuration} />
            {!validDuration && <p role="alert" className="text-xs text-error">{t("binary.invalidDuration")}</p>}
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="binary-timeout">{t("binary.timeout")}</Label>
            <Input id="binary-timeout" type="number" min={1} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)} aria-invalid={!validTimeout} />
            {!validTimeout && <p role="alert" className="text-xs text-error">{t("binary.invalidTimeout")}</p>}
          </div>
        </div>
        {!project && <p className="text-sm text-text-muted">{t("binary.noProject")}</p>}
        <div>
          <Button disabled={!canStart} onClick={() => void start()}>{t("binary.start")}</Button>
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
        <div role="alert" className="text-sm text-error">
          <div className="font-semibold">{t("binary.failed")}</div>
          <div>{error}</div>
        </div>
      )}
      {outcome ? (
        <Outcome project={project} outcome={outcome} />
      ) : !running && !error && (
        <div className="surface-card" style={{ padding: "var(--space-md)" }}>
          <div className="text-sm font-semibold">{t("binary.emptyTitle")}</div>
          <p className="text-sm text-text-muted">{t("binary.emptyBody")}</p>
        </div>
      )}
      <EarlierReport project={project} />
    </div>
  );
}
