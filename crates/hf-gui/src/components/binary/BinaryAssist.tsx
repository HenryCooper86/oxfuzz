import "../../i18n.parityBinary";
import { useState } from "react";
import { History, Play, RotateCcw, Sparkles, TriangleAlert } from "lucide-react";
import { Badge, Button, Input, Switch, Textarea } from "../ui";
import { useI18n } from "../../i18nContext";
import {
  BINARY_STAGES,
  binaryDictionaryRefine,
  binarySeedDrafts,
  formatCount as count,
  type BinaryInputMode,
  type BinaryProfile,
  type BinaryProgress,
  type BinarySeedDraft,
  type BinarySessionSummary,
} from "../../lib/parityBinary";
import { formatDuration } from "../../lib/duration";

const VISIBLE_IMPORTS = 14;
const VISIBLE_TOKENS = 28;

function bytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}

/** What inspection found: facts, imports, the suggestion and its reasons. */
export function ProfilePanel({ profile }: { profile: BinaryProfile }) {
  const { t } = useI18n();
  const imports = profile.imports.slice(0, VISIBLE_IMPORTS);
  return (
    <div className="flex flex-col gap-3" aria-label={t("binary.profile")}>
      <div>
        <div className="hf-field-label">{t("binary.profile")}</div>
        <p className="text-xs text-text-secondary" style={{ marginTop: 2 }}>{t("binary.profileHint")}</p>
      </div>
      <dl className="hf-finding-facts">
        <div><dt className="hf-field-label">{t("binary.machine")}</dt><dd>{profile.machine}</dd></div>
        <div><dt className="hf-field-label">{t("binary.linking")}</dt><dd>{t(`binary.linking.${profile.linking}`)}</dd></div>
        <div><dt className="hf-field-label">{t("binary.size")}</dt><dd>{bytes(profile.size)}</dd></div>
        <div><dt className="hf-field-label">{t("binary.imports")}</dt><dd>{profile.imports.length}</dd></div>
      </dl>
      {imports.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {imports.map((name) => <span key={name} className="hf-chip">{name}</span>)}
          {profile.imports.length > imports.length && (
            <span className="hf-chip hf-chip-muted">{t("binary.moreImports", { count: profile.imports.length - imports.length })}</span>
          )}
        </div>
      )}
      {profile.notes.map((note) => (
        <p key={note} role="note" className="hf-alert-warning text-xs flex items-start gap-2"><TriangleAlert size={14} />{note}</p>
      ))}
    </div>
  );
}

/** Dictionary tokens from the strings, optionally refined by the model and edited by hand. */
export function DictionaryPanel({ project, binary, input, tokens, enabled, onTokens, onEnabled }: {
  project: string; binary: string; input: BinaryInputMode; tokens: string[]; enabled: boolean;
  onTokens: (tokens: string[]) => void; onEnabled: (enabled: boolean) => void;
}) {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  async function refine() {
    setBusy(true); setError(null);
    try {
      const refined = await binaryDictionaryRefine(project, binary, input, tokens);
      onTokens(refined);
      onEnabled(refined.length > 0);
    } catch (e) {
      setError(`${t("binary.refineFailed")}: ${String(e)}`);
    } finally { setBusy(false); }
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="hf-field-label">{t("binary.dictionary")}</div>
          <p className="text-xs text-text-secondary" style={{ marginTop: 2 }}>{t("binary.dictionaryHint")}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" disabled={!project || !binary} loading={busy} onClick={() => void refine()}>
            {!busy && <Sparkles size={14} />}{t(busy ? "binary.refining" : "binary.refineDictionary")}
          </Button>
          <Button variant="ghost" size="sm" aria-pressed={editing} onClick={() => setEditing(!editing)}>{t("binary.editTokens")}</Button>
        </div>
      </div>
      {tokens.length > 0
        ? <Switch checked={enabled} onChange={onEnabled} label={t("binary.useDictionary", { count: tokens.length })} />
        : <p className="text-xs text-text-muted">{t("binary.noDictionary")}</p>}
      {!editing && tokens.length > 0 && (
        <div className="flex flex-wrap gap-1" style={{ opacity: enabled ? 1 : 0.5 }}>
          {tokens.slice(0, VISIBLE_TOKENS).map((token) => <span key={token} className="hf-chip font-mono">{token}</span>)}
          {tokens.length > VISIBLE_TOKENS && <span className="hf-chip hf-chip-muted">+{tokens.length - VISIBLE_TOKENS}</span>}
        </div>
      )}
      {editing && (
        <Textarea
          mono rows={8} aria-label={t("binary.tokensLabel")} placeholder={t("binary.tokensLabel")}
          value={tokens.join("\n")}
          onChange={(e) => onTokens(e.target.value.split("\n").map((line) => line.trim()).filter(Boolean))}
        />
      )}
      {error && <p role="alert" className="text-xs text-error">{error}</p>}
    </div>
  );
}

/** Model-drafted seeds, shown before the operator decides to use them. */
export function SeedDraftPanel({ project, binary, input, usedDirectory, onUse }: {
  project: string; binary: string; input: BinaryInputMode; usedDirectory: string; onUse: (directory: string) => void;
}) {
  const { t } = useI18n();
  const [description, setDescription] = useState("");
  const [draft, setDraft] = useState<BinarySeedDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true); setError(null);
    try {
      setDraft(await binarySeedDrafts(project, binary, input, description.trim() || null, 8));
    } catch (e) {
      setError(`${t("binary.seedsFailed")}: ${String(e)}`);
    } finally { setBusy(false); }
  }

  const used = draft !== null && usedDirectory === draft.directory;
  return (
    <div className="flex flex-col gap-2">
      <div>
        <div className="hf-field-label">{t("binary.aiSeeds")}</div>
        <p className="text-xs text-text-secondary" style={{ marginTop: 2 }}>{t("binary.aiSeedsHint")}</p>
      </div>
      <div className="flex gap-2 min-w-0">
        <Input
          className="h-8 min-w-0" aria-label={t("binary.seedDescription")} placeholder={t("binary.seedDescriptionPlaceholder")}
          value={description} onChange={(e) => setDescription(e.target.value)}
        />
        <Button variant="outline" className="shrink-0 whitespace-nowrap" disabled={!project || !binary} loading={busy} onClick={() => void run()}>
          {!busy && <Sparkles size={14} />}{t(busy ? "binary.draftingSeeds" : "binary.draftSeeds")}
        </Button>
      </div>
      {error && <p role="alert" className="text-xs text-error">{error}</p>}
      {draft && (
        <div className="hf-ai-note" aria-label={t("binary.aiSeeds")}>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-text-primary">{t("binary.seedsProposed", { count: draft.seeds.length })}</span>
              <Badge variant="accent">{t("binary.modelOutput")}</Badge>
            </div>
            {used
              ? <Badge variant="success">{t("binary.usingSeeds")}</Badge>
              : <Button variant="primary" size="sm" onClick={() => onUse(draft.directory)}>{t("binary.useSeeds")}</Button>}
          </div>
          <ul className="flex flex-col gap-1" style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {draft.seeds.map((seed) => (
              <li key={seed.sha256} className="flex items-center gap-3 text-xs min-w-0">
                <span className="font-mono text-text-muted shrink-0">{seed.name}</span>
                <span className="text-text-muted shrink-0" style={{ width: 56 }}>{bytes(seed.size)}</span>
                <span className="font-mono text-text-primary truncate min-w-0">{seed.preview}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/** Live session progress: stage, elapsed time and AFL++'s counters. */
export function ProgressPanel({ progress }: { progress: BinaryProgress | null }) {
  const { t } = useI18n();
  const stageIndex = progress ? BINARY_STAGES.indexOf(progress.stage) : 0;
  const share = progress && progress.duration_secs > 0
    ? Math.min(100, (progress.elapsed_secs / progress.duration_secs) * 100) : 0;
  const tiles: [string, string][] = progress ? [
    ["binary.stat.execs", count(progress.execs_done)],
    ["binary.stat.execsPerSec", progress.execs_per_sec === null ? "-" : progress.execs_per_sec.toFixed(1)],
    ["binary.stat.edges", count(progress.edges_found)],
    ["binary.stat.corpus", count(progress.corpus_count)],
    ["binary.savedCrashes", count(progress.saved_crashes)],
    ["binary.stat.hangs", count(progress.saved_hangs)],
  ] : [];
  return (
    <section role="status" aria-live="polite" className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md) var(--space-lg)" }} aria-label={t("binary.progress")}>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-sm font-semibold text-text-primary">{t("binary.progress")}</h2>
        {progress && (
          <span className="text-xs text-text-secondary tabular-nums">
            {t("binary.elapsed", { elapsed: formatDuration(Math.min(progress.elapsed_secs, progress.duration_secs)), duration: formatDuration(progress.duration_secs) })}
          </span>
        )}
      </div>
      <ol className="hf-stages">
        {BINARY_STAGES.map((stage, index) => (
          <li key={stage} data-state={index < stageIndex ? "done" : index === stageIndex ? "current" : "next"}>{t(`binary.stage.${stage}`)}</li>
        ))}
      </ol>
      <div className="hf-progress-track"><div className="hf-progress-fill" style={{ width: `${share}%` }} /></div>
      {progress && progress.execs_done !== null
        ? <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))" }}>
          {tiles.map(([label, value]) => (
            <div key={label} className="hf-stat"><div className="hf-field-label">{t(label)}</div><div className="hf-stat-value">{value}</div></div>
          ))}
        </div>
        : <p className="text-xs text-text-muted">{t("binary.waitingForStats")}</p>}
    </section>
  );
}

/** Earlier sessions with Open and Continue. */
export function SessionHistory({ sessions, onOpen, onContinue, busy }: {
  sessions: BinarySessionSummary[]; onOpen: (session: BinarySessionSummary) => void;
  onContinue: (session: BinarySessionSummary) => void; busy: boolean;
}) {
  const { t, locale } = useI18n();
  const when = (value: string | null) => value ? new Date(value).toLocaleString(locale) : "-";
  return (
    <section className="surface-card overflow-hidden" aria-label={t("binary.history")}>
      <div className="hf-form-section flex flex-col gap-1">
        <h2 className="text-sm font-semibold flex items-center gap-2 text-text-primary"><History size={16} className="text-text-muted" />{t("binary.history")}</h2>
        <p className="text-xs text-text-secondary">{t("binary.historyHint")}</p>
      </div>
      {sessions.length === 0
        ? <p className="hf-form-section text-sm text-text-muted">{t("binary.noHistory")}</p>
        : (
          <ul className="hf-form-section flex flex-col gap-2" style={{ margin: 0, listStyle: "none" }}>
            {sessions.map((session) => (
              <li key={session.session} className="hf-history-row">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap text-sm">
                    <span className="font-semibold text-text-primary">{session.binary_name || session.binary_sha256.slice(0, 12)}</span>
                    <Badge>{t(`binary.mode.${session.input}`)}</Badge>
                    {session.distinct_findings > 0 && <Badge variant="error">{t("binary.findingsCount", { distinct: session.distinct_findings, confirmed: session.confirmed })}</Badge>}
                    {session.continued_from && <Badge variant="accent">{t("binary.continued")}</Badge>}
                  </div>
                  <p className="text-xs text-text-muted font-mono" style={{ marginTop: 2 }}>
                    {when(session.finished_at)} · {formatDuration(session.duration_secs)} · {count(session.execs_done)} execs · {session.session.slice(0, 8)}
                  </p>
                </div>
                <div className="flex gap-2 shrink-0">
                  <Button variant="outline" size="sm" disabled={busy} onClick={() => onOpen(session)}>{t("binary.open")}</Button>
                  {session.can_continue && (
                    <Button variant="outline" size="sm" disabled={busy} onClick={() => onContinue(session)}>
                      <RotateCcw size={13} />{t("binary.continue")}
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
    </section>
  );
}

export function ContinueBanner({ session, onCancel }: { session: BinarySessionSummary; onCancel: () => void }) {
  const { t } = useI18n();
  return (
    <div role="status" className="hf-ai-note flex-row items-center justify-between gap-3 flex-wrap">
      <span className="text-sm text-text-primary flex items-center gap-2">
        <Play size={14} className="text-accent" />
        {t("binary.continuing", { session: session.session.slice(0, 8), binary: session.binary_name })}
      </span>
      <Button variant="ghost" size="sm" onClick={onCancel}>{t("binary.cancelContinue")}</Button>
    </div>
  );
}
