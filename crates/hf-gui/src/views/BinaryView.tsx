import "../i18n.parityBinary";
import { useCallback, useEffect, useRef, useState } from "react";
import { Cpu, FileSearch, FolderOpen, Info, Play } from "lucide-react";
import { BinaryOutcome } from "../components/binary/BinaryFindings";
import {
  ContinueBanner,
  DictionaryPanel,
  ProfilePanel,
  ProgressPanel,
  SeedDraftPanel,
  SessionHistory,
} from "../components/binary/BinaryAssist";
import { Badge, Button, EmptyState, Input, Switch, ViewHeader } from "../components/ui";
import { DurationInput } from "../components/ui/DurationInput";
import { useI18n } from "../i18nContext";
import { pickFile, pickFolder } from "../lib";
import {
  BINARY_INPUT_MODES,
  DEFAULT_BINARY_DURATION_SECS,
  DEFAULT_BINARY_TIMEOUT_MS,
  binaryFuzz,
  binaryInspect,
  binaryProgress,
  binarySession,
  binarySessions,
  binaryStop,
  sessionBinary,
  type BinaryFuzzOutcome,
  type BinaryInputMode,
  type BinaryProfile,
  type BinaryProgress,
  type BinarySessionSummary,
} from "../lib/parityBinary";
import { useProject } from "../providers/project";

/** How long typing pauses before the binary is analyzed, and how often a run is polled. */
const INSPECT_DELAY_MS = 450;
const PROGRESS_POLL_MS = 1500;

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

export function BinaryView() {
  const { t } = useI18n();
  const { activeProject } = useProject();
  const project = activeProject || "";
  const [binary, setBinaryValue] = useState("");
  const [input, setInputValue] = useState<BinaryInputMode>("file");
  // Whether the operator picked a mode; an analysis suggestion applies only until then.
  const inputTouched = useRef(false);
  const [seeds, setSeeds] = useState("");
  const [libraries, setLibraries] = useState("");
  const [duration, setDuration] = useState(String(DEFAULT_BINARY_DURATION_SECS));
  const [timeoutMs, setTimeoutMs] = useState(String(DEFAULT_BINARY_TIMEOUT_MS));
  const [profile, setProfile] = useState<BinaryProfile | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const [tokens, setTokens] = useState<string[]>([]);
  const [useDictionary, setUseDictionary] = useState(false);
  const [continueFrom, setContinueFrom] = useState<BinarySessionSummary | null>(null);
  const [compcov, setCompcov] = useState(true);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<BinaryProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<BinaryFuzzOutcome | null>(null);
  const [history, setHistory] = useState<BinarySessionSummary[]>([]);
  const [opening, setOpening] = useState(false);

  const durationSecs = Number(duration);
  const timeout = Number(timeoutMs);
  const validDuration = duration.trim() !== "" && Number.isSafeInteger(durationSecs) && durationSecs >= 1;
  const validTimeout = timeoutMs.trim() !== "" && Number.isSafeInteger(timeout) && timeout >= 1;
  const canStart = !running && !!project && binary.trim() !== "" && validDuration && validTimeout;

  function setBinary(value: string) {
    setBinaryValue(value);
    setContinueFrom(null);
    if (!value.trim()) { setProfile(null); setInspectError(null); }
  }
  function setInput(mode: BinaryInputMode) {
    setInputValue(mode);
    inputTouched.current = true;
  }

  const loadHistory = useCallback(() => {
    if (!project) return;
    binarySessions(project)
      .then((sessions) => setHistory(Array.isArray(sessions) ? sessions : []))
      .catch(() => setHistory([])); // no history can be read (web mode, no workspace): show none
  }, [project]);
  useEffect(loadHistory, [loadHistory]);

  // Analyze the binary once typing pauses; nothing is run.
  useEffect(() => {
    const path = binary.trim();
    if (!path) return;
    let live = true;
    const timer = window.setTimeout(() => {
      setInspecting(true);
      binaryInspect(path)
        .then((found) => {
          if (!live || !found || !Array.isArray(found.dictionary)) return;
          setProfile(found); setInspectError(null);
          setTokens(found.dictionary);
          setUseDictionary(found.dictionary.length > 0);
          if (!inputTouched.current) setInputValue(found.suggested_input);
        })
        .catch((e) => { if (live) { setProfile(null); setInspectError(String(e)); } })
        .finally(() => { if (live) setInspecting(false); });
    }, INSPECT_DELAY_MS);
    return () => { live = false; window.clearTimeout(timer); };
  }, [binary]);

  // Poll the running session's stage and counters.
  useEffect(() => {
    if (!running || !project) return;
    let live = true;
    const poll = () => binaryProgress(project)
      .then((found) => { if (live && found && typeof found.stage === "string") setProgress(found); })
      .catch(() => undefined); // a missed poll is retried on the next tick
    void poll();
    const timer = window.setInterval(() => void poll(), PROGRESS_POLL_MS);
    return () => { live = false; window.clearInterval(timer); };
  }, [running, project]);

  async function start() {
    if (!canStart) return;
    setProgress(null);
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
        dictionary: useDictionary ? tokens : [],
        continueFrom: continueFrom?.session,
        compcov,
      }));
      setContinueFrom(null);
      loadHistory();
    } catch (e) {
      setError(String(e));
    } finally { setRunning(false); }
  }

  async function open(session: BinarySessionSummary) {
    setOpening(true); setError(null);
    try {
      setOutcome(await binarySession(project, session.session));
    } catch (e) {
      setError(String(e));
    } finally { setOpening(false); }
  }

  function continueSession(session: BinarySessionSummary) {
    setBinaryValue(sessionBinary(session.workspace));
    setInputValue(session.input);
    inputTouched.current = true;
    setContinueFrom(session);
    document.querySelector(".view-scroll")?.scrollTo({ top: 0, behavior: "smooth" });
  }

  return (
    <div className="flex flex-col gap-4">
      <ViewHeader title={t("title.binary")} description={t("binary.subtitle")} />
      <p className="text-sm text-text-secondary">{t("binary.requirement")}</p>
      <section className="surface-card overflow-hidden">
        {continueFrom && (
          <FormSection><ContinueBanner session={continueFrom} onCancel={() => setContinueFrom(null)} /></FormSection>
        )}
        <FormSection>
          <PathField
            id="binary-path" label={t("binary.path")} value={binary} onChange={setBinary}
            placeholder={t("binary.pathPlaceholder")} pickLabel={t("binary.browse")} pickIcon={<FileSearch size={14} />}
            onPick={() => pickFile(t("binary.path"))}
          />
          {inspecting && <p role="status" className="text-xs text-text-muted">{t("binary.inspecting")}</p>}
          {inspectError && !inspecting && <p role="alert" className="text-xs text-error">{t("binary.inspectFailed")}: {inspectError}</p>}
          {profile && <ProfilePanel profile={profile} />}
        </FormSection>
        <FormSection>
          <fieldset className="flex flex-col gap-2 min-w-0" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="hf-field-label" style={{ marginBottom: 8 }}>{t("binary.inputMode")}</legend>
            {profile && profile.suggestion_reasons.length > 0 && (
              <p className="text-xs text-text-secondary flex items-center gap-2 flex-wrap" style={{ marginBottom: 4 }}>
                <Badge variant="accent">{t("binary.suggested")}: {t(`binary.mode.${profile.suggested_input}`)}</Badge>
                {profile.suggestion_reasons.join(" ")}
                {input !== profile.suggested_input && (
                  <Button variant="ghost" size="sm" onClick={() => setInput(profile.suggested_input)}>{t("binary.useSuggested")}</Button>
                )}
              </p>
            )}
            <div className="hf-grid-260 grid gap-2">
              {BINARY_INPUT_MODES.map((mode) => (
                <label key={mode} className="hf-choice">
                  <input type="radio" name="binary-input" value={mode} checked={input === mode} onChange={() => setInput(mode)} />
                  <span className="hf-choice-dot" aria-hidden="true" />
                  <span className="min-w-0">
                    <span className="flex items-center gap-2 text-13px font-medium text-text-primary">
                      {t(`binary.mode.${mode}`)}
                      {profile?.suggested_input === mode && <Badge variant="accent">{t("binary.suggested")}</Badge>}
                    </span>
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
          {binary.trim() !== "" && (
            <SeedDraftPanel project={project} binary={binary.trim()} input={input} usedDirectory={seeds} onUse={setSeeds} />
          )}
        </FormSection>
        {profile && (
          <FormSection>
            <DictionaryPanel
              project={project} binary={binary.trim()} input={input} tokens={tokens} enabled={useDictionary}
              onTokens={setTokens} onEnabled={setUseDictionary}
            />
          </FormSection>
        )}
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
          <div className="flex flex-col gap-1">
            <Switch checked={compcov} onChange={setCompcov} label={t("binary.compcov")} />
            <p className="text-xs text-text-muted">{t("binary.compcovHint")}</p>
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
            {t(continueFrom ? "binary.continue" : "binary.start")}
          </Button>
        </div>
      </section>

      {running && (
        <ProgressPanel
          progress={progress}
          onStop={async (session) => {
            await binaryStop(project, session);
            setProgress((current) => (current ? { ...current, stopping: true } : current));
          }}
        />
      )}
      {error && (
        <div role="alert" className="hf-alert-error text-sm">
          <div className="font-semibold">{t("binary.failed")}</div>
          <div style={{ overflowWrap: "anywhere" }}>{error}</div>
        </div>
      )}
      {outcome ? (
        <BinaryOutcome project={project} outcome={outcome} />
      ) : !running && !error && (
        <EmptyState icon={<Cpu size={22} />} title={t("binary.emptyTitle")} hint={t("binary.emptyBody")} />
      )}
      {project && <SessionHistory sessions={history} onOpen={(session) => void open(session)} onContinue={continueSession} busy={running || opening} />}
    </div>
  );
}
