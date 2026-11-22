import "../i18n.parityRun";
import { useI18n } from "../i18nContext";
import { Input, Select, Switch } from "./ui";
import {
  isAflEngine,
  runOptionsError,
  type AiPolicy,
  type RunOptionsState,
  type SanitizerChoice,
} from "../lib/parityRun";

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
      {children}
    </span>
  );
}

/**
 * Per-run options shared by single runs and campaigns, mirroring the
 * `oxfuzz run` / `oxfuzz campaign` flags. Controlled by the owner so the run
 * button can read the same state.
 */
export function RunOptionsFields({
  value,
  onChange,
  engine,
  maxCpus,
  showCpus = true,
  disabled = false,
}: {
  value: RunOptionsState;
  onChange: (next: RunOptionsState) => void;
  engine: string;
  maxCpus: number | null;
  showCpus?: boolean;
  disabled?: boolean;
}) {
  const { t } = useI18n();
  const error = runOptionsError(value, { maxCpus, showCpus });
  const set = <K extends keyof RunOptionsState>(key: K, next: RunOptionsState[K]) =>
    onChange({ ...value, [key]: next });
  const afl = isAflEngine(engine);
  const sanitizerOptions: { value: SanitizerChoice; label: string }[] = [
    { value: "none", label: t("runOpts.sanitizerNone") },
    { value: "address", label: "address" },
    { value: "undefined", label: "undefined" },
    { value: "memory", label: "memory" },
    { value: "thread", label: "thread" },
  ];
  const aiOptions: { value: AiPolicy; label: string }[] = [
    { value: "auto", label: t("runOpts.aiAuto") },
    { value: "require", label: t("runOpts.aiRequire") },
    { value: "off", label: t("runOpts.aiOff") },
  ];
  return (
    <div className="flex flex-col gap-3" role="group" aria-label={t("runOpts.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-xs font-semibold text-text-primary">{t("runOpts.title")}</span>
        <span className="text-xs text-text-muted">{t("runOpts.hint")}</span>
      </div>
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" }}>
        <div className="flex flex-col gap-1">
          <FieldLabel>{t("runOpts.seed")}</FieldLabel>
          <Input
            mono
            inputMode="numeric"
            aria-label={t("runOpts.seed")}
            placeholder={t("runOpts.seedPlaceholder")}
            value={value.seed}
            disabled={disabled}
            onChange={(e) => set("seed", e.target.value.trim())}
          />
          <span className="text-xs text-text-muted">{t("runOpts.seedHelp")}</span>
        </div>
        {showCpus && (
          <div className="flex flex-col gap-1">
            <FieldLabel>{t("runOpts.cpus")}</FieldLabel>
            <Input
              type="number"
              min={1}
              max={maxCpus ?? undefined}
              aria-label={t("runOpts.cpus")}
              placeholder={maxCpus === null ? "" : String(maxCpus)}
              value={value.cpus}
              disabled={disabled}
              onChange={(e) => set("cpus", e.target.value)}
            />
            <span className="text-xs text-text-muted">
              {maxCpus === null ? t("runOpts.cpusHelpUnknown") : t("runOpts.cpusHelp", { max: maxCpus })}
            </span>
          </div>
        )}
        <div className="flex flex-col gap-1">
          <FieldLabel>{t("runOpts.timeout")}</FieldLabel>
          <Input
            type="number"
            min={1}
            aria-label={t("runOpts.timeout")}
            value={value.timeoutMs}
            disabled={disabled}
            onChange={(e) => set("timeoutMs", e.target.value)}
          />
          <span className="text-xs text-text-muted">{t("runOpts.timeoutHelp")}</span>
        </div>
        <div className="flex flex-col gap-1">
          <FieldLabel>{t("runOpts.sanitizer")}</FieldLabel>
          <Select
            ariaLabel={t("runOpts.sanitizer")}
            value={value.sanitizer}
            disabled={disabled}
            onChange={(next) => set("sanitizer", next as SanitizerChoice)}
            options={sanitizerOptions}
          />
          <span className="text-xs text-text-muted">{t("runOpts.sanitizerHelp")}</span>
        </div>
        <div className="flex flex-col gap-1">
          <FieldLabel>{t("runOpts.ai")}</FieldLabel>
          <Select
            ariaLabel={t("runOpts.ai")}
            value={value.ai}
            disabled={disabled}
            onChange={(next) => set("ai", next as AiPolicy)}
            options={aiOptions}
          />
          <span className="text-xs text-text-muted">{t("runOpts.aiHelp")}</span>
        </div>
      </div>
      {afl && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-col gap-1">
            <Switch
              checked={value.resume}
              onChange={(next) => set("resume", next)}
              ariaLabel={t("runOpts.resume")}
              label={t("runOpts.resume")}
              disabled={disabled}
            />
            <span className="text-xs text-text-muted">{t("runOpts.resumeHelp")}</span>
          </div>
          <div className="flex flex-col gap-1">
            <Switch
              checked={value.cmplog}
              onChange={(next) => set("cmplog", next)}
              ariaLabel={t("runOpts.cmplog")}
              label={t("runOpts.cmplog")}
              disabled={disabled}
            />
            <span className="text-xs text-text-muted">{t("runOpts.cmplogHelp")}</span>
          </div>
        </div>
      )}
      {error && <p role="alert" className="text-xs text-error">{t(error, { max: maxCpus ?? 0 })}</p>}
    </div>
  );
}
