import "../i18n.parityHarness";
import { useI18n } from "../i18nContext";
import { Input } from "./ui";
import { Switch } from "./ui/Switch";
import { clampRepairs, MAX_REPAIRS, type HarnessOptions, type HarnessSanitizer } from "../lib/parityHarness";

interface Props {
  value: HarnessOptions;
  onChange: (next: HarnessOptions) => void;
  engine: string;
  disabled: boolean;
}

const SANITIZERS: [HarnessSanitizer, string][] = [
  ["address", "parityHarness.sanitizerAddress"],
  ["undefined", "parityHarness.sanitizerUndefined"],
  ["thread", "parityHarness.sanitizerThread"],
  ["memory", "parityHarness.sanitizerMemory"],
];

/** Build and qualification options, mirroring `oxfuzz harness`. Always visible. */
export function HarnessOptionsPanel({ value, onChange, engine, disabled }: Props) {
  const { t } = useI18n();
  const afl = engine === "afl++";
  return <section className="surface-card flex flex-col gap-3 text-xs" style={{ padding: "var(--space-md)" }}>
    <h3 className="text-sm font-medium">{t("parityHarness.optionsTitle")}</h3>
    <label className="flex flex-col gap-1">{t("parityHarness.sanitizer")}
      <select className="rounded border border-border bg-surface-primary p-1 w-64 max-w-full" aria-label={t("parityHarness.sanitizer")} disabled={disabled}
        value={value.sanitizer} onChange={(event) => onChange({ ...value, sanitizer: event.target.value as HarnessSanitizer })}>
        {SANITIZERS.map(([option, label]) => <option key={option} value={option}>{t(label)}</option>)}
      </select>
      <span className="text-text-muted">{t("parityHarness.sanitizerHelp")}</span>
    </label>
    <label className="flex flex-col gap-1">
      <span className="flex items-center gap-2"><Switch ariaLabel={t("parityHarness.cmplog")} disabled={disabled || !afl} checked={afl && value.cmplog}
        onChange={(next) => onChange({ ...value, cmplog: next })} />{t("parityHarness.cmplog")}</span>
      <span className="text-text-muted">{t("parityHarness.cmplogHelp")}</span>
    </label>
    <label className="flex flex-col gap-1">
      <span className="flex items-center gap-2"><Switch ariaLabel={t("parityHarness.persistent")} disabled={disabled || !afl} checked={afl && value.persistent}
        onChange={(next) => onChange({ ...value, persistent: next })} />{t("parityHarness.persistent")}</span>
      <span className="text-text-muted">{t("parityHarness.persistentHelp")}</span>
    </label>
    <label className="flex flex-col gap-1">{t("parityHarness.repairs")}
      <Input type="number" min={0} max={MAX_REPAIRS} className="w-24" aria-label={t("parityHarness.repairs")} disabled={disabled}
        value={value.repairs} onChange={(event) => onChange({ ...value, repairs: clampRepairs(Number(event.target.value)) })} />
      <span className="text-text-muted">{t("parityHarness.repairsHelp")}</span>
    </label>
    <label className="flex flex-col gap-1">
      <span className="flex items-center gap-2"><Switch ariaLabel={t("parityHarness.skipReview")} disabled={disabled} checked={value.skipModelReview}
        onChange={(next) => onChange({ ...value, skipModelReview: next })} />{t("parityHarness.skipReview")}</span>
      <span role="note" style={{ color: "var(--warning, var(--text-secondary))" }}>{t("parityHarness.skipReviewWarning")}</span>
    </label>
  </section>;
}
