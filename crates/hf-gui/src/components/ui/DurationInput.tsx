import { useState } from "react";
import { useI18n } from "../../i18nContext";
import { splitDuration, toSeconds, type DurationUnit } from "../../lib/duration";
import { Input } from "./Input";
import { Select } from "./Select";

/**
 * A duration field: an amount plus seconds / minutes / hours. The value in and
 * out is a seconds string, so callers keep storing and validating seconds.
 */
export function DurationInput({
  seconds,
  onChange,
  ariaLabel,
  invalid,
  describedBy,
  disabled,
}: {
  seconds: string;
  onChange: (seconds: string) => void;
  ariaLabel: string;
  invalid?: boolean;
  describedBy?: string;
  disabled?: boolean;
}) {
  const { t } = useI18n();
  // `prop` is the last value received; `emitted` the last value this field sent.
  // The display is re-derived only when the owner sets a value this field did
  // not send (a loaded default, a reset), so typing is never overwritten -- even
  // when the owner ignores an invalid or partial entry.
  const [shown, setShown] = useState(() => ({ prop: seconds, emitted: seconds, ...splitDuration(seconds) }));
  if (seconds !== shown.prop) {
    setShown(seconds === shown.emitted
      ? { ...shown, prop: seconds }
      : { prop: seconds, emitted: seconds, ...splitDuration(seconds) });
  }

  const emit = (amount: string, unit: DurationUnit) => {
    const next = toSeconds(amount, unit);
    setShown((current) => ({ ...current, emitted: next, amount, unit }));
    onChange(next);
  };

  return (
    <div className="flex gap-1 items-center">
      <Input
        type="number"
        min={0}
        step="any"
        aria-label={ariaLabel}
        aria-invalid={invalid}
        aria-describedby={describedBy}
        disabled={disabled}
        value={shown.amount}
        onChange={(event) => emit(event.target.value, shown.unit)}
        className="w-24"
      />
      <Select
        ariaLabel={t("duration.unit")}
        value={shown.unit}
        disabled={disabled}
        onChange={(unit) => emit(shown.amount, unit as DurationUnit)}
        options={[
          { value: "s", label: t("duration.seconds") },
          { value: "m", label: t("duration.minutes") },
          { value: "h", label: t("duration.hours") },
        ]}
        // The amount field takes the row's spare width; the unit must not be
        // squeezed until "minutes" is cut off.
        className="w-28 shrink-0"
      />
    </div>
  );
}
