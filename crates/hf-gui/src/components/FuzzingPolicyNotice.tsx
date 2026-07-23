import { AlertTriangle, LoaderCircle } from "lucide-react";
import { useI18n } from "../i18nContext";

/**
 * Notice shown where the effective fuzzing policy is missing. Callers render it
 * only under `!fuzzingSettings`, so the policy either has not arrived yet or the
 * load settled without one -- there is no success state to show. The prop names
 * that state directly: passing the loader's settled flag straight through would
 * mean `true` selects the red failure branch.
 */
export function FuzzingPolicyNotice({
  state,
  error,
}: {
  state: "loading" | "unavailable";
  error: string | null;
}) {
  const { t } = useI18n();
  const unavailable = state === "unavailable";
  return (
    <div
      className="surface-card flex items-center gap-2 text-xs"
      role="status"
      style={{
        borderLeft: `3px solid ${unavailable ? "var(--error)" : "var(--accent)"}`,
        color: unavailable ? "var(--error)" : "var(--text-secondary)",
        padding: "var(--space-sm) var(--space-md)",
      }}
    >
      {unavailable ? (
        <AlertTriangle size={15} />
      ) : (
        <LoaderCircle className="animate-spin" size={15} />
      )}
      <span>
        {unavailable
          ? t("fuzzing.policyUnavailable", { error: error ?? "" })
          : t("fuzzing.policyLoading")}
      </span>
    </div>
  );
}
