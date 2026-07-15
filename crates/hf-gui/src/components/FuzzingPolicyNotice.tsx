import { AlertTriangle, LoaderCircle } from "lucide-react";
import { useI18n } from "../i18nContext";

export function FuzzingPolicyNotice({ loaded, error }: { loaded: boolean; error: string | null }) {
  const { t } = useI18n();
  return (
    <div
      className="surface-card flex items-center gap-2 text-xs"
      role="status"
      style={{
        borderLeft: `3px solid ${loaded ? "var(--error)" : "var(--accent)"}`,
        color: loaded ? "var(--error)" : "var(--text-secondary)",
        padding: "var(--space-sm) var(--space-md)",
      }}
    >
      {loaded ? <AlertTriangle size={15} /> : <LoaderCircle className="animate-spin" size={15} />}
      <span>
        {loaded
          ? t("fuzzing.policyUnavailable", { error: error ?? "" })
          : t("fuzzing.policyLoading")}
      </span>
    </div>
  );
}
