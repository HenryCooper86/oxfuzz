import type { ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { useI18n } from "../../i18n";

// The shared "this failed to load" placeholder -- the error-colored sibling of
// EmptyState/LoadingState, so failures look the same everywhere (an error
// circle, a title, the message, and an optional retry action) instead of each
// view hand-rolling its own error card.
export function ErrorState({
  title,
  message,
  action,
}: {
  title?: string;
  message: string;
  action?: ReactNode;
}) {
  const { t } = useI18n();
  const heading = title ?? t("ui.errorTitle");
  return (
    <div
      className="surface-card flex flex-col items-center justify-center text-center"
      style={{ padding: "var(--space-xl) var(--space-md)" }}
    >
      <div
        className="flex items-center justify-center mb-3 rounded-full"
        style={{
          width: "48px",
          height: "48px",
          background: "var(--error-subtle)",
          border: "1px solid var(--border)",
          color: "var(--error)",
        }}
      >
        <AlertTriangle size={20} />
      </div>
      <p className="text-sm font-medium text-text-primary mb-1">{heading}</p>
      <p
        className="text-xs text-text-muted max-w-sm font-mono"
        style={{ lineHeight: 1.5, wordBreak: "break-word" }}
      >
        {message}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
