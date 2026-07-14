import type { CSSProperties } from "react";
import { useI18n } from "../../i18n";

// Shared loading primitives so spinners and placeholders look the same
// everywhere (the complement to EmptyState).

/** A small spinning ring that inherits the current text color. */
export function Spinner({ size = 16, className }: { size?: number; className?: string }) {
  return (
    <span
      className={`inline-block animate-spin rounded-full border-2 border-current border-t-transparent ${className ?? ""}`}
      style={{ width: size, height: size }}
      aria-hidden="true"
    />
  );
}

/** A centered spinner + label, for a section/panel that is loading. */
export function LoadingState({ label }: { label?: string }) {
  const { t } = useI18n();
  return (
    <div
      className="surface-card flex flex-col items-center justify-center text-center text-text-muted"
      style={{ padding: "var(--space-xl) var(--space-md)", gap: "var(--space-sm)" }}
    >
      <Spinner size={20} />
      <p className="text-sm">{label ?? t("common.loading")}</p>
    </div>
  );
}

/** A shimmering placeholder block, sized via className/style, for skeleton rows. */
export function Skeleton({ className, style }: { className?: string; style?: CSSProperties }) {
  return (
    <div
      className={`animate-pulse rounded-md ${className ?? ""}`}
      style={{ background: "var(--surface-active)", ...style }}
      aria-hidden="true"
    />
  );
}
