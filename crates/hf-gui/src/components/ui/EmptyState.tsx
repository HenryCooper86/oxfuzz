import type { ReactNode } from "react";

// A consistent empty-state placeholder: a muted accent icon, an optional title,
// a hint line, and an optional call-to-action. Used wherever a list/section has
// no content yet, so empty states look the same across the app.
export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon: ReactNode;
  title?: string;
  hint: string;
  action?: ReactNode;
}) {
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
          background: "var(--accent-subtle)",
          border: "1px solid var(--border)",
          color: "var(--accent)",
        }}
      >
        {icon}
      </div>
      {title && <p className="text-sm font-medium text-text-primary mb-1">{title}</p>}
      <p className="text-sm text-text-secondary max-w-sm" style={{ lineHeight: 1.5 }}>
        {hint}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
