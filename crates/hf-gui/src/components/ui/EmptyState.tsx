import type { ReactNode } from "react";

interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center text-center" style={{ padding: "var(--space-xl) var(--space-md)" }}>
      <div className="mb-3" style={{ opacity: 0.4, color: "var(--text-muted)" }}>{icon}</div>
      <p className="text-sm text-text-muted">{title}</p>
      <p className="text-xs text-text-muted mt-1">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}