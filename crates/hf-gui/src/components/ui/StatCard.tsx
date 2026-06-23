import type { ReactNode } from "react";

interface StatCardProps {
  icon: ReactNode;
  label: string;
  value: string | number;
  color?: string;
}

export function StatCard({ icon, label, value, color = "var(--accent)" }: StatCardProps) {
  return (
    <div className="surface-card flex items-center gap-3" style={{ padding: "var(--space-md)" }}>
      <div style={{ color }}>{icon}</div>
      <div className="flex flex-col">
        <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
          {label}
        </span>
        <span className="text-lg font-semibold" style={{ color }}>
          {typeof value === "number" ? value.toLocaleString() : value}
        </span>
      </div>
    </div>
  );
}