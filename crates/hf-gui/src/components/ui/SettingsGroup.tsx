// Reusable settings layout primitives.

import type { ReactNode } from "react";
import { Separator } from "./Separator";

interface SettingsGroupProps {
  title: string;
  children: ReactNode;
}

export function SettingsGroup({ title, children }: SettingsGroupProps) {
  return (
    <div
      className="surface-card"
      style={{ padding: "var(--space-md)", marginBottom: "var(--space-md)" }}
    >
      <h3 className="text-sm font-semibold text-text-primary mb-3">{title}</h3>
      {children}
    </div>
  );
}

interface SettingsItemProps {
  label: string;
  children: ReactNode;
  description?: string;
}

export function SettingsItem({ label, children, description }: SettingsItemProps) {
  return (
    <div className="flex flex-col gap-1 mb-3">
      <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
        {label}
      </label>
      {children}
      {description && <p className="text-xs text-text-muted">{description}</p>}
    </div>
  );
}

export { Separator };