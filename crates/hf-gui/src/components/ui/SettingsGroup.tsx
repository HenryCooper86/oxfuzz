// Settings layout primitives, modeled on y-agent's SettingsForm.
//
// A SettingsGroup renders an uppercase section title (and optional
// description) ABOVE a rounded card. Inside the card, each SettingsItem is a
// row with its label/description on the left and a control on the right.
// Rows are separated by hairline borders (see `.settings-item` rule in
// styles/index.css).

import type { ReactNode } from "react";
import { Separator } from "./Separator";

interface SettingsGroupProps {
  /** Uppercase section title shown above the card. */
  title: string;
  /** Optional helper text shown under the title. */
  description?: string;
  children: ReactNode;
}

export function SettingsGroup({ title, description, children }: SettingsGroupProps) {
  return (
    <div style={{ marginBottom: "var(--space-lg)" }}>
      <div style={{ padding: "0 4px 8px" }}>
        <div
          style={{
            fontSize: "11px",
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: "var(--text-muted)",
          }}
        >
          {title}
        </div>
        {description && (
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px", lineHeight: 1.5 }}>
            {description}
          </div>
        )}
      </div>
      <div
        style={{
          background: "var(--surface-secondary)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          overflow: "hidden",
        }}
      >
        {children}
      </div>
    </div>
  );
}

interface SettingsItemProps {
  /** Row label. */
  title: string;
  /** Optional secondary description under the label. */
  description?: string;
  /** The control rendered on the right (Switch, Select, Input, Button…). */
  children?: ReactNode;
  /**
   * When true, the control drops to a full-width row beneath the label
   * instead of sitting on the right. Use for textareas / wide inputs.
   */
  stacked?: boolean;
}

export function SettingsItem({ title, description, children, stacked }: SettingsItemProps) {
  return (
    <div
      className="settings-item"
      style={{
        display: "flex",
        flexDirection: stacked ? "column" : "row",
        alignItems: stacked ? "stretch" : "center",
        gap: stacked ? "8px" : "16px",
        minHeight: "44px",
        padding: "10px 14px",
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: "13px", fontWeight: 500, color: "var(--text-primary)" }}>{title}</div>
        {description && (
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px", lineHeight: 1.4 }}>
            {description}
          </div>
        )}
      </div>
      {children != null && <div style={{ flexShrink: 0, width: stacked ? "100%" : "auto" }}>{children}</div>}
    </div>
  );
}

export { Separator };
