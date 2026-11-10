import { PanelLeft } from "lucide-react";
import type { ReactNode } from "react";
import { ThemeButton } from "./ThemeButton";
import type { Theme } from "../providers/prefs";
import { IconButton } from "./ui/IconButton";

interface HeaderProps {
  title: string;
  icon?: ReactNode;
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  actions?: ReactNode;
  onToggleSidebar?: () => void;
  /** Reserve space for the macOS traffic lights when the sidebar is hidden. */
  reserveLeftInset?: boolean;
}

export function Header({ title, icon, theme, onThemeChange, actions, onToggleSidebar, reserveLeftInset }: HeaderProps) {
  return (
    <header
      data-tauri-drag-region
      className="flex items-center justify-between flex-shrink-0 select-none"
      style={{
        height: "52px",
        paddingTop: 0,
        paddingBottom: 0,
        paddingRight: "var(--space-lg)",
        paddingLeft: reserveLeftInset ? "78px" : "var(--space-lg)",
        background: "var(--surface-primary)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div className="flex items-center gap-3" data-tauri-drag-region>
        {onToggleSidebar && (
          <IconButton size={32} onClick={onToggleSidebar} title="Toggle sidebar" aria-label="Toggle sidebar">
            <PanelLeft size={18} />
          </IconButton>
        )}
        {icon && (
          <span data-tauri-drag-region style={{ color: "var(--text-secondary)" }}>
            {icon}
          </span>
        )}
        <span
          data-tauri-drag-region
          style={{
            fontFamily: "var(--font-display)",
            fontSize: "14px",
            fontWeight: 500,
            color: "var(--text-secondary)",
          }}
        >
          {title}
        </span>
      </div>
      <div className="flex items-center gap-1">
        {actions}
        <ThemeButton theme={theme} onChange={onThemeChange} />
      </div>
    </header>
  );
}
