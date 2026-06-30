import { Moon, Sun, PanelLeft } from "lucide-react";
import type { ReactNode } from "react";

interface HeaderProps {
  title: string;
  icon?: ReactNode;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  actions?: ReactNode;
  onToggleSidebar?: () => void;
  /** Reserve space for the macOS traffic lights when the sidebar is hidden. */
  reserveLeftInset?: boolean;
}

export function Header({ title, icon, theme, onToggleTheme, actions, onToggleSidebar, reserveLeftInset }: HeaderProps) {
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
      <div className="flex items-center gap-2" data-tauri-drag-region>
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="flex items-center justify-center rounded-md transition-all duration-150"
            style={{
              width: "32px",
              height: "32px",
              color: "var(--text-muted)",
              background: "transparent",
              border: "none",
              cursor: "pointer",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = "var(--text-primary)";
              e.currentTarget.style.background = "var(--surface-hover)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = "var(--text-muted)";
              e.currentTarget.style.background = "transparent";
            }}
            title="Toggle sidebar"
            aria-label="Toggle sidebar"
          >
            <PanelLeft size={18} />
          </button>
        )}
        {icon && (
          <span data-tauri-drag-region style={{ color: "var(--accent)" }}>
            {icon}
          </span>
        )}
        <span
          data-tauri-drag-region
          style={{
            fontFamily: "var(--font-display)",
            fontSize: "17px",
            fontWeight: 400,
            fontStyle: "italic",
            letterSpacing: "0.01em",
            opacity: 0.9,
          }}
        >
          {title}
        </span>
      </div>
      <div className="flex items-center gap-1">
        {actions}
        <button
          onClick={onToggleTheme}
          className="flex items-center justify-center rounded-md transition-all duration-150"
          style={{
            width: "32px",
            height: "32px",
            color: "var(--text-muted)",
            background: "transparent",
            border: "none",
            cursor: "pointer",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = "var(--text-primary)";
            e.currentTarget.style.background = "var(--surface-hover)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = "var(--text-muted)";
            e.currentTarget.style.background = "transparent";
          }}
          title="Toggle theme"
          aria-label="Toggle theme"
        >
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
      </div>
    </header>
  );
}