import { Moon, Sun } from "lucide-react";

interface HeaderProps {
  theme: "dark" | "light";
  onToggleTheme: () => void;
}

export function Header({ theme, onToggleTheme }: HeaderProps) {
  return (
    <header
      className="flex items-center justify-between flex-shrink-0 select-none"
      style={{
        height: "52px",
        padding: "0 var(--space-lg)",
        background: "var(--surface-primary)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <span
        style={{
          fontFamily: "var(--font-display)",
          fontSize: "17px",
          fontWeight: 400,
          fontStyle: "italic",
          letterSpacing: "0.01em",
          opacity: 0.9,
        }}
      >
        hobot_fuzz
      </span>
      <div className="flex items-center gap-1">
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
        >
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
      </div>
    </header>
  );
}