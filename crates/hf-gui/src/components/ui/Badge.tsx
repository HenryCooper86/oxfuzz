interface BadgeProps {
  children: React.ReactNode;
  variant?: "default" | "accent" | "success" | "error" | "warning";
  size?: "sm" | "xs";
}

const variantStyles = {
  default: { background: "var(--surface-active)", color: "var(--text-muted)" },
  accent: { background: "var(--accent-subtle)", color: "var(--accent)" },
  success: { background: "rgba(111,207,151,0.1)", color: "var(--success)" },
  error: { background: "var(--error-subtle)", color: "var(--error)" },
  warning: { background: "rgba(240,192,80,0.1)", color: "var(--warning)" },
};

export function Badge({ children, variant = "default", size = "xs" }: BadgeProps) {
  return (
    <span
      className="inline-flex items-center rounded-sm font-medium"
      style={{
        ...variantStyles[variant],
        fontSize: size === "xs" ? "10px" : "11px",
        padding: "2px 6px",
        lineHeight: 1.4,
      }}
    >
      {children}
    </span>
  );
}