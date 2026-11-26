interface BadgeProps {
  children: React.ReactNode;
  variant?: "default" | "accent" | "success" | "error" | "warning";
  size?: "sm" | "xs";
}

const variantStyles = {
  default: { background: "var(--surface-active)", color: "var(--text-secondary)", borderColor: "var(--border)" },
  accent: { background: "var(--accent-subtle)", color: "var(--accent)", borderColor: "var(--accent-border)" },
  success: { background: "var(--success-subtle)", color: "var(--success)", borderColor: "transparent" },
  error: { background: "var(--error-subtle)", color: "var(--error)", borderColor: "transparent" },
  warning: { background: "var(--warning-subtle)", color: "var(--warning)", borderColor: "transparent" },
};

export function Badge({ children, variant = "default", size = "xs" }: BadgeProps) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full font-medium whitespace-nowrap"
      style={{
        ...variantStyles[variant],
        borderWidth: 1,
        borderStyle: "solid",
        fontSize: size === "xs" ? "10px" : "11px",
        padding: "1px 7px",
        lineHeight: 1.5,
      }}
    >
      {children}
    </span>
  );
}