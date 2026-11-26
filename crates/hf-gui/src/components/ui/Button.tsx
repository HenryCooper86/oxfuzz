import { forwardRef } from "react";

type Variant = "primary" | "ghost" | "danger" | "outline" | "icon";
type Size = "sm" | "md";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

// Button hierarchy: one `primary` per area (filled gold), `outline` for the
// secondary action (raised surface + strong border), `ghost` for tertiary and
// toolbar actions, `danger` for destructive confirmation. Hover moves to a
// state color (never a fade) and press nudges the button down by half a pixel.
const variantClasses: Record<Variant, string> = {
  primary:
    "bg-[var(--accent)] text-[var(--accent-contrast)] border-[var(--accent)] shadow-[var(--accent-highlight)] hover:(bg-[var(--accent-hover)] border-[var(--accent-hover)])",
  ghost: "bg-transparent text-text-secondary border-transparent hover:(bg-surface-hover text-text-primary)",
  danger:
    "bg-[var(--danger-solid)] text-white border-[var(--danger-solid)] hover:(bg-[var(--danger-solid-hover)] border-[var(--danger-solid-hover)])",
  outline:
    "bg-surface-raised text-text-primary border-[var(--border-strong)] shadow-sm hover:(bg-surface-tertiary border-[var(--border-focus)])",
  icon: "bg-transparent text-text-muted border-transparent hover:(text-text-primary bg-surface-hover)",
};

const sizeClasses: Record<Size, string> = {
  sm: "px-2.5 py-1 text-11px h-7 gap-1.5",
  md: "px-3.5 py-1.5 text-12px h-8 gap-1.5",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "ghost", size = "md", loading, className, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center font-500 font-sans leading-none cursor-pointer rounded-md border border-solid transition-[background-color,border-color,color,box-shadow,transform] duration-120 ease-out outline-none active:translate-y-[0.5px] disabled:(op-50 cursor-not-allowed pointer-events-none shadow-none) ${variantClasses[variant]} ${sizeClasses[size]} ${className ?? ""}`}
      {...props}
    >
      {loading ? <span className="animate-spin inline-block w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full" /> : null}
      {children}
    </button>
  ),
);
Button.displayName = "Button";