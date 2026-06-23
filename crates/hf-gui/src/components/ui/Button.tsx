import { forwardRef } from "react";

type Variant = "primary" | "ghost" | "danger" | "outline" | "icon";
type Size = "sm" | "md";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

const variantClasses: Record<Variant, string> = {
  primary: "bg-[var(--accent)] text-[var(--accent-contrast)] border-transparent hover:op-85",
  ghost: "bg-transparent text-text-secondary border-border hover:(bg-surface-hover text-text-primary)",
  danger: "bg-[var(--error)] text-white border-transparent hover:op-85",
  outline: "bg-surface-primary text-text-secondary border-border hover:(bg-surface-hover text-text-primary)",
  icon: "bg-transparent text-text-muted border-transparent hover:(text-text-primary border-border bg-surface-hover)",
};

const sizeClasses: Record<Size, string> = {
  sm: "px-3 py-1 text-11px h-7",
  md: "px-4 py-1.5 text-12px h-8",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "ghost", size = "md", loading, className, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center gap-1 font-500 font-sans cursor-pointer rounded-md border border-solid transition-all duration-150 outline-none disabled:(op-55 cursor-not-allowed pointer-events-none) ${variantClasses[variant]} ${sizeClasses[size]} ${className ?? ""}`}
      {...props}
    >
      {loading ? <span className="animate-spin inline-block w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full" /> : null}
      {children}
    </button>
  ),
);
Button.displayName = "Button";