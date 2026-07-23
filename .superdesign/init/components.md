# Shared UI Primitives

Framework: React 19 with TypeScript. Components are custom primitives, with Radix UI used selectively for accessible overlays and controls. Styling combines UnoCSS utility classes with CSS variables from `src/styles/index.css`.

## Button

- File: `crates/hf-gui/src/components/ui/Button.tsx`
- Description: Primary and secondary action button primitive.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
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
  ghost: "bg-transparent text-text-secondary border-transparent hover:(bg-surface-hover text-text-primary)",
  danger: "bg-[var(--error)] text-white border-transparent hover:op-85",
  outline: "bg-surface-primary text-text-secondary border-border hover:(bg-surface-hover text-text-primary)",
  icon: "bg-transparent text-text-muted border-transparent hover:(text-text-primary bg-surface-hover)",
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
```

## IconButton

- File: `crates/hf-gui/src/components/ui/IconButton.tsx`
- Description: Compact icon-only action primitive.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import { forwardRef } from "react";

// The one icon-only button for the whole app. Uses the `.hf-action-btn` look
// (transparent border at rest -> subtle surface + border on hover; `.danger`
// -> red hover), so bare icon actions read as real, consistent buttons instead
// of floating boxes. Callers must pass `title` / `aria-label` for the label.
interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Square size in px (default 28). */
  size?: number;
  /** Destructive affordance (red on hover). */
  danger?: boolean;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ size = 28, danger, className, style, type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={`hf-action-btn${danger ? " danger" : ""} ${className ?? ""}`}
      style={{ width: size, height: size, ...style }}
      {...props}
    />
  ),
);
IconButton.displayName = "IconButton";
```

## Input

- File: `crates/hf-gui/src/components/ui/Input.tsx`
- Description: Text input primitive with shared focus and disabled states.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import { forwardRef } from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  mono?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ mono, className, ...props }, ref) => (
    <input
      ref={ref}
      className={`w-full px-3 py-1.5 text-12px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary transition-colors duration-150 outline-none focus:border-[var(--border-focus)] placeholder:text-text-muted ${mono ? "font-[var(--font-mono)]" : "font-sans"} ${className ?? ""}`}
      {...props}
    />
  ),
);
Input.displayName = "Input";

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  mono?: boolean;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ mono, className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={`w-full px-3 py-2 text-12px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary transition-colors duration-150 outline-none focus:border-[var(--border-focus)] placeholder:text-text-muted resize-y leading-[1.65] tab-size-2 ${mono ? "font-[var(--font-mono)]" : "font-sans"} ${className ?? ""}`}
      {...props}
    />
  ),
);
Textarea.displayName = "Textarea";
```

## Select

- File: `crates/hf-gui/src/components/ui/Select.tsx`
- Description: Native and Radix-compatible selection primitive.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import * as RadixSelect from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";

interface SelectProps {
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  className?: string;
  mono?: boolean;
  disabled?: boolean;
  /**
   * Trigger text when nothing is selected. Radix reserves the empty string for
   * "no selection" -- an `Item` may not use it -- so an empty `options` list
   * plus a placeholder is how a select with nothing to offer says so, rather
   * than rendering a blank box.
   */
  placeholder?: string;
}

export function Select({
  value,
  options,
  onChange,
  className,
  mono,
  disabled,
  placeholder,
}: SelectProps) {
  return (
    <RadixSelect.Root value={value} onValueChange={onChange} disabled={disabled}>
      <RadixSelect.Trigger
        className={`inline-flex items-center justify-between gap-2 px-2 py-1.5 text-12px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary transition-colors duration-150 outline-none focus:border-[var(--border-focus)] cursor-pointer data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50 ${mono ? "font-[var(--font-mono)]" : "font-sans"} ${className ?? ""}`}
      >
        <RadixSelect.Value placeholder={placeholder} />
        <RadixSelect.Icon style={{ opacity: 0.7 }}>
          <ChevronDown size={14} />
        </RadixSelect.Icon>
      </RadixSelect.Trigger>
      <RadixSelect.Portal>
        <RadixSelect.Content
          position="popper"
          sideOffset={4}
          className={`overflow-hidden border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary z-50 ${mono ? "font-[var(--font-mono)]" : "font-sans"}`}
          style={{ boxShadow: "0 8px 24px rgba(0,0,0,0.25)", maxHeight: "300px" }}
        >
          <RadixSelect.Viewport className="p-1" style={{ maxHeight: "300px" }}>
            {options.map((o) => (
              <RadixSelect.Item
                key={o.value}
                value={o.value}
                className="relative flex items-center pl-7 pr-2 py-1.5 text-12px rounded-[var(--radius-sm)] cursor-pointer outline-none select-none data-[highlighted]:bg-[var(--surface-hover)]"
              >
                <RadixSelect.ItemIndicator className="absolute left-2 inline-flex items-center text-[var(--accent)]">
                  <Check size={13} />
                </RadixSelect.ItemIndicator>
                <RadixSelect.ItemText>{o.label}</RadixSelect.ItemText>
              </RadixSelect.Item>
            ))}
          </RadixSelect.Viewport>
        </RadixSelect.Content>
      </RadixSelect.Portal>
    </RadixSelect.Root>
  );
}
```

## Badge

- File: `crates/hf-gui/src/components/ui/Badge.tsx`
- Description: Compact semantic status label.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
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
```

## SeverityBadge

- File: `crates/hf-gui/src/components/ui/SeverityBadge.tsx`
- Description: Crash-severity status badge.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
// The one CASR-exploitability badge for the whole app, keyed by the serialized
// CrashSeverity. Previously duplicated in TriageView and the Knowledge view with
// slightly different labels/colors; consolidated here so severity always reads
// the same.
const SEVERITY_STYLE: Record<string, { label: string; bg: string; fg: string }> = {
  Exploitable: { label: "EXPLOITABLE", bg: "var(--error-subtle)", fg: "var(--error)" },
  ProbablyExploitable: { label: "PROBABLY EXPL.", bg: "rgba(217,119,6,0.16)", fg: "#d97706" },
  NotExploitable: { label: "NOT EXPL.", bg: "var(--surface-active)", fg: "var(--text-secondary)" },
  Undefined: { label: "UNCLASSIFIED", bg: "var(--surface-active)", fg: "var(--text-muted)" },
};

export function SeverityBadge({ severity, title }: { severity: string; title?: string }) {
  const s = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.Undefined;
  return (
    <span
      className="text-xs px-1.5 py-0.5 rounded-sm font-semibold shrink-0"
      style={{ background: s.bg, color: s.fg, letterSpacing: "0.03em" }}
      title={title ?? severity}
    >
      {s.label}
    </span>
  );
}
```

## Switch

- File: `crates/hf-gui/src/components/ui/Switch.tsx`
- Description: Boolean preference control.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
interface SwitchProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
  ariaLabel?: string;
  disabled?: boolean;
}

export function Switch({ checked, onChange, label, ariaLabel, disabled = false }: SwitchProps) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      disabled={disabled}
      aria-pressed={checked}
      aria-label={ariaLabel}
      className="flex items-center gap-2 outline-none focus-visible:[&>span]:outline-2 focus-visible:[&>span]:outline focus-visible:[&>span]:outline-[var(--accent)] focus-visible:[&>span]:outline-offset-2"
      style={{
        background: "transparent",
        border: "none",
        padding: 0,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.55 : 1,
      }}
    >
      <span
        className="rounded-full border border-solid transition-all duration-200 relative inline-block"
        style={{
          width: "36px",
          height: "20px",
          borderColor: "var(--border)",
          background: checked ? "var(--accent)" : "var(--surface-tertiary)",
        }}
      >
        <span
          className="rounded-full bg-white transition-all duration-200 absolute"
          style={{
            width: "14px",
            height: "14px",
            top: "2px",
            left: checked ? "18px" : "2px",
          }}
        />
      </span>
      {label && <span className="text-xs text-text-secondary">{label}</span>}
    </button>
  );
}
```

## Separator

- File: `crates/hf-gui/src/components/ui/Separator.tsx`
- Description: Horizontal or vertical visual divider.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
export function Separator({ orientation = "horizontal" }: { orientation?: "horizontal" | "vertical" }) {
  return (
    <div
      style={{
        background: "var(--border)",
        width: orientation === "horizontal" ? "100%" : "1px",
        height: orientation === "horizontal" ? "1px" : "100%",
      }}
    />
  );
}
```

## ViewHeader

- File: `crates/hf-gui/src/components/ui/ViewHeader.tsx`
- Description: Standard page title, description, and actions row.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
// The standard page header for a view: a title and a one-line description, with
// consistent type scale and spacing. Use at the top of every primary view so
// headers share one vertical rhythm.
export function ViewHeader({ title, description }: { title: string; description?: string }) {
  return (
    <div>
      <h1 className="text-xl font-semibold">{title}</h1>
      {description && <p className="text-sm text-text-secondary mt-0.5">{description}</p>}
    </div>
  );
}
```

## EmptyState

- File: `crates/hf-gui/src/components/ui/EmptyState.tsx`
- Description: Empty-result guidance state.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import type { ReactNode } from "react";

// A consistent empty-state placeholder: a muted accent icon, an optional title,
// a hint line, and an optional call-to-action. Used wherever a list/section has
// no content yet, so empty states look the same across the app.
export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon: ReactNode;
  title?: string;
  hint: string;
  action?: ReactNode;
}) {
  return (
    <div
      className="surface-card flex flex-col items-center justify-center text-center"
      style={{ padding: "var(--space-xl) var(--space-md)" }}
    >
      <div
        className="flex items-center justify-center mb-3 rounded-full"
        style={{
          width: "48px",
          height: "48px",
          background: "var(--accent-subtle)",
          border: "1px solid var(--border)",
          color: "var(--accent)",
        }}
      >
        {icon}
      </div>
      {title && <p className="text-sm font-medium text-text-primary mb-1">{title}</p>}
      <p className="text-sm text-text-secondary max-w-sm" style={{ lineHeight: 1.5 }}>
        {hint}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
```

## Loading

- File: `crates/hf-gui/src/components/ui/Loading.tsx`
- Description: Shared loading indicators and loading state.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import type { CSSProperties } from "react";
import { useI18n } from "../../i18nContext";

// Shared loading primitives so spinners and placeholders look the same
// everywhere (the complement to EmptyState).

/** A small spinning ring that inherits the current text color. */
export function Spinner({ size = 16, className }: { size?: number; className?: string }) {
  return (
    <span
      className={`inline-block animate-spin rounded-full border-2 border-current border-t-transparent ${className ?? ""}`}
      style={{ width: size, height: size }}
      aria-hidden="true"
    />
  );
}

/** A centered spinner + label, for a section/panel that is loading. */
export function LoadingState({ label }: { label?: string }) {
  const { t } = useI18n();
  return (
    <div
      className="surface-card flex flex-col items-center justify-center text-center text-text-muted"
      style={{ padding: "var(--space-xl) var(--space-md)", gap: "var(--space-sm)" }}
    >
      <Spinner size={20} />
      <p className="text-sm">{label ?? t("common.loading")}</p>
    </div>
  );
}

/** A shimmering placeholder block, sized via className/style, for skeleton rows. */
export function Skeleton({ className, style }: { className?: string; style?: CSSProperties }) {
  return (
    <div
      className={`animate-pulse rounded-md ${className ?? ""}`}
      style={{ background: "var(--surface-active)", ...style }}
      aria-hidden="true"
    />
  );
}
```

## ErrorState

- File: `crates/hf-gui/src/components/ui/ErrorState.tsx`
- Description: Recoverable error presentation.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import type { ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { useI18n } from "../../i18nContext";

// The shared "this failed to load" placeholder -- the error-colored sibling of
// EmptyState/LoadingState, so failures look the same everywhere (an error
// circle, a title, the message, and an optional retry action) instead of each
// view hand-rolling its own error card.
export function ErrorState({
  title,
  message,
  action,
}: {
  title?: string;
  message: string;
  action?: ReactNode;
}) {
  const { t } = useI18n();
  const heading = title ?? t("ui.errorTitle");
  return (
    <div
      className="surface-card flex flex-col items-center justify-center text-center"
      style={{ padding: "var(--space-xl) var(--space-md)" }}
    >
      <div
        className="flex items-center justify-center mb-3 rounded-full"
        style={{
          width: "48px",
          height: "48px",
          background: "var(--error-subtle)",
          border: "1px solid var(--border)",
          color: "var(--error)",
        }}
      >
        <AlertTriangle size={20} />
      </div>
      <p className="text-sm font-medium text-text-primary mb-1">{heading}</p>
      <p
        className="text-xs text-text-muted max-w-sm font-mono"
        style={{ lineHeight: 1.5, wordBreak: "break-word" }}
      >
        {message}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
```

## Tooltip

- File: `crates/hf-gui/src/components/ui/Tooltip.tsx`
- Description: Radix tooltip wrappers.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

interface TooltipContextValue {
  show: (text: string, e: React.MouseEvent) => void;
  hide: () => void;
}

const TooltipContext = createContext<TooltipContextValue | null>(null);

export function TooltipProvider({ children }: { children: ReactNode }) {
  const [tooltip, setTooltip] = useState<{ text: string; x: number; y: number } | null>(null);
  const show = useCallback((text: string, e: React.MouseEvent) => {
    setTooltip({ text, x: e.clientX, y: e.clientY + 20 });
  }, []);
  const hide = useCallback(() => setTooltip(null), []);
  return (
    <TooltipContext.Provider value={{ show, hide }}>
      {children}
      {tooltip && (
        <div
          className="fixed z-9999 px-2 py-1 text-xs rounded-md pointer-events-none"
          style={{
            left: tooltip.x,
            top: tooltip.y,
            background: "var(--surface-tertiary)",
            border: "1px solid var(--border)",
            color: "var(--text-primary)",
            boxShadow: "var(--shadow-sm)",
            whiteSpace: "nowrap",
            animation: "fadeIn 0.1s ease",
          }}
        >
          {tooltip.text}
        </div>
      )}
    </TooltipContext.Provider>
  );
}

export function Tooltip({ text, children }: { text: string; children: ReactNode }) {
  const ctx = useContext(TooltipContext);
  if (!ctx) return <>{children}</>;
  return (
    <span onMouseEnter={(e) => ctx.show(text, e)} onMouseLeave={ctx.hide}>
      {children}
    </span>
  );
}
```

## Toast

- File: `crates/hf-gui/src/components/ui/Toast.tsx`
- Description: Application toast viewport and provider.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
import { useCallback, useState, type ReactNode } from "react";
import { X } from "lucide-react";
import { IconButton } from "./IconButton";
import { useI18n } from "../../i18nContext";
import { ToastContext, type ToastNotification } from "./toastContext";

// Errors linger so they can actually be read; routine toasts auto-clear fast.
const DISMISS_MS = { error: 8000, default: 3500, success: 3500 } as const;

export function ToastProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  const [toasts, setToasts] = useState<ToastNotification[]>([]);
  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((x) => x.id !== id));
  }, []);
  const toast = useCallback(
    (t: Omit<ToastNotification, "id">) => {
      const id = Date.now() + Math.random();
      setToasts((prev) => [...prev, { ...t, id }]);
      const ms = DISMISS_MS[t.variant ?? "default"];
      setTimeout(() => dismiss(id), ms);
    },
    [dismiss],
  );
  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      {/* Announced to assistive tech; assertive so errors interrupt. */}
      <div
        className="fixed bottom-4 right-4 z-9999 flex flex-col gap-2"
        role="region"
        aria-label={t("ui.notifications")}
        aria-live="assertive"
      >
        {toasts.map((n) => (
          <div
            key={n.id}
            role={n.variant === "error" ? "alert" : "status"}
            className="surface-card flex items-start gap-2"
            style={{
              padding: "var(--space-sm) var(--space-md)",
              minWidth: 240,
              maxWidth: 360,
              animation: "slideInUp 0.2s ease",
              boxShadow: "var(--shadow-md)",
              borderColor: n.variant === "success" ? "var(--success)" : n.variant === "error" ? "var(--error)" : "var(--border)",
            }}
          >
            <div className="flex flex-col gap-1 min-w-0 flex-1">
              <span className="text-sm font-medium text-text-primary">{n.title}</span>
              {n.description && (
                <span className="text-xs text-text-secondary" style={{ overflowWrap: "anywhere" }}>
                  {n.description}
                </span>
              )}
            </div>
            <IconButton
              size={22}
              className="shrink-0"
              onClick={() => dismiss(n.id)}
              aria-label={t("ui.dismissNotification")}
              title={t("ui.dismiss")}
            >
              <X size={13} />
            </IconButton>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
```

## SettingsGroup

- File: `crates/hf-gui/src/components/ui/SettingsGroup.tsx`
- Description: Grouped settings section and row primitives.
- Key props: See the exported TypeScript interface/type in the complete source below.

```tsx
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
```


