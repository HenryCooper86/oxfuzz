import { forwardRef } from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  mono?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ mono, className, ...props }, ref) => (
    <input
      ref={ref}
      className={`w-full px-3 py-1.5 text-12px border border-solid border-[var(--border-strong)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary transition-[border-color,box-shadow] duration-150 outline-none hover:border-[var(--border-focus)] focus:border-[var(--accent)] focus:shadow-[0_0_0_3px_var(--accent-glow)] placeholder:text-text-muted ${mono ? "font-[var(--font-mono)]" : "font-sans"} ${className ?? ""}`}
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
      className={`w-full px-3 py-2 text-12px border border-solid border-[var(--border-strong)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary transition-[border-color,box-shadow] duration-150 outline-none hover:border-[var(--border-focus)] focus:border-[var(--accent)] focus:shadow-[0_0_0_3px_var(--accent-glow)] placeholder:text-text-muted resize-y leading-[1.65] tab-size-2 ${mono ? "font-[var(--font-mono)]" : "font-sans"} ${className ?? ""}`}
      {...props}
    />
  ),
);
Textarea.displayName = "Textarea";