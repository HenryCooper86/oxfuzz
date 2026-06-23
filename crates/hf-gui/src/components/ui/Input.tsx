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