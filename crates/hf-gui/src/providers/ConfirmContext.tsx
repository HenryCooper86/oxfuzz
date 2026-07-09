import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

interface ConfirmOptions {
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Style the confirm button as destructive (red). */
  danger?: boolean;
}

type ConfirmFn = (opts: ConfirmOptions) => Promise<boolean>;

const ConfirmCtx = createContext<ConfirmFn | null>(null);

// A themed replacement for window.confirm: matches the app's look and dark
// mode, is keyboard-accessible (Enter confirms, Escape cancels), and returns a
// promise resolving to the user's choice.
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [opts, setOpts] = useState<ConfirmOptions | null>(null);
  const resolver = useRef<((v: boolean) => void) | null>(null);

  const confirm = useCallback<ConfirmFn>((options) => {
    setOpts(options);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  const settle = useCallback((value: boolean) => {
    resolver.current?.(value);
    resolver.current = null;
    setOpts(null);
  }, []);

  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      {opts && (
        <div
          className="fixed inset-0 z-9999 flex items-center justify-center"
          style={{ background: "rgba(0,0,0,0.5)", backdropFilter: "blur(2px)" }}
          onClick={() => settle(false)}
          onKeyDown={(e) => {
            if (e.key === "Escape") settle(false);
            if (e.key === "Enter") settle(true);
          }}
        >
          <div
            role="alertdialog"
            aria-modal="true"
            aria-label={opts.title}
            className="surface-card flex flex-col gap-3"
            style={{ width: "min(440px, 92vw)", padding: "var(--space-lg)", boxShadow: "var(--shadow-lg)", animation: "dialogContentIn 0.15s ease" }}
            onClick={(e) => e.stopPropagation()}
          >
            <span className="text-sm font-semibold">{opts.title}</span>
            {opts.message && (
              <p className="text-xs text-text-secondary" style={{ whiteSpace: "pre-line", overflowWrap: "anywhere" }}>
                {opts.message}
              </p>
            )}
            <div className="flex items-center justify-end gap-2 mt-1">
              <button
                onClick={() => settle(false)}
                className="px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary"
              >
                {opts.cancelLabel ?? "Cancel"}
              </button>
              <button
                autoFocus
                onClick={() => settle(true)}
                className="px-3 py-1.5 text-xs font-medium rounded-md"
                style={
                  opts.danger
                    ? { background: "var(--error)", color: "#fff", border: "none" }
                    : { background: "var(--accent)", color: "var(--accent-contrast)", border: "none" }
                }
              >
                {opts.confirmLabel ?? "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmCtx.Provider>
  );
}

/** Access the themed confirm. Falls back to window.confirm outside a provider. */
export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmCtx);
  return useMemo(
    () => ctx ?? ((opts: ConfirmOptions) => Promise.resolve(window.confirm(opts.message ?? opts.title))),
    [ctx],
  );
}
