import { useCallback, useRef, useState, type ReactNode } from "react";
import { Button } from "../components/ui/Button";
import { useI18n } from "../i18nContext";
import {
  confirmationFocusTarget,
  confirmationKeyboardAction,
} from "../lib/confirmationBehavior";
import { ConfirmContext, type ConfirmFn, type ConfirmOptions } from "./confirm";

// A themed replacement for window.confirm: matches the app's look and dark
// mode, keeps destructive actions off the default focus path, and returns a
// promise resolving to the user's choice. Escape cancels; Enter activates the
// focused button through native button semantics.
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n();
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
    <ConfirmContext.Provider value={confirm}>
      {children}
      {opts && (
        <div
          className="fixed inset-0 z-9999 flex items-center justify-center"
          style={{ background: "rgba(0,0,0,0.5)", backdropFilter: "blur(2px)" }}
          onClick={() => settle(false)}
          onKeyDown={(e) => {
            if (confirmationKeyboardAction(e.key) === "cancel") settle(false);
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
              <Button
                autoFocus={confirmationFocusTarget(Boolean(opts.danger)) === "cancel"}
                variant="outline"
                size="sm"
                onClick={() => settle(false)}
              >
                {opts.cancelLabel ?? t("common.cancel")}
              </Button>
              <Button
                autoFocus={confirmationFocusTarget(Boolean(opts.danger)) === "confirm"}
                variant={opts.danger ? "danger" : "primary"}
                size="sm"
                onClick={() => settle(true)}
              >
                {opts.confirmLabel ?? t("common.confirm")}
              </Button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}
