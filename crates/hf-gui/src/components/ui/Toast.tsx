import { createContext, useContext, useState, useCallback, type ReactNode } from "react";
import { X } from "lucide-react";
import { IconButton } from "./IconButton";
import { useI18n } from "../../i18n";

interface Toast {
  id: number;
  title: string;
  description?: string;
  variant?: "default" | "success" | "error";
}

interface ToastCtx {
  toast: (t: Omit<Toast, "id">) => void;
}

const Ctx = createContext<ToastCtx | null>(null);

// Errors linger so they can actually be read; routine toasts auto-clear fast.
const DISMISS_MS = { error: 8000, default: 3500, success: 3500 } as const;

export function ToastProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((x) => x.id !== id));
  }, []);
  const toast = useCallback(
    (t: Omit<Toast, "id">) => {
      const id = Date.now() + Math.random();
      setToasts((prev) => [...prev, { ...t, id }]);
      const ms = DISMISS_MS[t.variant ?? "default"];
      setTimeout(() => dismiss(id), ms);
    },
    [dismiss],
  );
  return (
    <Ctx.Provider value={{ toast }}>
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
    </Ctx.Provider>
  );
}

export function useToast() {
  const ctx = useContext(Ctx);
  return ctx ?? { toast: () => {} };
}
