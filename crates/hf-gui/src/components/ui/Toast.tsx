import { createContext, useContext, useState, useCallback, type ReactNode } from "react";
import { X } from "lucide-react";
import { IconButton } from "./IconButton";

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
        aria-label="Notifications"
        aria-live="assertive"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.variant === "error" ? "alert" : "status"}
            className="surface-card flex items-start gap-2"
            style={{
              padding: "var(--space-sm) var(--space-md)",
              minWidth: 240,
              maxWidth: 360,
              animation: "slideInUp 0.2s ease",
              boxShadow: "var(--shadow-md)",
              borderColor: t.variant === "success" ? "var(--success)" : t.variant === "error" ? "var(--error)" : "var(--border)",
            }}
          >
            <div className="flex flex-col gap-1 min-w-0 flex-1">
              <span className="text-sm font-medium text-text-primary">{t.title}</span>
              {t.description && (
                <span className="text-xs text-text-secondary" style={{ overflowWrap: "anywhere" }}>
                  {t.description}
                </span>
              )}
            </div>
            <IconButton
              size={22}
              className="shrink-0"
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss notification"
              title="Dismiss"
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
