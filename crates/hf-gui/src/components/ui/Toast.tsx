import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

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

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toast = useCallback((t: Omit<Toast, "id">) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { ...t, id }]);
    setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), 3000);
  }, []);
  return (
    <Ctx.Provider value={{ toast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-9999 flex flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="surface-card flex flex-col gap-1"
            style={{
              padding: "var(--space-sm) var(--space-md)",
              minWidth: 240,
              maxWidth: 360,
              animation: "slideInUp 0.2s ease",
              borderColor: t.variant === "success" ? "var(--success)" : t.variant === "error" ? "var(--error)" : "var(--border)",
            }}
          >
            <span className="text-sm font-medium text-text-primary">{t.title}</span>
            {t.description && <span className="text-xs text-text-secondary">{t.description}</span>}
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