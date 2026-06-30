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