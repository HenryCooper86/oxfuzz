import type { ReactNode } from "react";

interface DialogProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  size?: "sm" | "md" | "lg" | "xl";
}

const sizeWidths = { sm: 360, md: 480, lg: 640, xl: 960 };

export function Dialog({ open, onClose, children, size = "md" }: DialogProps) {
  if (!open) return null;
  return (
    <DialogOverlay onClose={onClose}>
      <div
        className="flex flex-col gap-4 bg-[var(--surface-primary)] border border-solid border-[var(--border)] rounded-[var(--radius-lg)] p-6 outline-none"
        style={{
          maxWidth: sizeWidths[size],
          width: "100%",
          maxHeight: "calc(100vh - 64px)",
          boxShadow: "0 16px 48px rgba(0,0,0,0.3), 0 0 0 1px rgba(255,255,255,0.04)",
          animation: "dialogContentIn 0.2s cubic-bezier(0.34,1.56,0.64,1)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
    </DialogOverlay>
  );
}

function DialogOverlay({ children, onClose }: { children: ReactNode; onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-9999 flex items-center justify-center"
      style={{ background: "rgba(0,0,0,0.5)", backdropFilter: "blur(4px)", animation: "fadeIn 0.15s ease" }}
      onClick={onClose}
    >
      {children}
    </div>
  );
}

export function DialogTitle({ children }: { children: ReactNode }) {
  return <h2 className="text-15px font-600 text-text-primary">{children}</h2>;
}

export function DialogDescription({ children }: { children: ReactNode }) {
  return <p className="text-13px text-text-secondary leading-relaxed">{children}</p>;
}

export function DialogContent({ children }: { children: ReactNode }) {
  return <div className="flex-1 overflow-y-auto">{children}</div>;
}

export { DialogOverlay };