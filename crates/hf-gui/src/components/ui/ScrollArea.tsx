import type { ReactNode } from "react";

export function ScrollArea({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={`overflow-y-auto ${className ?? ""}`}>{children}</div>;
}