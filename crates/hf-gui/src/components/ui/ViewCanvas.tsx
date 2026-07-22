import type { ReactNode } from "react";

interface ViewCanvasProps {
  children: ReactNode;
}

export function ViewCanvas({ children }: ViewCanvasProps) {
  return (
    <div className="view-scroll">
      <div className="view-canvas">{children}</div>
    </div>
  );
}
