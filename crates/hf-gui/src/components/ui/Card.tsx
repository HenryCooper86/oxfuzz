import type { ReactNode } from "react";

interface CardProps {
  children: ReactNode;
  className?: string;
  hoverable?: boolean;
  onClick?: () => void;
  style?: React.CSSProperties;
}

export function Card({ children, className, hoverable, onClick, style }: CardProps) {
  return (
    <div
      onClick={onClick}
      className={`bg-surface-primary border border-solid border-border rounded-lg shadow-md ${className ?? ""}`}
      style={{
        transition: hoverable ? "border-color 0.15s ease" : undefined,
        cursor: onClick ? "pointer" : undefined,
        ...style,
      }}
      onMouseEnter={hoverable ? (e) => (e.currentTarget.style.borderColor = "var(--border-focus)") : undefined}
      onMouseLeave={hoverable ? (e) => (e.currentTarget.style.borderColor = "var(--border)") : undefined}
    >
      {children}
    </div>
  );
}