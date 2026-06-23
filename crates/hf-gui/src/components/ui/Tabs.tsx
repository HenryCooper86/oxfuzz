import { useState, type ReactNode } from "react";

interface TabsProps {
  items: { value: string; label: string; content: ReactNode }[];
  defaultValue?: string;
}

export function Tabs({ items, defaultValue }: TabsProps) {
  const [active, setActive] = useState(defaultValue ?? items[0]?.value ?? "");
  return (
    <div className="flex flex-col h-full">
      <div className="flex border-b border-border" style={{ gap: "2px", padding: "0 8px" }}>
        {items.map((item) => (
          <button
            key={item.value}
            onClick={() => setActive(item.value)}
            className="text-xs px-3 py-2 transition-colors duration-150 outline-none border-b-2"
            style={{
              color: active === item.value ? "var(--accent)" : "var(--text-muted)",
              borderColor: active === item.value ? "var(--accent)" : "transparent",
              fontWeight: active === item.value ? 600 : 400,
              cursor: "pointer",
              background: "transparent",
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto" style={{ paddingTop: "var(--space-md)" }}>
        {items.find((i) => i.value === active)?.content}
      </div>
    </div>
  );
}

export function TabsList({ children }: { children: ReactNode }) {
  return <div className="flex gap-1">{children}</div>;
}

export function TabsTrigger({ value, children, active, onClick }: { value: string; children: ReactNode; active?: boolean; onClick?: (v: string) => void }) {
  return (
    <button onClick={() => onClick?.(value)} className="text-xs px-3 py-1.5 rounded-md transition-colors duration-150" style={{ background: active ? "var(--surface-active)" : "transparent", color: active ? "var(--accent)" : "var(--text-muted)", cursor: "pointer", border: "none", fontWeight: active ? 600 : 400 }}>
      {children}
    </button>
  );
}

export function TabsContent({ children }: { children: ReactNode }) {
  return <div>{children}</div>;
}