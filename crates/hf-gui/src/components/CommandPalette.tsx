import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import type { ViewType } from "../types";
import { useI18n } from "../i18n";

// Views reachable from the palette, in a sensible order.
const VIEWS: ViewType[] = [
  "dashboard",
  "chat",
  "workflow",
  "discover",
  "harness",
  "run",
  "triage",
  "corpus",
  "projects",
  "artifacts",
  "reports",
  "runs",
  "agents",
  "skills",
  "knowledge",
  "automation",
  "defectdojo",
  "settings",
];

// A ⌘K / Ctrl-K command palette for fast keyboard-driven navigation, matching
// what professional tools provide. Arrow keys move, Enter navigates, Escape
// closes. Self-contained: installs its own global hotkey.
export function CommandPalette({ onNavigate }: { onNavigate: (view: ViewType) => void }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!open) return;
    queueMicrotask(() => {
      setQuery("");
      setActive(0);
    });
    // Focus after the element mounts.
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    return VIEWS.map((v) => ({ view: v, label: t(`nav.${v}`) })).filter(
      (i) => !q || i.label.toLowerCase().includes(q) || i.view.includes(q),
    );
  }, [query, t]);

  if (!open) return null;

  const choose = (view: ViewType) => {
    onNavigate(view);
    setOpen(false);
  };

  return (
    <div
      className="fixed inset-0 z-9999 flex items-start justify-center"
      style={{ background: "rgba(0,0,0,0.4)", backdropFilter: "blur(2px)", paddingTop: "12vh" }}
      onClick={() => setOpen(false)}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="surface-card flex flex-col overflow-hidden"
        style={{ width: "min(560px, 92vw)", padding: 0, boxShadow: "var(--shadow-lg)", animation: "dialogContentIn 0.14s ease" }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") setOpen(false);
          else if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(items.length - 1, a + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(0, a - 1));
          } else if (e.key === "Enter" && items[active]) {
            e.preventDefault();
            choose(items[active].view);
          }
        }}
      >
        <div className="flex items-center gap-2 border-b border-border" style={{ padding: "10px 14px" }}>
          <Search size={15} className="text-text-muted" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            placeholder="Jump to..."
            className="flex-1 bg-transparent outline-none text-sm text-text-primary"
            style={{ border: "none" }}
          />
          <kbd className="text-xs text-text-muted">esc</kbd>
        </div>
        <div className="overflow-auto" style={{ maxHeight: "50vh" }}>
          {items.length === 0 ? (
            <div className="text-xs text-text-muted" style={{ padding: "12px 14px" }}>No matches.</div>
          ) : (
            items.map((item, i) => (
              <button
                key={item.view}
                onMouseEnter={() => setActive(i)}
                onClick={() => choose(item.view)}
                className="flex items-center w-full text-left text-sm transition-colors"
                style={{
                  padding: "9px 14px",
                  background: i === active ? "var(--surface-active)" : "transparent",
                  color: i === active ? "var(--text-primary)" : "var(--text-secondary)",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                {item.label}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
