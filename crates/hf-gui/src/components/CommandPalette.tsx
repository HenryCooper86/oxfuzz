import { useEffect, useMemo, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Search } from "lucide-react";
import type { ViewType } from "../types";
import { useI18n } from "../i18nContext";

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
  "changes",
  "audit",
  "agents",
  "skills",
  "knowledge",
  "automation",
  "automotive",
  "defectdojo",
  "help",
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
  const activeItem = useRef<HTMLButtonElement | null>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (!open) {
          previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
          setQuery("");
          setActive(0);
        }
        setOpen((o) => !o);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    return VIEWS.map((v) => ({ view: v, label: t(`nav.${v}`) })).filter(
      (i) => !q || i.label.toLowerCase().includes(q) || i.view.includes(q),
    );
  }, [query, t]);

  useEffect(() => {
    if (open) activeItem.current?.scrollIntoView({ block: "nearest" });
  }, [open, active, items]);

  const choose = (view: ViewType) => {
    onNavigate(view);
    setOpen(false);
  };

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-9999"
          style={{ background: "rgba(0,0,0,0.4)", backdropFilter: "blur(2px)" }}
        />
        <Dialog.Content
          aria-describedby={undefined}
          className="surface-card fixed z-9999 flex flex-col overflow-hidden"
          style={{ width: "min(560px, 92vw)", left: 0, right: 0, margin: "0 auto", top: "12vh", padding: 0, boxShadow: "var(--shadow-lg)", animation: "dialogContentIn 0.14s ease" }}
          onOpenAutoFocus={(event) => { event.preventDefault(); inputRef.current?.focus(); }}
          onCloseAutoFocus={(event) => { event.preventDefault(); previousFocus.current?.focus(); }}
          onKeyDown={(e) => {
            if (e.target !== inputRef.current) return;
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((a) => Math.max(0, Math.min(items.length - 1, a + 1)));
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
          <Dialog.Title className="sr-only">{t("palette.ariaLabel")}</Dialog.Title>
          <Search size={15} className="text-text-muted" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            placeholder={t("palette.placeholder")}
            className="flex-1 bg-transparent outline-none text-sm text-text-primary"
            style={{ border: "none" }}
          />
          <kbd className="text-xs text-text-muted">{t("palette.esc")}</kbd>
        </div>
        <div className="overflow-auto" style={{ maxHeight: "50vh" }}>
          {items.length === 0 ? (
            <div className="text-xs text-text-muted" style={{ padding: "12px 14px" }}>{t("palette.noMatches")}</div>
          ) : (
            items.map((item, i) => (
              <button
                key={item.view}
                ref={i === active ? activeItem : undefined}
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
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
