import { useEffect, useRef, type KeyboardEvent } from "react";

// Keyboard support for a custom listbox-style dropdown. Wire the returned refs
// and handlers onto the trigger button and the menu container; options must
// carry role="option". Provides arrow/Home/End navigation between options and
// Escape to close and return focus to the trigger. On open, focus moves to the
// selected option (or the first), so the menu is fully keyboard-drivable.
export function useListboxNav(open: boolean, close: () => void) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open || !menuRef.current) return;
    const items = menuRef.current.querySelectorAll<HTMLButtonElement>('[role="option"]');
    const selected = menuRef.current.querySelector<HTMLButtonElement>(
      '[role="option"][aria-selected="true"]',
    );
    (selected ?? items[0])?.focus();
  }, [open]);

  function onMenuKey(e: KeyboardEvent<HTMLDivElement>) {
    const items = Array.from(
      menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? [],
    );
    const idx = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") {
      e.preventDefault();
      close();
      triggerRef.current?.focus();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      items[Math.min(items.length - 1, idx + 1)]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      items[Math.max(0, idx - 1)]?.focus();
    } else if (e.key === "Home") {
      e.preventDefault();
      items[0]?.focus();
    } else if (e.key === "End") {
      e.preventDefault();
      items[items.length - 1]?.focus();
    }
  }

  function onTriggerKey(e: KeyboardEvent<HTMLButtonElement>, openMenu: () => void) {
    if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openMenu();
    }
  }

  return { triggerRef, menuRef, onMenuKey, onTriggerKey };
}
