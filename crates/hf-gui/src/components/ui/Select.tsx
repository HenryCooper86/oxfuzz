import * as RadixSelect from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";

interface SelectProps {
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  className?: string;
  mono?: boolean;
  disabled?: boolean;
  /**
   * Trigger text when nothing is selected. Radix reserves the empty string for
   * "no selection" -- an `Item` may not use it -- so an empty `options` list
   * plus a placeholder is how a select with nothing to offer says so, rather
   * than rendering a blank box.
   */
  placeholder?: string;
}

export function Select({
  value,
  options,
  onChange,
  className,
  mono,
  disabled,
  placeholder,
}: SelectProps) {
  return (
    <RadixSelect.Root value={value} onValueChange={onChange} disabled={disabled}>
      <RadixSelect.Trigger
        className={`inline-flex items-center justify-between gap-2 px-2 py-1.5 text-12px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary transition-colors duration-150 outline-none focus:border-[var(--border-focus)] cursor-pointer data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50 ${mono ? "font-[var(--font-mono)]" : "font-sans"} ${className ?? ""}`}
      >
        <RadixSelect.Value placeholder={placeholder} />
        <RadixSelect.Icon style={{ opacity: 0.7 }}>
          <ChevronDown size={14} />
        </RadixSelect.Icon>
      </RadixSelect.Trigger>
      <RadixSelect.Portal>
        <RadixSelect.Content
          position="popper"
          sideOffset={4}
          className={`overflow-hidden border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary z-50 ${mono ? "font-[var(--font-mono)]" : "font-sans"}`}
          style={{ boxShadow: "0 8px 24px rgba(0,0,0,0.25)", maxHeight: "300px" }}
        >
          <RadixSelect.Viewport className="p-1" style={{ maxHeight: "300px" }}>
            {options.map((o) => (
              <RadixSelect.Item
                key={o.value}
                value={o.value}
                className="relative flex items-center pl-7 pr-2 py-1.5 text-12px rounded-[var(--radius-sm)] cursor-pointer outline-none select-none data-[highlighted]:bg-[var(--surface-hover)]"
              >
                <RadixSelect.ItemIndicator className="absolute left-2 inline-flex items-center text-[var(--accent)]">
                  <Check size={13} />
                </RadixSelect.ItemIndicator>
                <RadixSelect.ItemText>{o.label}</RadixSelect.ItemText>
              </RadixSelect.Item>
            ))}
          </RadixSelect.Viewport>
        </RadixSelect.Content>
      </RadixSelect.Portal>
    </RadixSelect.Root>
  );
}
