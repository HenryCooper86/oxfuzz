interface SelectProps {
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  className?: string;
  mono?: boolean;
}

export function Select({ value, options, onChange, className, mono }: SelectProps) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={`px-3 py-1.5 text-12px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary transition-colors duration-150 outline-none focus:border-[var(--border-focus)] cursor-pointer ${mono ? "font-[var(--font-mono)]" : "font-sans"} ${className ?? ""}`}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}