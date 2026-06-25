interface SwitchProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
}

export function Switch({ checked, onChange, label }: SwitchProps) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className="flex items-center gap-2 cursor-pointer outline-none focus-visible:[&>span]:outline-2 focus-visible:[&>span]:outline focus-visible:[&>span]:outline-[var(--accent)] focus-visible:[&>span]:outline-offset-2"
      style={{ background: "transparent", border: "none", padding: 0 }}
    >
      <span
        className="rounded-full border border-solid transition-all duration-200 relative inline-block"
        style={{
          width: "36px",
          height: "20px",
          borderColor: "var(--border)",
          background: checked ? "var(--accent)" : "var(--surface-tertiary)",
        }}
      >
        <span
          className="rounded-full bg-white transition-all duration-200 absolute"
          style={{
            width: "14px",
            height: "14px",
            top: "2px",
            left: checked ? "18px" : "2px",
          }}
        />
      </span>
      {label && <span className="text-xs text-text-secondary">{label}</span>}
    </button>
  );
}
