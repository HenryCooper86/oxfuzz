interface SwitchProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
}

export function Switch({ checked, onChange, label }: SwitchProps) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className="flex items-center gap-2 cursor-pointer"
      style={{ background: "transparent", border: "none" }}
    >
      <div
        className="rounded-full transition-colors duration-150"
        style={{
          width: "32px",
          height: "18px",
          background: checked ? "var(--accent)" : "var(--surface-active)",
          position: "relative",
        }}
      >
        <div
          className="rounded-full bg-white transition-all duration-150"
          style={{
            width: "14px",
            height: "14px",
            position: "absolute",
            top: "2px",
            left: checked ? "16px" : "2px",
          }}
        />
      </div>
      {label && <span className="text-xs text-text-secondary">{label}</span>}
    </button>
  );
}