// The one CASR-exploitability badge for the whole app, keyed by the serialized
// CrashSeverity. Previously duplicated in TriageView and the Knowledge view with
// slightly different labels/colors; consolidated here so severity always reads
// the same.
const SEVERITY_STYLE: Record<string, { label: string; bg: string; fg: string }> = {
  Exploitable: { label: "EXPLOITABLE", bg: "var(--error-subtle)", fg: "var(--error)" },
  ProbablyExploitable: { label: "PROBABLY EXPL.", bg: "var(--warning-subtle)", fg: "var(--warning)" },
  NotExploitable: { label: "NOT EXPL.", bg: "var(--surface-active)", fg: "var(--text-secondary)" },
  Undefined: { label: "UNCLASSIFIED", bg: "var(--surface-active)", fg: "var(--text-muted)" },
};

export function SeverityBadge({ severity, title }: { severity: string; title?: string }) {
  const s = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.Undefined;
  return (
    <span
      className="px-1.5 py-0.5 rounded-sm font-semibold shrink-0"
      style={{ background: s.bg, color: s.fg, fontSize: "10.5px", letterSpacing: "0.04em" }}
      title={title ?? severity}
    >
      {s.label}
    </span>
  );
}
