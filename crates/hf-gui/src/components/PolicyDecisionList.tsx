import { ShieldCheck, ShieldX } from "lucide-react";

// One persisted guardrail authorization decision, as recorded by the service in
// migration 0018. Field names match GuardrailDecisionRecord exactly so the
// transport needs no mapping layer.
export interface PolicyDecision {
  id: string;
  decided_at: string;
  action: string;
  risk_tier: string;
  decision: string;
  origin: string;
  project: string | null;
  detail: string | null;
}

interface PolicyDecisionListProps {
  decisions: PolicyDecision[];
  emptyLabel: string;
}

function fmtTime(ts: string): string {
  const d = new Date(ts);
  return isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// A denial is the outcome an operator scans for, so it carries the warning
// treatment; everything else reads as routine.
function isDenial(decision: string): boolean {
  return decision.startsWith("denied");
}

export function PolicyDecisionList({ decisions, emptyLabel }: PolicyDecisionListProps) {
  if (decisions.length === 0) {
    return <div className="text-xs text-text-muted">{emptyLabel}</div>;
  }

  return (
    <div className="flex flex-col gap-1.5">
      {decisions.map((d) => {
        const denied = isDenial(d.decision);
        const color = denied ? "var(--warning, var(--accent))" : "var(--accent)";
        const projectName = d.project
          ? d.project.split("/").filter(Boolean).pop() || d.project
          : null;
        return (
          <div
            key={d.id}
            className="surface-card flex items-start gap-3"
            style={{ padding: "var(--space-sm) var(--space-md)", borderLeft: `3px solid ${color}` }}
          >
            {denied ? (
              <ShieldX size={16} style={{ color, flexShrink: 0, marginTop: 2 }} />
            ) : (
              <ShieldCheck size={16} style={{ color, flexShrink: 0, marginTop: 2 }} />
            )}
            <div className="flex flex-col min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-medium truncate" style={{ fontFamily: "var(--font-mono)" }}>
                  {d.action}
                </span>
                <span
                  className="text-xs rounded-full"
                  style={{ padding: "0 8px", border: `1px solid ${color}`, color }}
                >
                  {d.decision}
                </span>
                <span className="text-xs text-text-muted">{d.risk_tier}</span>
                {projectName && (
                  <span className="text-xs text-text-muted truncate">{projectName}</span>
                )}
              </div>
              <span className="text-xs text-text-secondary" style={{ lineHeight: 1.5 }}>
                <code>{d.origin}</code>
                {d.detail ? ` -- ${d.detail}` : ""}
              </span>
            </div>
            <span className="text-xs text-text-muted whitespace-nowrap" style={{ marginTop: 2 }}>
              {fmtTime(d.decided_at)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
