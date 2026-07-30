import { Button } from "./ui";

export interface OneTimeRecoveryView {
  occurrence_id: string;
  schedule_id: string;
  schedule_name: string | null;
  execution_id: string;
  triggered_at: string;
  state: string;
  recovery_detail: string | null;
  schedule_exists: boolean;
}

interface ScheduleRecoveryPanelProps {
  recoveries: OneTimeRecoveryView[];
  title: string;
  actionLabel: string;
  unknownScheduleLabel: string;
  onAcknowledge: (occurrenceId: string) => void;
}

export function ScheduleRecoveryPanel({
  recoveries,
  title,
  actionLabel,
  unknownScheduleLabel,
  onAcknowledge,
}: ScheduleRecoveryPanelProps) {
  if (recoveries.length === 0) return null;
  return (
    <section
      role="alert"
      className="surface-card flex flex-col gap-2"
      style={{ borderLeft: "3px solid var(--error)", padding: "var(--space-md)" }}
    >
      <strong className="text-sm">{title}</strong>
      {recoveries.map((recovery) => (
        <div key={recovery.occurrence_id} className="flex items-center gap-3">
          <div className="flex flex-col min-w-0 flex-1 text-xs">
            <span className="font-medium">
              {recovery.schedule_name ?? unknownScheduleLabel}
            </span>
            <span className="font-mono text-text-muted">
              {recovery.state} · {new Date(recovery.triggered_at).toLocaleString()}
            </span>
            {recovery.recovery_detail && (
              <span className="text-text-secondary">{recovery.recovery_detail}</span>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onAcknowledge(recovery.occurrence_id)}
          >
            {actionLabel}
          </Button>
        </div>
      ))}
    </section>
  );
}
