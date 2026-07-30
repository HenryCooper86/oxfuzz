interface RecoveryAction {
  occurrenceId: string;
  confirm: () => Promise<boolean>;
  acknowledge: (occurrenceId: string) => Promise<unknown>;
  refresh: () => Promise<unknown>;
}

export async function acknowledgeRecoveryWithRefresh({
  occurrenceId,
  confirm,
  acknowledge,
  refresh,
}: RecoveryAction): Promise<boolean> {
  if (!(await confirm())) return false;
  await acknowledge(occurrenceId);
  await refresh();
  return true;
}
