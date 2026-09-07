export function formatInvokeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (error !== null && typeof error === "object") {
    const value = error as Record<string, unknown>;
    const code = typeof value.code === "string" ? value.code : null;
    const message = typeof value.message === "string"
      ? value.message
      : typeof value.error === "string"
        ? value.error
        : null;
    if (code && message) return `${code}: ${message}`;
    if (message) return message;
    if (code) return code;
  }
  return String(error);
}

export function formatRunHistoryError(error: unknown, t: (key: string, params?: Record<string, string | number>) => string): string {
  if (error !== null && typeof error === "object") {
    const value = error as Record<string, unknown>;
    if (value.code === "run_retained_by_experiment" && typeof value.run_id === "string" && typeof value.experiment_id === "string" && (value.role === "baseline" || value.role === "result")) {
      return t("experiments.error.run_retained_by_experiment", { run: value.run_id, experiment: value.experiment_id, role: t(`experiments.role.${value.role}`) });
    }
  }
  return String(error);
}
