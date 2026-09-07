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
