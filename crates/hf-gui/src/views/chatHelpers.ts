/** Instruction prepended in Plan mode (no backend -- pure prompt steering). */
const PLAN_PREFIX =
  "[Plan mode] Before taking any action or calling tools, lay out a concise, " +
  "numbered step-by-step plan for how you will approach this. Then proceed.";

/** Composer mode. `plan` prepends a planning instruction to the message. */
export type ChatMode = "auto" | "plan";

/** Build the message actually sent to the agent for a given mode. */
export function applyMode(text: string, mode: ChatMode): string {
  return mode === "plan" ? `${PLAN_PREFIX}\n\n${text}` : text;
}

export type ChatRole = "user" | "assistant" | "system";

export function normalizeChatRole(role: string): ChatRole {
  switch (role.toLowerCase()) {
    case "assistant":
      return "assistant";
    case "system":
    case "tool":
      return "system";
    default:
      return "user";
  }
}
