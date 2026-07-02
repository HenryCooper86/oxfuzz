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

export function normalizeAssistantContent(content: string): string {
  return extractProtocolFinal(content) ?? content;
}

function extractProtocolFinal(content: string, depth = 0): string | null {
  const trimmed = content.trim();
  if (!trimmed) return null;

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed === "string" && depth < 1) {
      return extractProtocolFinal(parsed, depth + 1);
    }
    if (isRecord(parsed) && typeof parsed.final === "string") {
      return parsed.final;
    }
  } catch {
    /* fall through to relaxed protocol extraction */
  }

  const objectText = firstObjectLikeText(trimmed);
  return objectText ? extractRelaxedStringField(objectText, "final") : null;
}

function firstObjectLikeText(content: string): string | null {
  const fenced = content.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  const candidate = (fenced?.[1] ?? content).trim();
  const start = candidate.indexOf("{");
  return start >= 0 ? candidate.slice(start) : null;
}

function extractRelaxedStringField(content: string, field: string): string | null {
  const key = `"${field}"`;
  const keyPos = content.indexOf(key);
  if (keyPos < 0) return null;

  const afterKey = content.slice(keyPos + key.length);
  const colon = afterKey.indexOf(":");
  if (colon < 0) return null;

  return readRelaxedQuotedString(afterKey.slice(colon + 1).trimStart());
}

function readRelaxedQuotedString(value: string): string | null {
  if (!value.startsWith('"')) return null;

  let out = "";
  let escaped = false;
  for (const ch of value.slice(1)) {
    if (escaped) {
      switch (ch) {
        case '"':
          out += '"';
          break;
        case "\\":
          out += "\\";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        default:
          out += ch;
          break;
      }
      escaped = false;
      continue;
    }

    if (ch === "\\") {
      escaped = true;
    } else if (ch === '"') {
      return out;
    } else {
      out += ch;
    }
  }

  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
