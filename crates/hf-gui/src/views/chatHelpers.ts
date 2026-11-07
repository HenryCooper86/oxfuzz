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

export interface CanonicalChatTurn {
  role: string;
  content: string;
  /** RFC 3339 time the message was persisted (absent on older backends). */
  timestamp?: string;
}

export interface CanonicalChatMessage {
  role: ChatRole;
  content: string;
  timestamp: string;
  /** Pretty-printed tool output, shown behind a collapsed disclosure. */
  detail?: string;
}

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

/** Rebuild visible state from the backend-owned display transcript. */
export function toCanonicalChatMessages(
  turns: CanonicalChatTurn[],
  fallbackTimestamp: () => string = () => new Date().toLocaleTimeString(),
): CanonicalChatMessage[] {
  return turns.map((turn) => {
    const role = normalizeChatRole(turn.role);
    return {
      role,
      content: role === "assistant" ? normalizeAssistantContent(turn.content) : turn.content,
      timestamp: persistedTime(turn.timestamp) ?? fallbackTimestamp(),
    };
  });
}

/** Local display time of a persisted RFC 3339 stamp, or null when unusable. */
function persistedTime(stamp: string | undefined): string | null {
  if (!stamp) return null;
  const date = new Date(stamp);
  return Number.isNaN(date.getTime()) ? null : date.toLocaleTimeString();
}

const COMPOSER_MIN_PX = 76;
const COMPOSER_EXPANDED_MIN_PX = 200;
const COMPOSER_MAX_FRACTION = 0.4;
const COMPOSER_EXPANDED_MAX_FRACTION = 0.5;

/** Height of the composer textarea: about three lines at rest, growing with
 *  its content up to a share of the window, then scrolling internally. */
export function composerLayout(input: {
  scrollHeight: number;
  expanded: boolean;
  viewportHeight: number;
}): { height: number; scroll: boolean } {
  const min = input.expanded ? COMPOSER_EXPANDED_MIN_PX : COMPOSER_MIN_PX;
  const fraction = input.expanded ? COMPOSER_EXPANDED_MAX_FRACTION : COMPOSER_MAX_FRACTION;
  const max = Math.max(min, Math.floor(input.viewportHeight * fraction));
  return {
    height: Math.min(Math.max(input.scrollHeight, min), max),
    scroll: input.scrollHeight > max,
  };
}

const TOOL_ARG_VALUE_MAX = 40;
const TOOL_LINE_MAX = 120;
const TOOL_HEADLINE_MAX = 100;
const TOOL_DETAIL_MAX = 4000;

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

function scalarText(value: unknown, max: number): string {
  return clip(typeof value === "string" ? value : JSON.stringify(value), max);
}

/** One-line tool call label: the name plus a short argument summary. */
export function formatToolCall(name: string, args: unknown): string {
  if (!isRecord(args)) return name;
  const pairs = Object.entries(args).map(([key, value]) => `${key}=${scalarText(value, TOOL_ARG_VALUE_MAX)}`);
  return pairs.length ? clip(`${name} (${pairs.join(", ")})`, TOOL_LINE_MAX) : name;
}

function describeEntry(key: string, value: unknown): string {
  if (Array.isArray(value)) return `${key}[${value.length}]`;
  if (isRecord(value)) return `${key}{}`;
  return `${key}=${scalarText(value, 24)}`;
}

/** A tool result reduced to a one-line headline plus bounded detail text. */
export function summarizeToolResult(name: string, summary: string): { headline: string; detail: string } {
  const text = summary.trim();
  if (!text) return { headline: name, detail: "" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (isRecord(parsed)) {
    const entries = Object.entries(parsed).map(([key, value]) => describeEntry(key, value));
    return {
      headline: clip(`${name}: ${entries.join(", ")}`, TOOL_HEADLINE_MAX),
      detail: clip(JSON.stringify(parsed, null, 2), TOOL_DETAIL_MAX),
    };
  }
  return {
    headline: clip(`${name}: ${text.split("\n")[0]}`, TOOL_HEADLINE_MAX),
    detail: clip(text, TOOL_DETAIL_MAX),
  };
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
