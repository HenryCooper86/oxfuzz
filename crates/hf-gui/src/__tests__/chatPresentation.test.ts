import { expect, it } from "vitest";
import {
  composerLayout,
  formatToolCall,
  summarizeToolResult,
  toCanonicalChatMessages,
} from "../views/chatHelpers";

it("starts the composer at about three lines and grows to 40% of the window", () => {
  const empty = composerLayout({ scrollHeight: 24, expanded: false, viewportHeight: 1000 });
  expect(empty.height).toBeGreaterThanOrEqual(72);
  expect(empty.height).toBeLessThanOrEqual(80);
  expect(empty.scroll).toBe(false);

  const grown = composerLayout({ scrollHeight: 200, expanded: false, viewportHeight: 1000 });
  expect(grown.height).toBe(200);

  const capped = composerLayout({ scrollHeight: 900, expanded: false, viewportHeight: 1000 });
  expect(capped.height).toBe(400);
  expect(capped.scroll).toBe(true);
});

it("keeps the expanded editor larger than the default one", () => {
  const normal = composerLayout({ scrollHeight: 10, expanded: false, viewportHeight: 800 });
  const big = composerLayout({ scrollHeight: 10, expanded: true, viewportHeight: 800 });
  expect(big.height).toBeGreaterThanOrEqual(200);
  expect(big.height).toBeGreaterThan(normal.height);
});

it("never lets the cap shrink the composer below its minimum on tiny windows", () => {
  const tiny = composerLayout({ scrollHeight: 10, expanded: false, viewportHeight: 100 });
  expect(tiny.height).toBeGreaterThanOrEqual(72);
});

it("shows each message's own persisted time, not the reload time", () => {
  const reloadTime = () => "RELOAD";
  const messages = toCanonicalChatMessages(
    [
      { role: "user", content: "a", timestamp: "2026-11-07T06:16:24Z" },
      { role: "assistant", content: "b", timestamp: "2026-11-07T06:16:40Z" },
      { role: "user", content: "c" },
      { role: "user", content: "d", timestamp: "not a date" },
    ],
    reloadTime,
  );
  const expected = (iso: string) => new Date(iso).toLocaleTimeString();
  expect(messages[0].timestamp).toBe(expected("2026-11-07T06:16:24Z"));
  expect(messages[1].timestamp).toBe(expected("2026-11-07T06:16:40Z"));
  expect(messages[0].timestamp).not.toBe(messages[1].timestamp);
  expect(messages[2].timestamp).toBe("RELOAD");
  expect(messages[3].timestamp).toBe("RELOAD");
});

it("summarizes a tool call on one short line", () => {
  expect(formatToolCall("Glob", { pattern: "**/*.c", path: "/p" })).toBe("Glob (pattern=**/*.c, path=/p)");
  expect(formatToolCall("discover", {})).toBe("discover");
  expect(formatToolCall("discover", null)).toBe("discover");
  const long = formatToolCall("write", { content: "x".repeat(500), n: 3 });
  expect(long.length).toBeLessThan(140);
  expect(long).toContain("n=3");
  expect(long).not.toContain("\n");
});

it("collapses a JSON tool result to a one-line headline with pretty detail", () => {
  const raw = JSON.stringify({ count: 1, matches: ["a.c"], note: "ok" });
  const { headline, detail } = summarizeToolResult("Glob", raw);
  expect(headline).toBe("Glob: count=1, matches[1], note=ok");
  expect(headline).not.toContain("{");
  expect(detail).toBe(JSON.stringify({ count: 1, matches: ["a.c"], note: "ok" }, null, 2));
});

it("bounds long and non-JSON tool results", () => {
  const big = JSON.stringify({ items: Array.from({ length: 2000 }, (_, i) => `item-${i}`) });
  const { headline, detail } = summarizeToolResult("list", big);
  expect(headline).toBe("list: items[2000]");
  expect(detail.length).toBeLessThanOrEqual(4100);
  expect(detail.endsWith("...")).toBe(true);

  const text = summarizeToolResult("shell", "first line\nsecond line");
  expect(text.headline).toBe("shell: first line");
  expect(text.detail).toBe("first line\nsecond line");

  expect(summarizeToolResult("noop", "").detail).toBe("");
});
