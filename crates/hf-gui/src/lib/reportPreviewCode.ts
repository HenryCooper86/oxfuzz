/**
 * Extract the language and source text from a react-markdown code node.
 * Keeping this utility separate lets Help and the lazily loaded report preview
 * share it without pulling the full preview component into the initial bundle.
 */
export function codeInfo(className: unknown, children: unknown): { lang: string; text: string } {
  const lang = typeof className === "string" ? (/language-(\w+)/.exec(className)?.[1] ?? "") : "";
  const text = String(children ?? "").replace(/\n$/, "");
  return { lang, text };
}
