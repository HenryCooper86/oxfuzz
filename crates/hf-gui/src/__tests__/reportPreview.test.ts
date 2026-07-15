import { describe, it, expect } from "vitest";
import { codeInfo } from "../lib/reportPreviewCode";

describe("codeInfo", () => {
  it("detects a mermaid fenced block by language class", () => {
    const { lang, text } = codeInfo("language-mermaid", "pie showData\n");
    expect(lang).toBe("mermaid");
    // Trailing newline is trimmed so mermaid.render gets clean source.
    expect(text).toBe("pie showData");
  });

  it("reports the language for other code blocks", () => {
    const { lang } = codeInfo("language-rust", "fn main() {}");
    expect(lang).toBe("rust");
  });

  it("returns an empty language for inline/plain code", () => {
    const { lang, text } = codeInfo(undefined, "x = 1");
    expect(lang).toBe("");
    expect(text).toBe("x = 1");
  });
});
