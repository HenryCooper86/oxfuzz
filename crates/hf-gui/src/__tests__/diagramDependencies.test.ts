// @vitest-environment jsdom
import createDOMPurify from "dompurify";
import katex from "katex";
import { describe, expect, it } from "vitest";

describe("diagram rendering dependencies", () => {
  // GHSA-p98j-92pf-mc4p: hooks must not leave live event handlers behind.
  it("removes event handlers from nodes detached during sanitization", () => {
    const sanitizer = createDOMPurify(window);
    const root = document.createElement("div");
    const wrapper = document.createElement("section");
    const image = document.createElement("img");
    image.setAttribute("onerror", "unexpectedHandler()");
    wrapper.append(image);
    root.append(wrapper);
    sanitizer.addHook("afterSanitizeElements", (node) => {
      if (node === wrapper) wrapper.remove();
    });

    sanitizer.sanitize(root, { IN_PLACE: true });

    expect(root.contains(wrapper)).toBe(false);
    expect(image.hasAttribute("onerror")).toBe(false);
  });

  // GHSA-238p-pmpm-9mq7: Mermaid relies on KaTeX's default trust setting.
  it("does not treat inherited renderer options as permission for links", () => {
    const options = Object.create({ trust: true }) as katex.KatexOptions;
    const html = katex.renderToString(String.raw`\href{https://example.com}{link}`, options);
    const output = document.createElement("div");
    output.innerHTML = html;

    expect(output.querySelector("a")).toBeNull();
  });

  it("retains sanitized math markup with the options used by Mermaid", () => {
    const rendered = katex.renderToString(String.raw`\frac{x^2}{2}`, {
      throwOnError: true,
      displayMode: true,
      output: "mathml",
    });
    const output = document.createElement("div");
    output.innerHTML = createDOMPurify(window).sanitize(rendered);

    expect(output.querySelector("math mfrac msup")).not.toBeNull();
    expect(output.querySelector("math")?.textContent).toContain("x");
  });
});
