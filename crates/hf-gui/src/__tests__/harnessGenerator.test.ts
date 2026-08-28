import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("harness generator choice", () => {
  /// The generator is an operator decision, not an accident of whether a key
  /// happens to be configured on the machine running the service.
  it("sends the chosen policy with every draft request", () => {
    const view = source("../views/HarnessView.tsx");
    expect(view).toMatch(/type AiPolicy = "auto" \| "require" \| "off"/);
    expect(view).toContain('t("harness.generatorRequire")');
    expect(view).toContain('t("harness.generatorOff")');
    // The value reaches the backend rather than only styling a dropdown.
    expect(view).toMatch(/invoke<HarnessResult>\("harness_draft", \{[\s\S]*?ai: aiPolicy/);
  });

  /// Under `auto` a provider outage substitutes the template silently, and the
  /// two harnesses are materially different, so the view must say which one it
  /// is showing.
  it("shows which generator wrote the draft", () => {
    const view = source("../views/HarnessView.tsx");
    expect(view).toContain("harness.generator");
    expect(view).toContain('t("harness.wroteByLlm")');
    expect(view).toContain('t("harness.wroteByHeuristic")');

    const strings = source("../i18n.extra.ts");
    for (const key of [
      "harness.generator",
      "harness.generatorAuto",
      "harness.generatorRequire",
      "harness.generatorOff",
      "harness.wroteByLlm",
      "harness.wroteByHeuristic",
    ]) {
      // Both locales carry the key: a missing translation renders the raw id.
      const occurrences = strings.split(`"${key}":`).length - 1;
      expect(occurrences, `${key} must exist in both en and zh`).toBe(2);
    }
  });

  /// The service is the one place that decides; the surfaces only carry the
  /// choice, so all three speak the same vocabulary.
  it("keeps one vocabulary across the CLI, REST and desktop surfaces", () => {
    expect(source("../../src-tauri/src/commands.rs")).toContain(
      "ai: Option<hf_service::AiPolicy>",
    );
    expect(source("../../../hf-web/src/router.rs")).toContain(
      "ai: hf_service::AiPolicy",
    );
    // Both responses report the generator, not just the CLI.
    expect(source("../../src-tauri/src/commands.rs")).toContain('"generator": draft.generator');
    expect(source("../../../hf-web/src/router.rs")).toContain('"generator": draft.generator');
  });
});
