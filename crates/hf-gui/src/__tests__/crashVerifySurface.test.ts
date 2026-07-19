import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("on-demand crash verification surface (L2 4c)", () => {
  it("exposes a verify_crash transport route and Tauri command", () => {
    expect(source("../lib/httpTransport.ts")).toContain('"/crash/verify"');
    expect(source("../../src-tauri/src/commands.rs")).toContain("pub async fn verify_crash");
    expect(source("../../src-tauri/src/lib.rs")).toContain("verify_crash,");
  });

  it("offers a per-crash verify action and renders the verdict in TriageView", () => {
    const view = source("../views/TriageView.tsx");
    expect(view).toContain('invoke<CrashVerdict | null>("verify_crash"');
    expect(view).toContain('t("triage.verifyCrash")');
    expect(view).toContain("verdict.likely_target_bug");
  });

  it("declares a typed CrashVerdict matching the service", () => {
    expect(source("../types/index.ts")).toContain("interface CrashVerdict");
  });
});
