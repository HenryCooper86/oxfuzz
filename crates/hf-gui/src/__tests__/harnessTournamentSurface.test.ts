import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned harness tournament surface", () => {
  it("declares the serialized tournament result", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface HarnessTournamentResult");
    expect(types).toContain("interface HarnessCandidateEvidence");
    expect(types).toContain("interface SmokeEvidence");
    expect(types).toContain("winner_index");
    expect(types).toContain("compile_error");
    expect(types).toContain("repairs_used");
  });

  it("shows every candidate, not just the winner", () => {
    const panel = source("../components/HarnessTournamentPanel.tsx");
    expect(panel).toContain("result.candidates.map");
    expect(panel).toContain("candidate.compile_error");
    expect(panel).toContain("candidate.repairs_used");
    expect(panel).toContain("candidate.smoke");
  });

  it("renders the service ranking without recomputing it", () => {
    const panel = source("../components/HarnessTournamentPanel.tsx");
    // Optional chaining is fine; what matters is that the ranking is the
    // service's, not one computed here.
    expect(panel).toMatch(/result\??\.ranking/);
    expect(panel).toContain("result.winner_index");
    expect(panel).not.toContain("rankCandidates");
    expect(panel).not.toMatch(/candidates\.sort\(/);
  });

  it("states that a tournament does not promote", () => {
    const panel = source("../components/HarnessTournamentPanel.tsx");
    expect(panel).toContain("harnessTournament.noPromotion");
  });

  it("keeps REST and Tauri as transports", () => {
    expect(source("../lib/httpTransport.ts")).toContain('path: "/harness/tournament"');
    expect(source("../../src-tauri/src/commands.rs")).toContain(
      "pub async fn harness_tournament",
    );
    expect(source("../../../hf-web/src/router.rs")).toContain('.route("/harness/tournament"');
  });

  it("is mounted in the harness view", () => {
    expect(source("../views/HarnessView.tsx")).toContain("HarnessTournamentPanel");
  });

  it("keeps English and Chinese tournament labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"harnessTournament.title": "Harness Tournament"');
    expect(translations).toContain('"harnessTournament.title": "测试桩选拔"');
    expect(translations).toContain('"harnessTournament.winner": "Selected"');
    expect(translations).toContain('"harnessTournament.winner": "已选中"');
  });
});
