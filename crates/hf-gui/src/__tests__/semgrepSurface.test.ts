import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));

vi.mock("../lib/index", () => ({
  getTransport: () => ({ invoke }),
}));

import { waitForSemgrep } from "../lib/semgrep";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("Semgrep advisory discovery surface", () => {
  it("offers enrichment only for an already-discovered C or C++ inventory", () => {
    const view = source("../views/DiscoverView.tsx");
    expect(view).toContain("setDiscoveryContext({ project, lang })");
    const eligibility = view.slice(view.indexOf("const semgrepEligible"));
    expect(eligibility).toContain("discoveryContext.project === project");
    expect(eligibility).toContain("discoveryContext.lang === lang");
    expect(eligibility).toContain(
      '(discoveryContext.lang === "c" || discoveryContext.lang === "cpp")',
    );
    expect(view).toMatch(/semgrepEligible[\s\S]*discover\.semgrepEnrich/);
  });

  it("does not reclassify a displayed inventory when inputs change", () => {
    const view = source("../views/DiscoverView.tsx");
    expect(view).toContain("project: discoveryContext.project");
    expect(view).toContain("lang: discoveryContext.lang");
    expect(view).not.toMatch(
      /"semgrep_enrich",\s*\{\s*project,\s*lang\s*\}/,
    );
  });

  it("keeps normal discovery free of automatic enrichment", () => {
    const view = source("../views/DiscoverView.tsx");
    const discoverBody = view.match(
      /(?:async function|const) discover[\s\S]*?(?=\n\s*(?:async function|const) [a-zA-Z])/,
    )?.[0];
    expect(discoverBody).toBeDefined();
    expect(discoverBody).not.toContain("semgrep_enrich");
    expect(discoverBody).not.toContain("waitForSemgrep");
  });

  it("maps every service lifecycle state to visible status text", () => {
    const i18n = source("../i18n.extra.ts");
    for (const state of [
      "staging",
      "scanning",
      "validating",
      "persisting",
      "done",
      "failed",
      "cancelled",
    ] as const) {
      expect(i18n).toContain(`"discover.semgrepState.${state}"`);
    }
  });

  it("stops the exact service-owned operation UUID", () => {
    const view = source("../views/DiscoverView.tsx");
    expect(view).toContain('invoke("semgrep_cancel", { operationId })');
    expect(view).toContain("setSemgrepOperationId(operationId)");
  });

  it("stops polling locally after the exact cancellation is accepted", async () => {
    invoke.mockReset();
    const controller = new AbortController();
    controller.abort();

    await expect(
      waitForSemgrep("operation-id", () => undefined, controller.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(invoke).not.toHaveBeenCalled();

    const view = source("../views/DiscoverView.tsx");
    const stop = view.slice(
      view.indexOf("const stopSemgrep"),
      view.indexOf("const baseCandidates"),
    );
    expect(stop.indexOf('invoke("semgrep_cancel", { operationId })')).toBeGreaterThan(
      -1,
    );
    expect(stop.indexOf("semgrepAbortRef.current?.abort()")).toBeGreaterThan(
      stop.indexOf('invoke("semgrep_cancel", { operationId })'),
    );
  });

  it("renders current candidates in service order with attributed scores", () => {
    const view = source("../views/DiscoverView.tsx");
    expect(view).toContain("semgrepInventory.candidates.map");
    expect(view).not.toMatch(/semgrepInventory\.candidates[\s\S]{0,120}\.sort\(/);
    expect(view).toContain('t("discover.semgrepBase"');
    expect(view).toContain('t("discover.semgrepBoost"');
    expect(view).toContain('t("discover.semgrepEffective"');
    expect(view).toContain('t("discover.semgrepMatchedRules"');
  });

  it("suppresses stale boosts and gives the matching rerun guidance", () => {
    const view = source("../views/DiscoverView.tsx");
    expect(view).toContain(
      'const showSemgrepScores = semgrepInventory?.overlay_state === "current"',
    );
    expect(view).toContain('case "stale_source"');
    expect(view).toContain('"discover.semgrepStaleSource"');
    expect(view).toContain('case "stale_base"');
    expect(view).toContain('"discover.semgrepStaleBase"');
    expect(view).toContain('case "incomplete_journal"');
    expect(view).toContain('"discover.semgrepIncompleteJournal"');
  });

  it("retains the base inventory on failed or cancelled enrichment", () => {
    const view = source("../views/DiscoverView.tsx");
    expect(view).toContain("setInventory(inv)");
    expect(view).toContain("setSemgrepInventory(result)");
    expect(view).not.toMatch(
      /catch\s*\([^)]*\)\s*\{[\s\S]{0,180}setInventory\(null\)/,
    );
  });

  it("uses the exact advisory label without confirmation claims", () => {
    const i18n = source("../i18n.tsx");
    const view = source("../views/DiscoverView.tsx");
    expect(i18n).toContain(
      '"discover.semgrepSignals": "Semgrep static-analysis signals"',
    );
    expect(view).toContain('t("discover.semgrepSignals")');
    const semgrepText = [i18n, source("../i18n.extra.ts")]
      .flatMap((file) => file.split("\n"))
      .filter((line) => line.toLowerCase().includes("semgrep"))
      .join("\n")
      .toLowerCase();
    expect(semgrepText).not.toContain("confirmed vulnerability");
    expect(semgrepText).not.toContain("confirmed crash");
  });
});
