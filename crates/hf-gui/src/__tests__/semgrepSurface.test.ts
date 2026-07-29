import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildSemgrepPresentation,
  canApplySemgrepResult,
  canStartSemgrep,
  hasOwnedSemgrepOperation,
  semgrepCancelDecision,
  semgrepStateAfterError,
  waitForSemgrep,
} from "../lib/semgrep";
import type {
  SemgrepInventory,
  SemgrepOperationView,
  TargetCandidate,
} from "../types";

const context = { project: "/workspace/parser", lang: "c" };

function candidate(id: string, score: number): TargetCandidate {
  return {
    id,
    project_root: context.project,
    language: "c",
    symbol: id,
    kind: "function",
    location: { file: "parser.c", line: 1, col: 1 },
    signature: `int ${id}(void)`,
    input_surface: "bytes",
    complexity: 1,
    fit_score: score,
    sanitizers: [],
    rationale: "fixture",
  };
}

function inventory(
  overlay: SemgrepInventory["overlay_state"] = "current",
): SemgrepInventory {
  return {
    project_root: context.project,
    language: "c",
    scan_id: "scan-1",
    source_sha256: "abc",
    overlay_state: overlay,
    candidates: [
      {
        ...candidate("service-second", 0.5),
        base_score: 0.5,
        semgrep_boost: 0.1,
        effective_score: 0.6,
        semgrep_matched_rule_count: 1,
      },
      {
        ...candidate("service-first", 0.9),
        base_score: 0.9,
        semgrep_boost: 0.05,
        effective_score: 0.95,
        semgrep_matched_rule_count: 2,
      },
    ],
    findings: [],
    call_graph: {},
  };
}

function doneView(result = inventory()): SemgrepOperationView {
  return {
    operation_id: "operation-id",
    project_root: context.project,
    language: "c",
    state: "done",
    active: false,
    started_at: "2026-07-29T00:00:00Z",
    ended_at: "2026-07-29T00:00:01Z",
    failure_code: null,
    failure_message: null,
    result,
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("Semgrep advisory discovery behavior", () => {
  it("requires build availability and the exact successful C/C++ discovery context", () => {
    expect(canStartSemgrep(true, true, context, context, false)).toBe(true);
    expect(canStartSemgrep(false, true, context, context, false)).toBe(false);
    expect(
      canStartSemgrep(
        true,
        true,
        context,
        { project: "/workspace/other", lang: "c" },
        false,
      ),
    ).toBe(false);
    expect(
      canStartSemgrep(
        true,
        true,
        context,
        { project: context.project, lang: "cpp" },
        false,
      ),
    ).toBe(false);
    expect(
      canStartSemgrep(
        true,
        true,
        { project: context.project, lang: "python" },
        { project: context.project, lang: "python" },
        false,
      ),
    ).toBe(false);
    expect(canStartSemgrep(true, true, context, context, true)).toBe(false);
  });

  it("keeps exact operation ownership independent of a spinner", () => {
    expect(hasOwnedSemgrepOperation("operation-id", "scanning")).toBe(true);
    expect(hasOwnedSemgrepOperation("operation-id", "persisting")).toBe(true);
    expect(hasOwnedSemgrepOperation("operation-id", "done")).toBe(false);
    expect(hasOwnedSemgrepOperation(null, "scanning")).toBe(false);
  });

  it("clears provisional staging when start fails before UUID admission", () => {
    expect(semgrepStateAfterError(null, "staging")).toBeNull();
    expect(semgrepStateAfterError("operation-id", "failed")).toBe("failed");
  });

  it.each([
    [
      "accepted",
      {
        abortPolling: true,
        releaseOwnership: false,
        nextState: "cancelled",
        errorKey: null,
      },
    ],
    [
      "inactive",
      {
        abortPolling: false,
        releaseOwnership: false,
        nextState: null,
        errorKey: null,
      },
    ],
    [
      "not_found",
      {
        abortPolling: false,
        releaseOwnership: true,
        nextState: null,
        errorKey: "discover.semgrepCancelNotFound",
      },
    ],
  ] as const)("applies the %s cancellation contract", (outcome, expected) => {
    expect(semgrepCancelDecision(outcome)).toEqual(expected);
  });

  it("renders enrichment only when its operation and discovery contexts are still exact", () => {
    expect(canApplySemgrepResult(context, context, context)).toBe(true);
    expect(
      canApplySemgrepResult(
        context,
        context,
        { project: "/workspace/other", lang: "c" },
      ),
    ).toBe(false);
    expect(
      canApplySemgrepResult(
        context,
        { project: context.project, lang: "cpp" },
        context,
      ),
    ).toBe(false);
  });

  it("preserves service order and shows scores only for a current overlay", () => {
    const base = [candidate("base", 0.2)];
    const current = inventory("current");
    const presentation = buildSemgrepPresentation(
      base,
      { context, inventory: current },
      context,
      context,
    );

    expect(presentation.candidates.map(({ id }) => id)).toEqual([
      "service-second",
      "service-first",
    ]);
    expect(presentation.inventory).toBe(current);
    expect(presentation.showScores).toBe(true);
    expect(presentation.staleMessageKey).toBeNull();
  });

  it.each([
    ["stale_source", "discover.semgrepStaleSource"],
    ["stale_base", "discover.semgrepStaleBase"],
    ["incomplete_journal", "discover.semgrepIncompleteJournal"],
  ] as const)(
    "suppresses scores and supplies guidance for %s",
    (overlay, messageKey) => {
      const base = [candidate("base", 0.2)];
      const stale = inventory(overlay);
      const stalePresentation = buildSemgrepPresentation(
        base,
        { context, inventory: stale },
        context,
        context,
      );
      expect(stalePresentation.showScores).toBe(false);
      expect(stalePresentation.staleMessageKey).toBe(messageKey);
    },
  );

  it.each(["failed", "cancelled", "no-result"] as const)(
    "retains the untouched base candidate array after %s enrichment",
    () => {
      const base = [
        candidate("base-first", 0.8),
        candidate("base-second", 0.3),
      ];
      const presentation = buildSemgrepPresentation(
        base,
        null,
        context,
        context,
      );

      expect(presentation.candidates).toBe(base);
      expect(presentation.inventory).toBeNull();
      expect(presentation.showScores).toBe(false);
    },
  );

  it("falls back to base candidates when a result belongs to an old context", () => {
    const base = [candidate("base", 0.8)];
    const presentation = buildSemgrepPresentation(
      base,
      { context, inventory: inventory() },
      context,
      { project: "/workspace/other", lang: "c" },
    );
    expect(presentation.candidates).toBe(base);
    expect(presentation.inventory).toBeNull();
  });

  it("releases a hung in-flight status read immediately on abort", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const pending = new Promise<SemgrepOperationView>(() => undefined);
    const waiting = waitForSemgrep(
      "operation-id",
      () => undefined,
      controller.signal,
      {
        transport: { invoke: () => pending },
        pollMs: 1000,
        requestTimeoutMs: 10_000,
      },
    );

    await Promise.resolve();
    controller.abort();

    await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("retries a transient status rejection without losing operation ownership", async () => {
    const states: string[] = [];
    let attempt = 0;
    const result = await waitForSemgrep(
      "operation-id",
      (state) => states.push(state),
      new AbortController().signal,
      {
        transport: {
          invoke: async () => {
            attempt += 1;
            if (attempt === 1) throw new Error("temporary transport failure");
            return doneView();
          },
        },
        pollMs: 0,
        requestTimeoutMs: 100,
      },
    );

    expect(attempt).toBe(2);
    expect(states).toEqual(["done"]);
    expect(result.scan_id).toBe("scan-1");
  });

  it("releases a missing operation and its pending status resources immediately", async () => {
    vi.useFakeTimers();
    const ownership = new AbortController();
    const pending = new Promise<SemgrepOperationView>(() => undefined);
    const waiting = waitForSemgrep(
      "operation-id",
      () => undefined,
      new AbortController().signal,
      {
        transport: { invoke: () => pending },
        ownershipSignal: ownership.signal,
        pollMs: 1000,
        requestTimeoutMs: 10_000,
      },
    );

    await Promise.resolve();
    ownership.abort();

    await expect(waiting).rejects.toMatchObject({
      name: "SemgrepOwnershipReleased",
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps only narrow advisory wording checks", () => {
    const i18n = readFileSync(
      new URL("../i18n.tsx", import.meta.url),
      "utf8",
    );
    const extra = readFileSync(
      new URL("../i18n.extra.ts", import.meta.url),
      "utf8",
    );
    for (const state of [
      "staging",
      "scanning",
      "validating",
      "persisting",
      "done",
      "failed",
      "cancelled",
    ]) {
      expect(extra).toContain(`"discover.semgrepState.${state}"`);
    }
    expect(i18n).toContain(
      '"discover.semgrepSignals": "Semgrep static-analysis signals"',
    );
    const advisoryCopy = `${i18n}\n${extra}`.toLowerCase();
    expect(advisoryCopy).not.toContain("confirmed vulnerability");
    expect(advisoryCopy).not.toContain("confirmed crash");
  });
});
