// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { HarnessRepairPanel } from "../components/HarnessRepairPanel";
import type { FindingHarnessRepair, FindingReviewItem } from "../types";

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }) }));

const HARNESS_ID = "a8a7d885-7794-4836-ae66-c191c6de04a7";
const repair = (outcome: FindingHarnessRepair["outcome"]): FindingHarnessRepair => ({
  repair_id: "repair-1",
  outcome,
  detail: "detail",
  harness_id: outcome === "proposed" ? HARNESS_ID : null,
  target: "parse.c::parse",
  engine: "libfuzzer",
  lang: "c",
  repairs_used: 0,
});
const item = (disposition: string, latest = true) => ({
  crash: { id: "crash-1" },
  project_root: "/project",
  disposition: { disposition },
  latest_scoped_actions_allowed: latest,
}) as unknown as FindingReviewItem;

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  mocks.invoke.mockReset();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

const render = (finding: FindingReviewItem) => act(async () => root.render(
  <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: (key) => key }}>
    <HarnessRepairPanel item={finding} disabled={false} />
  </I18nContext.Provider>,
));
const button = (label: string) => [...host.querySelectorAll("button")].find((candidate) => candidate.textContent === label);

it("is offered only for a latest finding that points at the harness", async () => {
  for (const disposition of ["reachability_unproven", "minimization_pending", "resolved"]) {
    await render(item(disposition));
    expect(host.querySelector('[data-testid="harness-repair"]')).toBeNull();
  }
  await render(item("harness_defect", false));
  expect(host.querySelector('[data-testid="harness-repair"]')).toBeNull();
  await render(item("input_independent_fault"));
  expect(host.querySelector('[data-testid="harness-repair"]')).not.toBeNull();
});

it("drafts a proposal and adopts it only on a second explicit action", async () => {
  mocks.invoke.mockImplementation((command: string) => Promise.resolve(command === "finding_harness_repair" ? repair("proposed") : { status: "Compiled" }));
  await render(item("harness_defect"));

  await act(async () => button("parityHarness.findingRepair")?.click());

  expect(mocks.invoke).toHaveBeenCalledTimes(1);
  expect(mocks.invoke).toHaveBeenCalledWith("finding_harness_repair", { project: "/project", findingId: "crash-1" });
  expect(host.textContent).toContain("parityHarness.findingRepairProposed");

  await act(async () => button("parityHarness.findingAdopt")?.click());

  expect(mocks.invoke).toHaveBeenCalledWith("harness_adopt_revision", { project: "/project", target: "parse.c::parse", engine: "libfuzzer", lang: "c", harnessId: HARNESS_ID });
  expect(host.textContent).toContain("parityHarness.findingAdopted");
});

it("offers no adoption when the model changed nothing or dropped the target", async () => {
  for (const [outcome, message] of [["unchanged", "parityHarness.findingRepairUnchanged"], ["rejected", "parityHarness.findingRepairRejected"]] as const) {
    mocks.invoke.mockResolvedValueOnce(repair(outcome));
    await render(item("input_independent_fault"));
    await act(async () => button("parityHarness.findingRepair")?.click());
    expect(host.textContent).toContain(message);
    expect(button("parityHarness.findingAdopt")).toBeUndefined();
  }
});
