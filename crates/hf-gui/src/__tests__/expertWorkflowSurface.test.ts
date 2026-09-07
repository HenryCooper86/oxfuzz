import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function source(path: string): string {
  return readFileSync(resolve(import.meta.dirname, path), "utf8");
}

describe("expert workflow adapters", () => {
  it("registers every Work Order and closeout Tauri command", () => {
    const registration = source("../../src-tauri/src/lib.rs");
    const workOrders = source("../../src-tauri/src/work_order_commands.rs");
    const closeout = source("../../src-tauri/src/closeout_commands.rs");

    for (const command of [
      "work_order_export",
      "work_order_list",
      "work_order_get",
      "work_order_import",
      "work_order_submissions",
      "work_order_qualify",
      "work_order_attempts",
      "work_order_attempt",
      "work_order_rank",
      "work_order_promote",
    ]) {
      expect(workOrders).toContain(`fn ${command}`);
      expect(registration).toContain(command);
    }
    for (const command of ["run_closeout_report", "run_closeout"]) {
      expect(closeout).toContain(`fn ${command}`);
      expect(registration).toContain(command);
    }
    expect(workOrders).toContain("not included in this application build");
    expect(closeout).toContain("not included in this application build");
    expect(workOrders).toContain("lang: String");
    expect(workOrders).not.toContain("language: String");
  });

  it("mounts Work Orders in Harness and closeout in expanded Run history", () => {
    const harness = source("../views/HarnessView.tsx");
    const runs = source("../views/RunsView.tsx");
    expect(harness).toContain("<WorkOrderPanel");
    expect(harness).toContain("project={project}");
    expect(harness).toContain("target={selectedTarget}");
    expect(harness).toContain("setExternalPromotion({ harnessId, project");
    expect(harness).toContain("item.harness_id === promotedId");
    expect(runs).toContain("<RunCloseoutPanel");
    expect(runs).toContain("runId={r.id}");
    expect(runs).toContain("runKind={r.kind}");
  });

  it("keeps external author admission visible and enforced in the panel", () => {
    const workOrders = source("../components/WorkOrderPanel.tsx");
    expect(workOrders).toContain('t("workOrder.toolRequired")');
    expect(workOrders).toContain("external && !tool.trim()");
  });

  it("renders closeout step names through the paired translation dictionaries", () => {
    const closeout = source("../components/RunCloseoutPanel.tsx");
    expect(closeout).toContain("`runCloseout.step.${step}`");
  });
});
