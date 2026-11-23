import "../i18n.parityHarness";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import { adoptHarnessRevision } from "../lib/parityHarness";
import type { FindingHarnessRepair, FindingReviewItem } from "../types";
import { Button } from "./ui";

/** Draft a harness repair from a finding that points at the harness. */
export function HarnessRepairPanel({ item, disabled }: { item: FindingReviewItem; disabled: boolean }) {
  const { t } = useI18n();
  const [busy, setBusy] = useState<null | "repair" | "adopt">(null);
  const [repair, setRepair] = useState<FindingHarnessRepair | null>(null);
  const [adopted, setAdopted] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const qualifies = item.disposition.disposition === "harness_defect" || item.disposition.disposition === "input_independent_fault";
  if (!qualifies || !item.latest_scoped_actions_allowed) return null;

  async function draft() {
    setBusy("repair"); setError(null); setRepair(null); setAdopted(null);
    try {
      const result = await getTransport().invoke<FindingHarnessRepair>("finding_harness_repair", { project: item.project_root, findingId: item.crash.id });
      if (mounted.current) setRepair(result);
    } catch (reason) {
      if (mounted.current) setError(String(reason));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }

  async function adopt(proposal: FindingHarnessRepair) {
    if (!proposal.harness_id) return;
    setBusy("adopt"); setError(null);
    try {
      const result = await adoptHarnessRevision({ project: item.project_root, target: proposal.target, engine: proposal.engine, lang: proposal.lang }, proposal.harness_id);
      if (mounted.current) setAdopted(result.status);
    } catch (reason) {
      if (mounted.current) setError(String(reason));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }

  const locked = disabled || busy !== null;
  return <div data-testid="harness-repair" className="rounded-md border border-border text-xs flex flex-col gap-2" style={{ padding: "var(--space-sm)" }}>
    <span className="text-text-secondary">{t("parityHarness.findingRepairHelp")}</span>
    <div className="flex flex-wrap gap-2">
      <Button size="sm" variant="outline" loading={busy === "repair"} disabled={locked} onClick={() => { void draft(); }}>{t(busy === "repair" ? "parityHarness.findingRepairing" : "parityHarness.findingRepair")}</Button>
      {repair?.outcome === "proposed" && !adopted && <Button size="sm" loading={busy === "adopt"} disabled={locked} onClick={() => { void adopt(repair); }}>{t(busy === "adopt" ? "parityHarness.findingAdopting" : "parityHarness.findingAdopt")}</Button>}
    </div>
    {repair?.outcome === "proposed" && <p role="status" className="m-0">{t("parityHarness.findingRepairProposed", { id: repair.harness_id ?? "" })}</p>}
    {repair?.outcome === "unchanged" && <p role="status" className="m-0">{t("parityHarness.findingRepairUnchanged")}</p>}
    {repair?.outcome === "rejected" && <p role="alert" className="m-0">{t("parityHarness.findingRepairRejected")}</p>}
    {adopted && <p role="status" className="m-0">{t("parityHarness.findingAdopted", { status: adopted })}</p>}
    {error && <p role="alert" className="m-0" style={{ color: "var(--error)" }}>{error}</p>}
  </div>;
}
