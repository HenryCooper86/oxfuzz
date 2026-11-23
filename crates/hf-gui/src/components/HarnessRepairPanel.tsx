import "../i18n.parityHarness";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import { adoptHarnessRevision } from "../lib/parityHarness";
import type { FindingHarnessRepair, FindingReviewItem } from "../types";
import { Button } from "./ui";

const OUTCOME_NOTES = {
  proposed: "parityHarness.findingRepairProposed",
  unchanged: "parityHarness.findingRepairUnchanged",
  rejected: "parityHarness.findingRepairRejected",
  failed: null,
} as const;

/** Draft a harness repair from a finding that points at the harness. */
export function HarnessRepairPanel({ item, disabled }: { item: FindingReviewItem; disabled: boolean }) {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [repair, setRepair] = useState<FindingHarnessRepair | null>(null);
  const [adopted, setAdopted] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const { disposition } = item.disposition;
  if ((disposition !== "harness_defect" && disposition !== "input_independent_fault") || !item.latest_scoped_actions_allowed) return null;

  async function run(action: () => Promise<void>) {
    setBusy(true); setError(null);
    try {
      await action();
    } catch (reason) {
      if (mounted.current) setError(String(reason));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  const draft = () => run(async () => {
    setRepair(null); setAdopted(null);
    const result = await getTransport().invoke<FindingHarnessRepair>("finding_harness_repair", { project: item.project_root, findingId: item.crash.id });
    if (mounted.current) setRepair(result);
  });
  const adopt = (proposal: FindingHarnessRepair, harnessId: string) => run(async () => {
    const result = await adoptHarnessRevision({ project: item.project_root, target: proposal.target, engine: proposal.engine, lang: proposal.lang }, harnessId);
    if (mounted.current) setAdopted(result.status);
  });
  const note = repair && OUTCOME_NOTES[repair.outcome];

  return <div data-testid="harness-repair" className="rounded-md border border-border text-xs flex flex-col gap-2" style={{ padding: "var(--space-sm)" }}>
    <span className="text-text-secondary">{t("parityHarness.findingRepairHelp")}</span>
    <div className="flex flex-wrap gap-2">
      <Button size="sm" variant="outline" loading={busy} disabled={disabled || busy} onClick={() => { void draft(); }}>{t("parityHarness.findingRepair")}</Button>
      {repair?.harness_id && !adopted && <Button size="sm" disabled={disabled || busy} onClick={() => { void adopt(repair, repair.harness_id as string); }}>{t("parityHarness.adopt")}</Button>}
    </div>
    {note && <p role="status" className="m-0">{t(note, { id: repair?.harness_id ?? "" })}</p>}
    {adopted && <p role="status" className="m-0">{t("parityHarness.findingAdopted", { status: adopted })}</p>}
    {error && <p role="alert" className="m-0" style={{ color: "var(--error)" }}>{error}</p>}
  </div>;
}
