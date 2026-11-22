import "../i18n.parityAnalysis";
import { useEffect, useRef, useState } from "react";
import { Fingerprint, ShieldCheck } from "lucide-react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import type { CampaignTrustReport, RunEdgeSetCapture } from "../lib/parityAnalysis";
import { Button } from "./ui";

/** The trust audit of one finished run and the edge-set capture it can use. */
export function TrustReportPanel({ runId }: { runId: string }) {
  const { t } = useI18n();
  const [report, setReport] = useState<CampaignTrustReport | null>(null);
  const [capture, setCapture] = useState<RunEdgeSetCapture | null>(null);
  const [busy, setBusy] = useState<"trust" | "capture" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  async function load() {
    if (busy) return;
    setBusy("trust"); setError(null);
    try {
      const value = await getTransport().invoke<CampaignTrustReport>("campaign_trust_report", { runId });
      if (mounted.current) setReport(value);
    } catch (caught) {
      if (mounted.current) setError(String(caught));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }
  async function captureEdges() {
    if (busy) return;
    setBusy("capture"); setError(null);
    try {
      const value = await getTransport().invoke<RunEdgeSetCapture>("capture_run_edges", { runId });
      if (mounted.current) setCapture(value);
    } catch (caught) {
      if (mounted.current) setError(String(caught));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }

  return <section className="mt-3 flex flex-col gap-2 text-xs" aria-label={t("parity.analysis.trust.title")}>
    <div className="text-sm font-medium">{t("parity.analysis.trust.title")}</div>
    <div className="flex flex-wrap gap-2">
      <Button size="sm" variant="outline" onClick={() => void load()} loading={busy === "trust"} disabled={busy !== null}>{busy !== "trust" && <ShieldCheck size={13} />}{t(report ? "parity.analysis.trust.refresh" : "parity.analysis.trust.show")}</Button>
      <Button size="sm" variant="outline" onClick={() => void captureEdges()} loading={busy === "capture"} disabled={busy !== null} title={t("parity.analysis.trust.captureHelp")}>{busy !== "capture" && <Fingerprint size={13} />}{t("parity.analysis.trust.capture")}</Button>
    </div>
    {error && <p role="alert" className="m-0" style={{ color: "var(--error)" }}>{error}</p>}
    {capture && <p role="status" className="m-0">{t(capture.already_retained ? "parity.analysis.trust.captureRetained" : "parity.analysis.trust.captured", { edges: capture.edges, inputs: capture.inputs })}</p>}
    {report && <div data-testid="trust-report" className="flex flex-col gap-1">
      <p className="m-0 font-medium">{t("parity.analysis.trust.determination")}: {t(`parity.analysis.trust.determination.${report.determination}`)}</p>
      <ul className="m-0 flex flex-col gap-1" style={{ listStyle: "none", paddingLeft: 0 }}>
        {report.gates.map((gate) => <li key={gate.claim}>
          <span className="font-medium">{t(`parity.analysis.trust.claim.${gate.claim}`)}</span>: {t(`parity.analysis.trust.verdict.${gate.verdict}`)}
          <span className="text-text-muted"> -- {gate.detail}</span>
        </li>)}
      </ul>
      {report.unlicensed_claims.length > 0 && <p className="m-0 text-text-secondary">{t("parity.analysis.trust.unlicensed")}: {report.unlicensed_claims.map((claim) => t(`parity.analysis.trust.claim.${claim}`)).join(", ")}</p>}
    </div>}
  </section>;
}
