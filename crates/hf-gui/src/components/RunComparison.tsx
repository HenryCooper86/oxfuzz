import "../i18n.parityAnalysis";
import { useEffect, useState } from "react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import { isObject, type CoverageDiffReport } from "../lib/parityAnalysis";
import { Button } from "./ui/Button";

interface Assessment {
  baseline_id: string;
  result_id: string;
  comparable: boolean;
  reason: string;
  setup_matches: boolean | null;
  harness_changed: boolean | null;
  binary_changed: boolean | null;
  edge_delta: string | null;
}
interface Selection { baselineId: string; resultId: string }
type State = { status: "loading" } | { status: "error"; error: string } | { status: "loaded"; value: Assessment };

export function RunComparison(props: Selection) {
  return <SelectedComparison key={`${props.baselineId}/${props.resultId}`} {...props} />;
}
function SelectedComparison({ baselineId, resultId }: Selection) {
  const { t } = useI18n();
  const [state, setState] = useState<State>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    void getTransport().invoke<Assessment>("run_comparison", { baselineId, resultId }).then(value => {
      if (!active) return;
      if (value.baseline_id !== baselineId || value.result_id !== resultId) {
        setState({ status: "error", error: t("runs.comparison.wrongSelection") });
      } else {
        setState({ status: "loaded", value });
      }
    }).catch((error: unknown) => { if (active) setState({ status: "error", error: String(error) }); });
    return () => { active = false; };
  }, [baselineId, resultId, attempt, t]);
  if (state.status === "loading") return <p role="status" className="m-0 text-xs text-text-muted">{t("runs.comparison.loading")}</p>;
  if (state.status === "error") return <div role="alert" className="text-xs flex flex-wrap gap-2 items-center"><span>{t("runs.comparison.unavailable")}: {state.error}</span><Button variant="outline" size="sm" onClick={() => { setState({ status: "loading" }); setAttempt(value => value + 1); }}>{t("runs.comparison.retry")}</Button></div>;
  const value = state.value;
  return <div role="status" className="rounded-md border border-border p-3 text-xs flex flex-col gap-1">
    <p className="m-0">{t(`runs.comparison.${value.reason}`)}</p>
    <div className="flex flex-wrap gap-x-3 text-text-muted">
      {value.setup_matches ? <span>{t("runs.comparison.setupMatches")}</span> : null}
      {value.harness_changed ? <span>{t("runs.comparison.harnessChanged")}</span> : null}
      {value.binary_changed ? <span>{t("runs.comparison.binaryChanged")}</span> : null}
    </div>
    {value.comparable && value.edge_delta !== null ? <p className="m-0 font-semibold">{t("runs.comparison.delta")}: {value.edge_delta}</p> : null}
    {value.comparable ? <p className="m-0 text-text-muted">{t("runs.comparison.measurement")}</p> : null}
    <EdgeSetDiff baselineId={baselineId} resultId={resultId} />
  </div>;
}

type DiffState = { status: "idle" } | { status: "loading" } | { status: "error"; error: string } | { status: "loaded"; report: CoverageDiffReport };

/** Exact set arithmetic between the two runs' retained edge sets, on request. */
function EdgeSetDiff({ baselineId, resultId }: Selection) {
  const { t } = useI18n();
  const [state, setState] = useState<DiffState>({ status: "idle" });
  async function compare() {
    setState({ status: "loading" });
    try {
      const report = await getTransport().invoke<CoverageDiffReport>("run_edge_diff", { baselineId, resultId });
      setState(isObject(report) ? { status: "loaded", report } : { status: "error", error: t("parity.analysis.edgeDiff.unexpected") });
    } catch (error) {
      setState({ status: "error", error: String(error) });
    }
  }
  return <div className="flex flex-col gap-1 border-t border-border pt-2 mt-1" data-testid="edge-set-diff">
    <div className="flex flex-wrap items-center gap-2">
      <span className="font-semibold">{t("parity.analysis.edgeDiff.title")}</span>
      <Button variant="outline" size="sm" onClick={() => void compare()} loading={state.status === "loading"} disabled={state.status === "loading"}>{t("parity.analysis.edgeDiff.compare")}</Button>
    </div>
    {state.status === "error" && <p role="alert" className="m-0" style={{ color: "var(--error)" }}>{state.error}</p>}
    {state.status === "loaded" && <EdgeDiffReport report={state.report} />}
  </div>;
}

function EdgeDiffReport({ report }: { report: CoverageDiffReport }) {
  const { t } = useI18n();
  return <div className="flex flex-col gap-1">
    <p className="m-0">{t("parity.analysis.edgeDiff.counts", { lost: report.only_a, gained: report.only_b, shared: report.common, union: report.union })}</p>
    <p className="m-0 text-text-muted">{t("parity.analysis.edgeDiff.totals", { a: report.edges_a, b: report.edges_b })}</p>
    {!report.same_binary && <p className="m-0 text-text-muted">{t("parity.analysis.edgeDiff.differentBinary")}</p>}
    {report.only_a_sample.length > 0 && <p className="m-0 font-mono">{t("parity.analysis.edgeDiff.lostSample", { cap: report.sample_cap })}: {report.only_a_sample.join(", ")}</p>}
    {report.only_b_sample.length > 0 && <p className="m-0 font-mono">{t("parity.analysis.edgeDiff.gainedSample", { cap: report.sample_cap })}: {report.only_b_sample.join(", ")}</p>}
  </div>;
}
