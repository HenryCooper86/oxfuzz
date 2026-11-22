import "../i18n.parityAnalysis";
import { useEffect, useState } from "react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import { isObject, type AttributionCandidate, type SurfaceMeasurement, type UnreachedCandidate } from "../lib/parityAnalysis";

type Loaded<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; value: T };

interface View<C> { measurement: SurfaceMeasurement; candidates: C[] }

function useSurface<C>(command: string, project: string, lang: string): Loaded<View<C>> {
  const [state, setState] = useState<Loaded<View<C>>>({ status: "loading" });
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) setState({ status: "loading" }); });
    if (!project) return () => { active = false; };
    Promise.resolve().then(() => getTransport().invoke<View<C>>(command, { project, lang })).then((value) => {
      if (!active) return;
      if (isObject(value) && isObject(value.measurement) && Array.isArray(value.candidates)) setState({ status: "ready", value });
      else setState({ status: "error", error: "unexpected response" });
    }).catch((caught: unknown) => { if (active) setState({ status: "error", error: String(caught) }); });
    return () => { active = false; };
  }, [command, project, lang]);
  return state;
}

/** Read-only views over cached coverage measurements; neither runs anything. */
export function SurfacePanels({ project, lang }: { project: string; lang: string }) {
  const { t } = useI18n();
  const unreached = useSurface<UnreachedCandidate>("unreached_surface", project, lang);
  const attribution = useSurface<AttributionCandidate>("coverage_attribution", project, lang);
  return <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
    <Panel title={t("parity.analysis.surface.unreachedTitle")} state={unreached} empty="parity.analysis.surface.unreachedEmpty" measuring="parity.analysis.surface.unreachedMeasured"
      row={(c) => <li key={c.symbol} className="flex justify-between gap-2"><span className="font-mono truncate">{c.symbol}</span><span className="text-text-muted shrink-0">{t("parity.analysis.surface.score", { score: c.discovery_score.toFixed(2) })} · {t(`parity.analysis.surface.attempt.${c.attempt.state}`)}</span></li>} />
    <Panel title={t("parity.analysis.surface.attributionTitle")} state={attribution} empty="parity.analysis.surface.attributionEmpty" measuring="parity.analysis.surface.attributionMeasured"
      row={(c) => <li key={c.symbol} className="flex justify-between gap-2"><span className="font-mono truncate">{c.symbol}</span><span className="text-text-muted shrink-0">{t("parity.analysis.surface.score", { score: c.discovery_score.toFixed(2) })} · {Math.round(c.covered_share * 100)}% · {c.tier.tier === "untouched" ? t("parity.analysis.surface.untouched") : t(`parity.analysis.surface.${c.tier.tier}`, { covered: c.tier.covered, total: c.tier.total })}</span></li>} />
  </div>;
}

function Panel<C>({ title, state, empty, measuring, row }: { title: string; state: Loaded<View<C>>; empty: string; measuring: string; row: (candidate: C) => React.ReactNode }) {
  const { t } = useI18n();
  return <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }} aria-label={title}>
    <div className="text-sm font-medium">{title}</div>
    <p className="text-xs text-text-muted m-0">{t("parity.analysis.surface.readOnly")}</p>
    {state.status === "loading" && <p role="status" className="text-xs text-text-muted m-0">{t("parity.analysis.surface.loading")}</p>}
    {state.status === "error" && <p role="alert" className="text-xs m-0" style={{ color: "var(--error)" }}>{t("parity.analysis.surface.failed", { error: state.error })}</p>}
    {state.status === "ready" && (state.value.measurement.state === "unavailable"
      ? <p role="status" className="text-xs text-text-muted m-0">{t("parity.analysis.surface.noMeasurement", { reason: state.value.measurement.reason })}</p>
      : <>
        <p className="text-xs m-0">{t(measuring, { n: state.value.measurement.measurements })}</p>
        {state.value.candidates.length === 0
          ? <p className="text-xs text-text-muted m-0">{t(empty)}</p>
          : <ul className="m-0 text-xs flex flex-col gap-1" style={{ listStyle: "none", paddingLeft: 0 }}>{state.value.candidates.map(row)}</ul>}
      </>)}
  </section>;
}
