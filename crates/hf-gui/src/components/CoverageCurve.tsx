import { Activity } from "lucide-react";
import { useI18n } from "../i18nContext";
import type { CoverageSample } from "../types";

// The intra-run coverage curve: edges over elapsed time, drawn as an area chart.
export function CoverageCurve({ samples }: { samples: CoverageSample[] }) {
  const { t } = useI18n();
  const W = 600;
  const H = 150;
  const padL = 6;
  const padR = 6;
  const padT = 10;
  const padB = 16;
  const tMax = Math.max(1, ...samples.map((s) => s.t));
  const eMax = Math.max(1, ...samples.map((s) => s.edges));
  const x = (t: number) => padL + (t / tMax) * (W - padL - padR);
  const y = (e: number) => H - padB - (e / eMax) * (H - padT - padB);
  const pts = samples.map((s) => `${x(s.t).toFixed(1)},${y(s.edges).toFixed(1)}`);
  const line = `M${pts.join(" L")}`;
  const area = `M${x(samples[0].t).toFixed(1)},${H - padB} L${pts.join(" L")} L${x(
    samples[samples.length - 1].t,
  ).toFixed(1)},${H - padB} Z`;
  const peakEdges = Math.max(...samples.map((s) => s.edges));
  const duration = samples[samples.length - 1].t;
  return (
    <div className="min-w-0">
      <div className="flex items-center justify-between text-xs text-text-muted mb-2 gap-2">
        <span className="flex items-center gap-1">
          <Activity size={12} /> {t("runs.coverageOverTime")}
        </span>
        <span className="truncate">
          {t("runs.curveSummary", { edges: peakEdges.toLocaleString(), duration: Math.round(duration), samples: samples.length })}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" style={{ display: "block" }}>
        <path d={area} fill="var(--success)" opacity={0.14} />
        <path d={line} fill="none" stroke="var(--success)" strokeWidth={1.5} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        <line x1={padL} y1={H - padB} x2={W - padR} y2={H - padB} stroke="var(--border)" strokeWidth={1} vectorEffect="non-scaling-stroke" />
      </svg>
    </div>
  );
}
