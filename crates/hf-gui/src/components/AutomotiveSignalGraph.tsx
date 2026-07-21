import { useMemo, useState } from "react";
import { LineChart } from "lucide-react";
import { useI18n } from "../i18nContext";
import { Select } from "./ui";
import type { OfflineFrameView } from "../lib/automotive";

// A single-series, change-over-time line chart. One signal => accent hue, no
// legend (the title names it), recessive axes, text in ink tokens, and a
// crosshair + tooltip on hover. Self-contained inline SVG (CSP-safe).
const WIDTH = 640;
const HEIGHT = 200;
const PAD_L = 52;
const PAD_R = 14;
const PAD_T = 12;
const PAD_B = 26;

interface Point {
  t: number;
  v: number;
}

function formatValue(value: number): string {
  if (!Number.isFinite(value)) return "-";
  const abs = Math.abs(value);
  if (abs !== 0 && (abs < 0.001 || abs >= 1_000_000)) return value.toExponential(2);
  return Number(value.toFixed(3)).toString();
}

function formatSeconds(micros: number, base: number): string {
  return `${((micros - base) / 1_000_000).toFixed(3)}s`;
}

export function AutomotiveSignalGraph({ frames }: { frames: OfflineFrameView[] }) {
  const { t } = useI18n();
  const [hover, setHover] = useState<number | null>(null);

  const signalNames = useMemo(() => {
    const names = new Set<string>();
    for (const frame of frames) {
      for (const signal of frame.signals) names.add(signal.name);
    }
    return [...names].sort();
  }, [frames]);
  const [selected, setSelected] = useState(signalNames[0] ?? "");
  const active = signalNames.includes(selected) ? selected : (signalNames[0] ?? "");

  const { series, unit } = useMemo(() => {
    const out: Point[] = [];
    let signalUnit = "";
    for (const frame of frames) {
      const match = frame.signals.find((signal) => signal.name === active);
      if (match) {
        out.push({ t: frame.timestamp_micros, v: match.value });
        if (match.unit) signalUnit = match.unit;
      }
    }
    return { series: out, unit: signalUnit };
  }, [frames, active]);

  if (signalNames.length === 0) return null;

  const tMin = series.length ? series[0].t : 0;
  const tMax = series.length ? series[series.length - 1].t : 1;
  const values = series.map((point) => point.v);
  const vMin = values.length ? Math.min(...values) : 0;
  const vMax = values.length ? Math.max(...values) : 1;
  const tSpan = tMax - tMin || 1;
  const vSpan = vMax - vMin || 1;
  const xAt = (micros: number) => PAD_L + ((micros - tMin) / tSpan) * (WIDTH - PAD_L - PAD_R);
  const yAt = (value: number) => HEIGHT - PAD_B - ((value - vMin) / vSpan) * (HEIGHT - PAD_T - PAD_B);
  const path = series
    .map((point, index) => `${index === 0 ? "M" : "L"}${xAt(point.t).toFixed(1)} ${yAt(point.v).toFixed(1)}`)
    .join(" ");

  const gridValues = [vMax, (vMax + vMin) / 2, vMin];
  const hovered = hover !== null && hover < series.length ? series[hover] : null;

  function onMove(event: React.MouseEvent<SVGSVGElement>) {
    if (series.length === 0) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const svgX = ((event.clientX - rect.left) / rect.width) * WIDTH;
    let best = 0;
    let bestDistance = Infinity;
    for (let index = 0; index < series.length; index += 1) {
      const distance = Math.abs(xAt(series[index].t) - svgX);
      if (distance < bestDistance) {
        bestDistance = distance;
        best = index;
      }
    }
    setHover(best);
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <LineChart size={15} className="text-accent" />
        <h3 className="text-12px font-semibold">{t("automotive.graph.title")}</h3>
        <Select
          value={active}
          onChange={setSelected}
          options={signalNames.map((name) => ({ value: name, label: name }))}
          className="min-w-40"
        />
        {unit && <span className="text-11px text-text-muted">{unit}</span>}
      </div>
      <div className="relative overflow-hidden rounded-md border border-border bg-surface-primary">
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          width="100%"
          height={HEIGHT}
          preserveAspectRatio="none"
          style={{ display: "block" }}
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
          role="img"
          aria-label={t("automotive.graph.title")}
        >
          {gridValues.map((value) => (
            <line
              key={value}
              x1={PAD_L}
              y1={yAt(value)}
              x2={WIDTH - PAD_R}
              y2={yAt(value)}
              stroke="var(--border)"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          <path
            d={path}
            fill="none"
            stroke="var(--accent)"
            strokeWidth={2}
            vectorEffect="non-scaling-stroke"
            strokeLinejoin="round"
          />
          {hovered && (
            <>
              <line
                x1={xAt(hovered.t)}
                y1={PAD_T}
                x2={xAt(hovered.t)}
                y2={HEIGHT - PAD_B}
                stroke="var(--accent)"
                strokeWidth={1}
                strokeDasharray="3 3"
                vectorEffect="non-scaling-stroke"
              />
              <circle cx={xAt(hovered.t)} cy={yAt(hovered.v)} r={3.5} fill="var(--accent)" />
            </>
          )}
        </svg>
        {/* y-axis labels */}
        {gridValues.map((value) => (
          <span
            key={value}
            className="absolute text-10px font-mono text-text-muted"
            style={{ left: 4, top: yAt(value), transform: "translateY(-50%)" }}
          >
            {formatValue(value)}
          </span>
        ))}
        {series.length > 0 && (
          <>
            <span className="absolute text-10px font-mono text-text-muted" style={{ left: PAD_L, bottom: 2 }}>
              {formatSeconds(tMin, tMin)}
            </span>
            <span className="absolute text-10px font-mono text-text-muted" style={{ right: PAD_R, bottom: 2 }}>
              {formatSeconds(tMax, tMin)}
            </span>
          </>
        )}
        {hovered && (
          <div
            className="pointer-events-none absolute rounded border border-border bg-surface-secondary px-2 py-1 text-10px shadow"
            style={{
              left: `${(xAt(hovered.t) / WIDTH) * 100}%`,
              top: yAt(hovered.v),
              transform: "translate(-50%, -120%)",
              whiteSpace: "nowrap",
            }}
          >
            <div className="font-mono text-text-primary">
              {formatValue(hovered.v)}
              {unit ? ` ${unit}` : ""}
            </div>
            <div className="text-text-muted">{formatSeconds(hovered.t, tMin)}</div>
          </div>
        )}
      </div>
    </div>
  );
}
