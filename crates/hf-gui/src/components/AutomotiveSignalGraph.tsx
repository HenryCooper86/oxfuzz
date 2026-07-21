import { useMemo, useState } from "react";
import { LineChart } from "lucide-react";
import { useI18n } from "../i18nContext";
import type { OfflineFrameView } from "../lib/automotive";

// A signal-over-time line chart. One signal keeps a real-value axis; two or more
// are overlaid on a shared normalized [0,1] axis (each scaled to its own range,
// so shapes/timing compare on ONE axis -- never a dual axis). Identity is never
// color-alone: a dataviz-validated categorical palette (CSS vars, theme-aware),
// dash-pattern secondary encoding, a legend, and direct end-labels. Crosshair +
// per-series tooltip on hover. Self-contained inline SVG (CSP-safe).
const WIDTH = 640;
const HEIGHT = 220;
const PAD_L = 52;
const PAD_R = 96;
const PAD_T = 12;
const PAD_B = 26;
const MAX_SERIES = 4;
const SERIES_COLORS = [
  "var(--chart-series-1)",
  "var(--chart-series-2)",
  "var(--chart-series-3)",
  "var(--chart-series-4)",
];
// Secondary encoding so the palette holds for CVD readers and overlapping lines.
const SERIES_DASH = ["", "6 3", "2 3", "9 3 2 3"];

interface Point {
  t: number;
  v: number;
}

interface Series {
  name: string;
  unit: string;
  points: Point[];
  min: number;
  max: number;
  color: string;
  dash: string;
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

function nearest(points: Point[], time: number): Point | null {
  if (points.length === 0) return null;
  let best = points[0];
  let bestDistance = Infinity;
  for (const point of points) {
    const distance = Math.abs(point.t - time);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = point;
    }
  }
  return best;
}

export function AutomotiveSignalGraph({ frames }: { frames: OfflineFrameView[] }) {
  const { t } = useI18n();
  const [hoverTime, setHoverTime] = useState<number | null>(null);

  const signalNames = useMemo(() => {
    const names = new Set<string>();
    for (const frame of frames) {
      for (const signal of frame.signals) names.add(signal.name);
    }
    return [...names].sort();
  }, [frames]);
  const [selected, setSelected] = useState<string[]>(signalNames.slice(0, 1));

  const active = useMemo(
    () => selected.filter((name) => signalNames.includes(name)).slice(0, MAX_SERIES),
    [selected, signalNames],
  );

  const series = useMemo<Series[]>(() => {
    return active.map((name, index) => {
      const points: Point[] = [];
      let unit = "";
      for (const frame of frames) {
        const match = frame.signals.find((signal) => signal.name === name);
        if (match) {
          points.push({ t: frame.timestamp_micros, v: match.value });
          if (match.unit) unit = match.unit;
        }
      }
      const values = points.map((point) => point.v);
      return {
        name,
        unit,
        points,
        min: values.length ? Math.min(...values) : 0,
        max: values.length ? Math.max(...values) : 1,
        color: SERIES_COLORS[index] ?? SERIES_COLORS[0],
        dash: SERIES_DASH[index] ?? "",
      };
    });
  }, [frames, active]);

  if (signalNames.length === 0) return null;

  const multi = series.length > 1;
  const allPoints = series.flatMap((entry) => entry.points);
  const tMin = allPoints.length ? Math.min(...allPoints.map((point) => point.t)) : 0;
  const tMax = allPoints.length ? Math.max(...allPoints.map((point) => point.t)) : 1;
  const tSpan = tMax - tMin || 1;
  // Single series shows real values; multiple share a normalized [0,1] axis.
  const single = series[0];
  const vMin = single ? single.min : 0;
  const vMax = single ? single.max : 1;
  const vSpan = vMax - vMin || 1;

  const xAt = (micros: number) => PAD_L + ((micros - tMin) / tSpan) * (WIDTH - PAD_L - PAD_R);
  const yAt = (entry: Series, value: number) => {
    let fraction: number;
    if (multi) {
      fraction = entry.max - entry.min > 0 ? (value - entry.min) / (entry.max - entry.min) : 0.5;
    } else {
      fraction = (value - vMin) / vSpan;
    }
    return HEIGHT - PAD_B - fraction * (HEIGHT - PAD_T - PAD_B);
  };

  const gridY = (fraction: number) => HEIGHT - PAD_B - fraction * (HEIGHT - PAD_T - PAD_B);
  const gridRows = multi
    ? [
        { label: "1.0", fraction: 1 },
        { label: "0.5", fraction: 0.5 },
        { label: "0.0", fraction: 0 },
      ]
    : [
        { label: formatValue(vMax), fraction: 1 },
        { label: formatValue((vMax + vMin) / 2), fraction: 0.5 },
        { label: formatValue(vMin), fraction: 0 },
      ];

  function toggle(name: string) {
    setSelected((prev) => {
      if (prev.includes(name)) return prev.filter((value) => value !== name);
      if (prev.length >= MAX_SERIES) return prev;
      return [...prev, name];
    });
  }

  function onMove(event: React.MouseEvent<SVGSVGElement>) {
    if (allPoints.length === 0) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const svgX = ((event.clientX - rect.left) / rect.width) * WIDTH;
    const time = tMin + ((svgX - PAD_L) / (WIDTH - PAD_L - PAD_R)) * tSpan;
    setHoverTime(Math.min(tMax, Math.max(tMin, time)));
  }

  const hoverX = hoverTime === null ? null : xAt(hoverTime);

  // Direct end-labels, decluttered: nudge apart so they never overlap, then
  // shift the whole set up if the last one overflows the plot.
  const LABEL_GAP = 15;
  const endLabels = series
    .map((entry) => {
      const last = entry.points[entry.points.length - 1];
      return last ? { name: entry.name, color: entry.color, y: yAt(entry, last.v) } : null;
    })
    .filter((label): label is { name: string; color: string; y: number } => label !== null)
    .sort((a, b) => a.y - b.y);
  for (let i = 1; i < endLabels.length; i += 1) {
    if (endLabels[i].y - endLabels[i - 1].y < LABEL_GAP) {
      endLabels[i].y = endLabels[i - 1].y + LABEL_GAP;
    }
  }
  const lastLabel = endLabels[endLabels.length - 1];
  const overflow = lastLabel ? lastLabel.y - (HEIGHT - PAD_B) : 0;
  if (overflow > 0) {
    for (const label of endLabels) label.y -= overflow;
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <LineChart size={15} className="text-accent" />
        <h3 className="text-12px font-semibold">{t("automotive.graph.title")}</h3>
        <span className="text-11px text-text-muted">
          {multi ? t("automotive.graph.normalized") : single?.unit || ""}
        </span>
      </div>

      {/* Signal picker: overlay up to MAX_SERIES. */}
      <div className="flex flex-wrap gap-1.5">
        {signalNames.map((name) => {
          const index = active.indexOf(name);
          const on = index >= 0;
          const atCap = !on && active.length >= MAX_SERIES;
          return (
            <button
              key={name}
              onClick={() => toggle(name)}
              disabled={atCap}
              className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-11px transition-colors"
              style={{
                borderColor: on ? "transparent" : "var(--border)",
                background: on ? "var(--surface-active)" : "transparent",
                color: on ? "var(--text-primary)" : "var(--text-muted)",
                opacity: atCap ? 0.4 : 1,
                cursor: atCap ? "not-allowed" : "pointer",
              }}
            >
              <span
                aria-hidden="true"
                style={{
                  width: 10,
                  height: 2,
                  background: on ? SERIES_COLORS[index] : "var(--text-muted)",
                  display: "inline-block",
                }}
              />
              {name}
            </button>
          );
        })}
      </div>

      <div className="relative overflow-hidden rounded-md border border-border bg-surface-primary">
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          width="100%"
          height={HEIGHT}
          preserveAspectRatio="none"
          style={{ display: "block" }}
          onMouseMove={onMove}
          onMouseLeave={() => setHoverTime(null)}
          role="img"
          aria-label={t("automotive.graph.title")}
        >
          {gridRows.map((row) => (
            <line
              key={row.label}
              x1={PAD_L}
              y1={gridY(row.fraction)}
              x2={WIDTH - PAD_R}
              y2={gridY(row.fraction)}
              stroke="var(--border)"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {series.map((entry) => (
            <path
              key={entry.name}
              d={entry.points
                .map(
                  (point, index) =>
                    `${index === 0 ? "M" : "L"}${xAt(point.t).toFixed(1)} ${yAt(entry, point.v).toFixed(1)}`,
                )
                .join(" ")}
              fill="none"
              stroke={entry.color}
              strokeWidth={2}
              strokeDasharray={entry.dash || undefined}
              vectorEffect="non-scaling-stroke"
              strokeLinejoin="round"
            />
          ))}
          {hoverX !== null && (
            <line
              x1={hoverX}
              y1={PAD_T}
              x2={hoverX}
              y2={HEIGHT - PAD_B}
              stroke="var(--text-muted)"
              strokeWidth={1}
              strokeDasharray="3 3"
              vectorEffect="non-scaling-stroke"
            />
          )}
          {hoverTime !== null &&
            series.map((entry) => {
              const point = nearest(entry.points, hoverTime);
              if (!point) return null;
              return (
                <circle key={entry.name} cx={xAt(point.t)} cy={yAt(entry, point.v)} r={3} fill={entry.color} />
              );
            })}
        </svg>

        {/* y-axis labels */}
        {gridRows.map((row) => (
          <span
            key={row.label}
            className="absolute text-10px font-mono text-text-muted"
            style={{ left: 4, top: gridY(row.fraction), transform: "translateY(-50%)" }}
          >
            {row.label}
          </span>
        ))}

        {/* Direct end-labels (<= MAX_SERIES series), decluttered. */}
        {endLabels.map((label) => (
          <span
            key={label.name}
            className="pointer-events-none absolute text-10px font-mono"
            style={{
              right: 4,
              top: label.y,
              transform: "translateY(-50%)",
              color: label.color,
              maxWidth: PAD_R - 8,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {label.name}
          </span>
        ))}

        {allPoints.length > 0 && (
          <>
            <span className="absolute text-10px font-mono text-text-muted" style={{ left: PAD_L, bottom: 2 }}>
              {formatSeconds(tMin, tMin)}
            </span>
            <span
              className="absolute text-10px font-mono text-text-muted"
              style={{ left: xAt(tMax), transform: "translateX(-100%)", bottom: 2 }}
            >
              {formatSeconds(tMax, tMin)}
            </span>
          </>
        )}

        {hoverTime !== null && hoverX !== null && (
          <div
            className="pointer-events-none absolute rounded border border-border bg-surface-secondary px-2 py-1 text-10px shadow"
            style={{
              left: `${(hoverX / WIDTH) * 100}%`,
              top: PAD_T,
              transform: hoverX > WIDTH / 2 ? "translate(-105%, 0)" : "translate(5%, 0)",
              whiteSpace: "nowrap",
            }}
          >
            <div className="mb-0.5 text-text-muted">{formatSeconds(hoverTime, tMin)}</div>
            {series.map((entry) => {
              const point = nearest(entry.points, hoverTime);
              return (
                <div key={entry.name} className="flex items-center gap-1.5">
                  <span
                    aria-hidden="true"
                    style={{ width: 8, height: 8, borderRadius: 2, background: entry.color }}
                  />
                  <span className="text-text-secondary">{entry.name}</span>
                  <span className="ml-auto font-mono text-text-primary">
                    {point ? formatValue(point.v) : "-"}
                    {entry.unit ? ` ${entry.unit}` : ""}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Legend (always for >= 2 series). */}
      {multi && (
        <div className="flex flex-wrap gap-3">
          {series.map((entry) => (
            <span key={entry.name} className="inline-flex items-center gap-1.5 text-11px text-text-secondary">
              <svg width="18" height="8" aria-hidden="true">
                <line
                  x1="0"
                  y1="4"
                  x2="18"
                  y2="4"
                  stroke={entry.color}
                  strokeWidth="2"
                  strokeDasharray={entry.dash || undefined}
                />
              </svg>
              {entry.name}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
