import { useState, useEffect } from "react";
import { getTransport, useDefectDojo } from "../lib";
import { usePrefs } from "../providers/prefs";
import { useRunStatus } from "../providers/runStatus";
import type { EngineId, SystemStatus } from "../types";
import { useI18n } from "../i18nContext";
import { Container, Box, ShieldCheck } from "lucide-react";

// Engine display order + how each maps to a SystemStatus flag and the engine id
// the Run view reports while running (so we can highlight the active one).
const ENGINES: { label: string; key: keyof SystemStatus; runId: EngineId }[] = [
  { label: "libFuzzer", key: "libfuzzer", runId: "libfuzzer" },
  { label: "AFL++", key: "aflplusplus", runId: "afl++" },
  { label: "honggfuzz", key: "honggfuzz", runId: "honggfuzz" },
  { label: "syzkaller", key: "syzkaller", runId: "syzkaller" },
];

export function StatusBar() {
  const { sandboxArch } = usePrefs();
  const { t: translate } = useI18n();
  const [disconnected, setDisconnected] = useState(false);
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const { activeEngine } = useRunStatus();
  // DefectDojo is an optional integration, so it appears in the bar only once
  // configured -- matching the sidebar entry. Green when the instance answers.
  const { configured: defectDojoOn } = useDefectDojo();
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [cost, setCost] = useState<{ cost_usd: number; calls: number; input_tokens: number; output_tokens: number } | null>(null);
  const [time, setTime] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const t = getTransport();
    let active = true;
    let refreshing = false;
    const refreshStatus = async () => {
      if (refreshing) return;
      refreshing = true;
      try {
        const value = await t.invoke<SystemStatus>("system_status_cmd");
        if (active) {
          setStatus(value);
          setDisconnected(false);
          setLastChecked(new Date().toLocaleTimeString());
        }
      } catch {
        if (active) { setStatus(null); setDisconnected(true); }
      } finally { refreshing = false; }
    };
    void refreshStatus();

    // Keep runtime availability and current-session cost indicators fresh.
    // LLM spend accrues invisibly during agent turns / report+harness gen;
    // surface a running total so cost is never a surprise.
    const refreshCost = () => {
      t.invoke<{ cost_usd: number; calls: number; input_tokens: number; output_tokens: number }>("diagnostics_cost_summary")
        .then(value => { if (active) setCost(value); })
        // Do not keep labeling a stale value as this session's spend when the
        // diagnostics store is unavailable. The full panel surfaces the error.
        .catch(() => { if (active) setCost(null); });
    };
    refreshCost();

    const poll = setInterval(() => {
      void refreshStatus();
      refreshCost();
    }, 5000);

    return () => {
      active = false;
      clearInterval(poll);
    };
  }, [sandboxArch, retry]);

  return (
    <footer
      className="flex flex-wrap items-center justify-between gap-2 flex-shrink-0 select-none"
      style={{
        minHeight: "28px",
        padding: "0 var(--space-lg)",
        background: "var(--surface-secondary)",
        borderTop: "1px solid var(--border)",
        fontSize: "11px",
        color: "var(--text-muted)",
      }}
    >
      <div className="flex flex-wrap items-center gap-3">
        {status && (
          <>
            <StatusDot label="Docker" active={status.docker} icon={<Container size={11} />} />
            <StatusDot label="Sandbox" active={status.sandbox_image} icon={<Box size={11} />} />
            <span style={{ width: "1px", height: "12px", background: "var(--border)" }} />
            {ENGINES.map((e) => (
              <StatusDot
                key={e.runId}
                label={e.label}
                active={Boolean(status[e.key])}
                running={activeEngine === e.runId}
              />
            ))}
            {defectDojoOn && (
              <>
                <span style={{ width: "1px", height: "12px", background: "var(--border)" }} />
                <StatusDot label="DefectDojo" active={status.defectdojo} icon={<ShieldCheck size={11} />} />
              </>
            )}
          </>
        )}
        {!status && <span role="status">{translate(disconnected ? "gui.disconnected" : "gui.checkingStatus")}
          {lastChecked && <> · {translate("gui.lastChecked", { time: lastChecked })}</>}
          {disconnected && <button className="ml-2 underline" onClick={() => setRetry(value => value + 1)}>{translate("common.retry")}</button>}
        </span>}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        {activeEngine && (
          <span className="flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "var(--accent)",
                animation: "pulse 1.2s ease-in-out infinite",
              }}
            />
            Fuzzing: {ENGINES.find((e) => e.runId === activeEngine)?.label ?? activeEngine}
          </span>
        )}
        {cost && cost.cost_usd > 0 && (
          <span
            title={`LLM spend this session: $${cost.cost_usd.toFixed(4)} · ${cost.calls} calls · ${(cost.input_tokens + cost.output_tokens).toLocaleString()} tokens`}
          >
            ${cost.cost_usd.toFixed(2)}
          </span>
        )}
        <span>{time}</span>
      </div>
    </footer>
  );
}

function StatusDot({
  label,
  active,
  icon,
  running,
}: {
  label: string;
  active: boolean;
  icon?: React.ReactNode;
  running?: boolean;
}) {
  const color = running ? "var(--accent)" : active ? "var(--success)" : "var(--text-muted)";
  const title = running
    ? `${label} (running)`
    : active
      ? label
      : `${label} (unavailable)`;
  return (
    <div
      className="flex items-center gap-1"
      title={title}
    >
      {icon}
      <span style={{ color }}>{label}</span>
      <span
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          background: color,
          opacity: active || running ? 1 : 0.4,
          animation: running ? "pulse 1.2s ease-in-out infinite" : undefined,
        }}
      />
    </div>
  );
}
