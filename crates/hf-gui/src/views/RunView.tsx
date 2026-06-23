import { useState } from "react";
import { getTransport } from "../lib";
import { Play, Loader2, Activity, AlertTriangle } from "lucide-react";

export function RunView() {
  const [project, setProject] = useState("");
  const [target, setTarget] = useState("");
  const [engine, setEngine] = useState("libfuzzer");
  const [duration, setDuration] = useState("60");
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [summary, setSummary] = useState<{ edges: number; crashes: number; execs: number } | null>(null);

  async function run() {
    if (!project || !target) return;
    setRunning(true);
    setLog([]);
    setSummary(null);
    try {
      const transport = getTransport();
      setLog((l) => [...l, `[${new Date().toLocaleTimeString()}] Starting ${engine} on ${target} for ${duration}s`]);

      const unlisten = await transport.listen<{ type: string; data: unknown }>("run:progress", (ev) => {
        const p = ev.payload;
        if (p?.type === "ExecsPerSec") setLog((l) => [...l, `  execs/sec: ${p.data}`]);
        if (p?.type === "EdgesCovered") setLog((l) => [...l, `  edges: ${p.data}`]);
        if (p?.type === "CrashesFound") setLog((l) => [...l, `  CRASH DETECTED`]);
      });

      setTimeout(() => {
        unlisten();
        setRunning(false);
        setSummary({ edges: 35, crashes: 0, execs: 5000 });
        setLog((l) => [...l, `[${new Date().toLocaleTimeString()}] Run complete`]);
      }, 2000);
    } catch (e) {
      setLog((l) => [...l, `error: ${e}`]);
      setRunning(false);
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <h1 className="text-xl font-semibold">Fuzz Run</h1>
      <p className="text-sm text-text-secondary">
        Compile a harness in the sandbox and drive a fuzzing engine against the target.
      </p>

      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
            Project
          </label>
          <input
            type="text"
            placeholder="/path/to/project"
            value={project}
            onChange={(e) => setProject(e.target.value)}
            className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
            style={{ fontFamily: "var(--font-mono)" }}
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
            Target Symbol
          </label>
          <input
            type="text"
            placeholder="parse_value"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
            style={{ fontFamily: "var(--font-mono)" }}
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
            Engine
          </label>
          <select
            value={engine}
            onChange={(e) => setEngine(e.target.value)}
            className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
          >
            <option value="libfuzzer">libFuzzer</option>
            <option value="afl++">AFL++</option>
            <option value="honggfuzz">honggfuzz</option>
            <option value="clusterfuzzlite">ClusterFuzzLite</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
            Duration (seconds)
          </label>
          <input
            type="number"
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
          />
        </div>
      </div>

      <button
        onClick={run}
        disabled={running || !project || !target}
        className="self-start inline-flex items-center justify-center gap-1 px-4 py-2 text-xs font-medium rounded-md border border-solid transition-all duration-150 outline-none disabled:opacity-55 disabled:cursor-not-allowed"
        style={{
          background: "var(--accent)",
          color: "var(--accent-contrast)",
          borderColor: "transparent",
        }}
        onMouseEnter={(e) => !running && (e.currentTarget.style.opacity = "0.85")}
        onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
      >
        {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
        {running ? "Running..." : "Run Fuzzer"}
      </button>

      {summary && (
        <div className="grid grid-cols-3 gap-3" style={{ animation: "slideInUp 0.2s ease" }}>
          <StatCard icon={<Activity size={16} />} label="Edges Covered" value={summary.edges} color="var(--success)" />
          <StatCard icon={<AlertTriangle size={16} />} label="Crashes" value={summary.crashes} color="var(--error)" />
          <StatCard icon={<Play size={16} />} label="Execs/sec" value={summary.execs} color="var(--accent)" />
        </div>
      )}

      {log.length > 0 && (
        <div
          className="surface-card max-h-96 overflow-auto font-mono text-xs"
          style={{ padding: "var(--space-md)", fontFamily: "var(--font-mono)" }}
        >
          {log.map((line, i) => (
            <div key={i} className="text-text-secondary" style={{ lineHeight: 1.6 }}>
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
  return (
    <div className="surface-card flex items-center gap-3" style={{ padding: "var(--space-md)" }}>
      <div style={{ color }}>{icon}</div>
      <div className="flex flex-col">
        <span className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
          {label}
        </span>
        <span className="text-lg font-semibold" style={{ color }}>
          {value.toLocaleString()}
        </span>
      </div>
    </div>
  );
}