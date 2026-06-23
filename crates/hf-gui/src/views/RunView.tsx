import { useState } from "react";
import { getTransport } from "../lib";
import { Play } from "lucide-react";

export function RunView() {
  const [project, setProject] = useState("");
  const [target, setTarget] = useState("");
  const [engine, setEngine] = useState("libfuzzer");
  const [duration, setDuration] = useState("60");
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [summary, setSummary] = useState<string | null>(null);

  async function run() {
    if (!project || !target) return;
    setRunning(true);
    setLog([]);
    setSummary(null);
    try {
      const transport = getTransport();
      // In web mode this calls POST /run; in Tauri it invokes the run command.
      // For now, just invoke and show a summary.
      setLog((l) => [...l, `Starting ${engine} on ${target} for ${duration}s`]);
      // Listen for progress events.
      const unlisten = await transport.listen<{ type: string }>("run:progress", (ev) => {
        setLog((l) => [...l, `progress: ${JSON.stringify(ev.payload)}`]);
      });
      // Simulate completion after a short delay (real implementation would
      // wait for the run:complete event).
      setTimeout(() => {
        unlisten();
        setRunning(false);
        setSummary("Run complete. See log for details.");
      }, 1000);
    } catch (e) {
      setLog((l) => [...l, `error: ${e}`]);
      setRunning(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-bold">Fuzz Run</h1>
      <div className="grid grid-cols-2 gap-2">
        <input
          type="text"
          placeholder="Project path"
          value={project}
          onChange={(e) => setProject(e.target.value)}
          className="px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        />
        <input
          type="text"
          placeholder="Target symbol"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        />
        <select
          value={engine}
          onChange={(e) => setEngine(e.target.value)}
          className="px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        >
          <option value="libfuzzer">libFuzzer</option>
          <option value="afl++">AFL++</option>
          <option value="honggfuzz">honggfuzz</option>
          <option value="clusterfuzzlite">ClusterFuzzLite</option>
        </select>
        <input
          type="number"
          placeholder="Duration (s)"
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
          className="px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        />
      </div>
      <button
        onClick={run}
        disabled={running || !project || !target}
        className="self-start px-4 py-2 bg-accent text-surface-tertiary rounded-DEFAULT hover:bg-accent-hover disabled:opacity-50 flex items-center gap-2"
      >
        <Play size={16} />
        {running ? "Running..." : "Run"}
      </button>
      {log.length > 0 && (
        <div className="surface-card p-3 max-h-96 overflow-auto font-mono text-xs">
          {log.map((line, i) => (
            <div key={i} className="text-text-secondary">
              {line}
            </div>
          ))}
        </div>
      )}
      {summary && <p className="text-success">{summary}</p>}
    </div>
  );
}