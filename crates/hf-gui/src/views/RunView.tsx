import { useState, useEffect } from "react";
import { getTransport, pickFolder, pickFile } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import { usePrefs } from "../providers/PrefsContext";
import { useRunStatus } from "../providers/RunStatusContext";
import { useTarget } from "../providers/TargetContext";
import { Play, Loader2, Activity, AlertTriangle, FolderOpen } from "lucide-react";

export function RunView() {
  const { activeProject, setActiveProject } = useProject();
  const { markDone } = usePipeline();
  const { sandboxArch } = usePrefs();
  const { setActiveEngine } = useRunStatus();
  const { target: sharedTarget, engine: sharedEngine, compiled } = useTarget();
  const [project, setProject] = useState(activeProject);
  const [target, setTarget] = useState(sharedTarget || "");
  const [engine, setEngine] = useState(sharedEngine || "libfuzzer");
  const [duration, setDuration] = useState("60");
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [summary, setSummary] = useState<{ edges: number; crashes: number; execs: number } | null>(null);
  // Live stats updated in place from run:progress events while fuzzing.
  const [liveStats, setLiveStats] = useState<{ execs: number; edges: number; crashes: number }>({
    execs: 0,
    edges: 0,
    crashes: 0,
  });

  // syzkaller (kernel fuzzing) campaign artifacts.
  const [kernelImage, setKernelImage] = useState("");
  const [diskImage, setDiskImage] = useState("");
  const [sshKey, setSshKey] = useState("");
  const [managerCfg, setManagerCfg] = useState("");
  const [vmCount, setVmCount] = useState("2");

  const isSyz = engine === "syzkaller";

  // Sync the shared target/engine into local state when arriving from the
  // Harness view (or when the user picks a different target there).
  useEffect(() => {
    if (sharedTarget) setTarget(sharedTarget);
  }, [sharedTarget]);
  useEffect(() => {
    if (sharedEngine) setEngine(sharedEngine);
  }, [sharedEngine]);

  async function browse() {
    const path = await pickFolder();
    if (path) setProject(path);
  }

  async function run() {
    if (!project) return;
    // Non-kernel engines require a target symbol.
    if (!isSyz && !target) return;
    setActiveProject(project);
    setRunning(true);
    setActiveEngine(engine);
    setLog([]);
    setSummary(null);
    setLiveStats({ execs: 0, edges: 0, crashes: 0 });
    const transport = getTransport();
    let unlisten: (() => void) | undefined;
    try {
      setLog((l) => [
        ...l,
        `[${new Date().toLocaleTimeString()}] Starting ${engine}${isSyz ? "" : ` on ${target}`} for ${duration}s`,
      ]);

      // Subscribe to live progress streamed by the run command. Structured
      // stats update the live bar in place; raw fuzzer lines fill the log.
      unlisten = await transport.listen<{ type: string; data: unknown }>("run:progress", (ev) => {
        const p = ev.payload;
        if (p?.type === "ExecsPerSec") {
          const v = Number(p.data) || 0;
          setLiveStats((s) => ({ ...s, execs: Math.max(s.execs, v) }));
        } else if (p?.type === "EdgesCovered") {
          const v = Number(p.data) || 0;
          setLiveStats((s) => ({ ...s, edges: Math.max(s.edges, v) }));
        } else if (p?.type === "CrashesFound") {
          setLiveStats((s) => ({ ...s, crashes: s.crashes + 1 }));
          setLog((l) => [...l, `  ⚠ CRASH DETECTED`]);
        } else if (p?.type === "LogLine") {
          setLog((l) => (l.length > 500 ? [...l.slice(-500), `  ${p.data}`] : [...l, `  ${p.data}`]));
        }
      });

      type RunResult = { edges: number; crashes: number; execs: number; exit_code: number | null };
      const result = isSyz
        ? await transport.invoke<RunResult>("run_syzkaller", {
            opts: {
              project,
              arch: sandboxArch,
              duration: Number(duration) || 60,
              kernel_image: kernelImage || null,
              disk_image: diskImage || null,
              ssh_key: sshKey || null,
              manager_cfg: managerCfg || null,
              vm_count: Number(vmCount) || 2,
            },
          })
        : await transport.invoke<RunResult>("run_fuzzer", {
            project,
            target,
            engine,
            duration: Number(duration) || 60,
            arch: sandboxArch,
          });
      setSummary({ edges: result.edges, crashes: result.crashes, execs: Math.round(result.execs) });
      setLog((l) => [...l, `[${new Date().toLocaleTimeString()}] Run complete (exit ${result.exit_code ?? "?"})`]);
      markDone("run");
    } catch (e) {
      setLog((l) => [...l, `error: ${e}`]);
    } finally {
      if (unlisten) unlisten();
      setRunning(false);
      setActiveEngine(null);
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <h1 className="text-xl font-semibold">Fuzz Run</h1>
      <p className="text-sm text-text-secondary">
        {isSyz
          ? "Drive a syzkaller kernel-fuzzing campaign in the sandbox via syz-manager against a KCOV kernel + rootfs."
          : "Compile a harness in the sandbox and drive a fuzzing engine against the target."}
      </p>

      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <Label>Project</Label>
          <div className="flex gap-1">
            <input
              type="text"
              placeholder="/path/to/project"
              value={project}
              onChange={(e) => setProject(e.target.value)}
              className="flex-1 px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
              style={{ fontFamily: "var(--font-mono)" }}
            />
            <button
              onClick={browse}
              className="inline-flex items-center justify-center px-3 py-2 text-xs font-medium rounded-md border border-solid border-border bg-surface-primary text-text-secondary transition-all duration-150 outline-none hover:bg-surface-hover hover:text-text-primary"
              title="Browse for folder"
            >
              <FolderOpen size={14} />
            </button>
          </div>
        </div>
        {!isSyz && (
          <div className="flex flex-col gap-1">
            <Label>Target Symbol{compiled && <span style={{ color: "var(--success)", marginLeft: "8px" }}> (compiled)</span>}</Label>
            <input
              type="text"
              placeholder="parse_value"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
              style={{ fontFamily: "var(--font-mono)" }}
            />
          </div>
        )}
        <div className="flex flex-col gap-1">
          <Label>Engine</Label>
          <select
            value={engine}
            onChange={(e) => setEngine(e.target.value)}
            className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
          >
            <option value="libfuzzer">libFuzzer</option>
            <option value="afl++">AFL++</option>
            <option value="honggfuzz">honggfuzz</option>
            <option value="clusterfuzzlite">ClusterFuzzLite</option>
            <option value="syzkaller">syzkaller (kernel)</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <Label>Duration (seconds)</Label>
          <input
            type="number"
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
          />
        </div>
      </div>

      {isSyz && (
        <div
          className="surface-card flex flex-col gap-3"
          style={{ padding: "var(--space-md)", animation: "slideInUp 0.2s ease" }}
        >
          <div className="flex flex-col gap-1">
            <span className="text-xs font-semibold text-text-primary">Kernel campaign artifacts</span>
            <span className="text-xs text-text-muted">
              Supply a kernel image (bzImage) + rootfs to auto-generate a qemu config, or point at an existing
              manager.cfg. A matching SSH key is required to log into the rootfs.
            </span>
          </div>
          <FileField label="Kernel image (bzImage)" placeholder="/path/to/bzImage" value={kernelImage}
            onChange={setKernelImage} onPick={() => pickFile("Select kernel image (bzImage)").then((p) => p && setKernelImage(p))} />
          <FileField label="Rootfs disk image" placeholder="/path/to/rootfs.img" value={diskImage}
            onChange={setDiskImage} onPick={() => pickFile("Select rootfs disk image").then((p) => p && setDiskImage(p))} />
          <FileField label="SSH key (rootfs login)" placeholder="/path/to/id_rsa" value={sshKey}
            onChange={setSshKey} onPick={() => pickFile("Select SSH private key").then((p) => p && setSshKey(p))} />
          <FileField label="Existing manager.cfg (optional override)" placeholder="/path/to/manager.cfg" value={managerCfg}
            onChange={setManagerCfg} onPick={() => pickFile("Select manager.cfg").then((p) => p && setManagerCfg(p))} />
          <div className="flex flex-col gap-1" style={{ maxWidth: "160px" }}>
            <Label>VM count</Label>
            <input
              type="number"
              min={1}
              value={vmCount}
              onChange={(e) => setVmCount(e.target.value)}
              className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
            />
          </div>
        </div>
      )}

      <button
        onClick={run}
        disabled={running || !project || (!isSyz && !target)}
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
        {running ? "Running..." : isSyz ? "Launch Campaign" : "Run Fuzzer"}
      </button>

      {/* Live stats while fuzzing (updates in place from streamed events). */}
      {running && !isSyz && (
        <div className="grid grid-cols-3 gap-3" style={{ animation: "slideInUp 0.2s ease" }}>
          <StatCard icon={<Activity size={16} />} label="Edges Covered" value={liveStats.edges} color="var(--success)" />
          <StatCard icon={<AlertTriangle size={16} />} label="Crashes" value={liveStats.crashes} color="var(--error)" />
          <StatCard icon={<Play size={16} />} label="Execs/sec (peak)" value={liveStats.execs} color="var(--accent)" />
        </div>
      )}

      {summary && !running && (
        <div className="grid grid-cols-3 gap-3" style={{ animation: "slideInUp 0.2s ease" }}>
          <StatCard icon={<Activity size={16} />} label={isSyz ? "Coverage" : "Edges Covered"} value={summary.edges} color="var(--success)" />
          <StatCard icon={<AlertTriangle size={16} />} label="Crashes" value={summary.crashes} color="var(--error)" />
          <StatCard icon={<Play size={16} />} label={isSyz ? "Executed" : "Execs/sec"} value={summary.execs} color="var(--accent)" />
        </div>
      )}

      {log.length > 0 && (
        <div
          className="surface-card max-h-96 overflow-auto"
          style={{ padding: "var(--space-md)", fontFamily: "var(--font-mono)" }}
        >
          {log.map((line, i) => (
            <div key={i} className="text-xs text-text-secondary" style={{ lineHeight: 1.6 }}>
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label className="text-xs text-text-muted uppercase" style={{ letterSpacing: "0.05em", fontWeight: 600 }}>
      {children}
    </label>
  );
}

function FileField({
  label,
  placeholder,
  value,
  onChange,
  onPick,
}: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  onPick: () => void;
}) {
  return (
    <div className="flex flex-col gap-1">
      <Label>{label}</Label>
      <div className="flex gap-1">
        <input
          type="text"
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="flex-1 px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
          style={{ fontFamily: "var(--font-mono)" }}
        />
        <button
          onClick={onPick}
          className="inline-flex items-center justify-center px-3 py-2 text-xs font-medium rounded-md border border-solid border-border bg-surface-primary text-text-secondary transition-all duration-150 outline-none hover:bg-surface-hover hover:text-text-primary"
          title="Browse for file"
        >
          <FolderOpen size={14} />
        </button>
      </div>
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
