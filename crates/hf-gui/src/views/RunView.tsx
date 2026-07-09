import { useState, useEffect, useRef } from "react";
import { pickFolder, pickFile, getTransport } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import { usePrefs } from "../providers/PrefsContext";
import { useRunStatus } from "../providers/RunStatusContext";
import { useRunOutput } from "../providers/RunOutputContext";
import { useTarget } from "../providers/TargetContext";
import { Button, Input, Select, ViewHeader } from "../components/ui";
import { Play, Activity, AlertTriangle, FolderOpen, Square, RotateCw, RotateCcw } from "lucide-react";
import type { ViewType } from "../types";

export function RunView({
  embedded = false,
  onNavigate,
}: {
  embedded?: boolean;
  onNavigate?: (view: ViewType) => void;
}) {
  const { activeProject, setActiveProject } = useProject();
  const { markDone, markSkipped } = usePipeline();
  const { sandboxArch } = usePrefs();
  const { setActiveEngine } = useRunStatus();
  const { target: sharedTarget, engine: sharedEngine, compiled } = useTarget();
  // Run output (log/stats/summary/running) lives in a shared, always-mounted
  // context, so a run keeps streaming and is preserved when you navigate away.
  const { log, stats: liveStats, summary, running, cancelling, runFuzzer, runSyzkaller, cancelRun } = useRunOutput();
  // Embedded in the workflow, the project comes from the workflow's gate.
  const [localProject, setLocalProject] = useState(activeProject);
  const project = embedded ? activeProject : localProject;
  const [target, setTarget] = useState(sharedTarget || "");
  const [engine, setEngine] = useState(sharedEngine || "libfuzzer");
  const [duration, setDuration] = useState("60");
  const logRef = useRef<HTMLDivElement>(null);

  // syzkaller (kernel fuzzing) campaign artifacts.
  const [kernelImage, setKernelImage] = useState("");
  const [diskImage, setDiskImage] = useState("");
  const [sshKey, setSshKey] = useState("");
  const [managerCfg, setManagerCfg] = useState("");
  const [vmCount, setVmCount] = useState("2");

  const isSyz = engine === "syzkaller";

  // Note: target/engine initialize from the shared context on mount (the
  // Harness -> Run handoff). Because switching views unmounts this component,
  // a fresh mount always picks up the latest shared values without a syncing
  // effect.

  // Keep the live log pinned to the latest line as progress streams in.
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [log]);

  // Whether the target's harness binary actually exists on disk. The shared
  // `compiled` flag is only a localStorage hint and can go stale (e.g. after
  // the workspace is cleared), so the badge is driven from `artifact_summary`,
  // a real on-disk check -- otherwise Run shows "(compiled)" and then dead-ends
  // with "compiled harness not found".
  const [harnessBuilt, setHarnessBuilt] = useState(compiled);
  useEffect(() => {
    // syzkaller has no harness binary; the badge is hidden for it anyway.
    if (isSyz) return;
    let cancelled = false;
    getTransport()
      .invoke<{ harness_built: boolean }>("artifact_summary", { project: project ?? "", target: target ?? "" })
      .then((s) => {
        if (!cancelled) setHarnessBuilt(Boolean(s.harness_built));
      })
      .catch(() => {
        if (!cancelled) setHarnessBuilt(false);
      });
    return () => {
      cancelled = true;
    };
  }, [project, target, isSyz, summary]);

  async function browse() {
    const path = await pickFolder();
    if (path) {
      setLocalProject(path);
      setActiveProject(path); // persist immediately so it survives navigation
    }
  }

  async function run() {
    if (!project) return;
    // Non-kernel engines require a target symbol.
    if (!isSyz && !target) return;
    setActiveProject(project);
    setActiveEngine(engine);
    try {
      const crashes = isSyz
        ? await runSyzkaller({
            project,
            arch: sandboxArch,
            duration: Math.max(1, Math.floor(Number(duration) || 60)),
            kernel_image: kernelImage || null,
            disk_image: diskImage || null,
            ssh_key: sshKey || null,
            manager_cfg: managerCfg || null,
            vm_count: Number(vmCount) || 2,
          })
        : await runFuzzer({ project, target, engine, duration: Math.max(1, Math.floor(Number(duration) || 60)), arch: sandboxArch });
      markDone("run");
      // If the run found no crashes, there is nothing to triage.
      if (crashes === 0) markSkipped("triage");
    } catch {
      // The error is already surfaced in the run output log.
    } finally {
      setActiveEngine(null);
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      {!embedded && (
        <ViewHeader
          title="Fuzz Run"
          description={
            isSyz
              ? "Drive a syzkaller kernel-fuzzing campaign in the sandbox via syz-manager against a KCOV kernel + rootfs."
              : "Compile a harness in the sandbox and drive a fuzzing engine against the target."
          }
        />
      )}

      <div className="grid grid-cols-2 gap-3">
        {!embedded && (
          <div className="flex flex-col gap-1">
            <Label>Project</Label>
            <div className="flex gap-1">
              <Input
                mono
                type="text"
                placeholder="/path/to/project"
                value={project}
                onChange={(e) => setLocalProject(e.target.value)}
                className="flex-1"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={browse}
                title="Browse for folder"
              >
                <FolderOpen size={14} />
              </Button>
            </div>
          </div>
        )}
        {!isSyz && (
          <div className="flex flex-col gap-1">
            <Label>
              Target Symbol
              {harnessBuilt ? (
                <span style={{ color: "var(--success)", marginLeft: "8px" }}> (compiled)</span>
              ) : (
                target && <span style={{ color: "var(--text-muted)", marginLeft: "8px" }}> (not built)</span>
              )}
            </Label>
            <Input
              mono
              type="text"
              placeholder="parse_value"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
        )}
        <div className="flex flex-col gap-1">
          <Label>Engine</Label>
          <Select
            value={engine}
            onChange={(v) => setEngine(v)}
            options={[
              { value: "libfuzzer", label: "libFuzzer" },
              { value: "afl++", label: "AFL++" },
              { value: "honggfuzz", label: "honggfuzz" },
              { value: "clusterfuzzlite", label: "ClusterFuzzLite" },
              { value: "syzkaller", label: "syzkaller (kernel)" },
            ]}
          />
        </div>
        <div className="flex flex-col gap-1">
          <Label>Duration (seconds)</Label>
          <Input
            type="number"
            min={1}
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
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
            <Input
              type="number"
              min={1}
              value={vmCount}
              onChange={(e) => setVmCount(e.target.value)}
            />
          </div>
        </div>
      )}

      <div className="flex items-center gap-2">
        <Button
          variant="primary"
          className="self-start"
          onClick={run}
          disabled={running || !project || (!isSyz && !target)}
          loading={running}
        >
          {!running && <Play size={14} />}
          {running ? "Running..." : isSyz ? "Launch Campaign" : "Run Fuzzer"}
        </Button>

        {/* Stop is offered for any in-flight run. Both harness fuzzing and
            kernel (syzkaller) campaigns register a cancellation token, and
            cancel_run signals every active run, so this works for both. */}
        {running && (
          <Button
            variant="danger"
            className="self-start"
            onClick={() => void cancelRun()}
            loading={cancelling}
            title="Cancel the running campaign"
          >
            {!cancelling && <Square size={14} />}
            {cancelling ? "Stopping..." : "Stop"}
          </Button>
        )}
      </div>

      {/* No target for this project yet (e.g. opened Run straight from Projects):
          the run button is disabled, so point the user at where to get one. */}
      {!isSyz && !target && project && !running && (
        <div className="surface-card text-sm" style={{ padding: "var(--space-md)", borderLeft: "3px solid var(--warning, #d9a441)" }}>
          No harness target selected for this project yet.
          {onNavigate ? (
            <>
              {" "}
              <button
                onClick={() => onNavigate("harness")}
                className="underline"
                style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", padding: 0 }}
              >
                Discover and build a harness first
              </button>
              .
            </>
          ) : (
            " Discover and build a harness first (Harness view)."
          )}
        </div>
      )}

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

      {summary && !running && summary.stagnation && (
        <div
          className="surface-card flex items-center gap-3"
          style={{
            padding: "var(--space-md)",
            borderLeft: "3px solid var(--warning, var(--accent))",
            animation: "slideInUp 0.2s ease",
          }}
        >
          <AlertTriangle size={18} style={{ color: "var(--warning, var(--accent))", flexShrink: 0 }} />
          <div className="flex-1">
            <div className="text-sm" style={{ fontWeight: 600 }}>
              Coverage stalled
            </div>
            <div className="text-xs text-text-secondary" style={{ lineHeight: 1.5 }}>
              {stagnationHint(summary.stagnation)}
            </div>
          </div>
          {summary.stagnation === "new_harness" && onNavigate && (
            <Button variant="outline" size="sm" onClick={() => onNavigate("harness")}>
              <RotateCw size={14} /> Regenerate harness
            </Button>
          )}
        </div>
      )}

      {summary && !running && summary.autoRevert && (
        <div
          className="surface-card flex items-center gap-3"
          style={{
            padding: "var(--space-md)",
            borderLeft: "3px solid var(--accent)",
            animation: "slideInUp 0.2s ease",
          }}
        >
          <RotateCcw size={18} style={{ color: "var(--accent)", flexShrink: 0 }} />
          <div className="flex-1">
            <div className="text-sm" style={{ fontWeight: 600 }}>
              Auto-reverted the harness
            </div>
            <div className="text-xs text-text-secondary" style={{ lineHeight: 1.5 }}>
              This revision dropped coverage {summary.autoRevert.drop_pct.toFixed(1)}% (
              {summary.autoRevert.regressed_edges} &lt; {summary.autoRevert.previous_edges} edges), so
              the previous revision <code>{summary.autoRevert.to_rev.slice(0, 8)}</code> was restored
              and recompiled.
            </div>
          </div>
        </div>
      )}

      {log.length > 0 && (
        <div
          ref={logRef}
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

/** User-facing guidance for a backend coverage-stagnation proposal. */
function stagnationHint(proposal: string): string {
  switch (proposal) {
    case "new_harness":
      return "Coverage plateaued during the run. Regenerating the harness may reach new code paths.";
    case "custom_mutator":
      return "Coverage plateaued. Adding a dictionary or seed corpus may help the fuzzer make progress.";
    case "stop":
      return "Coverage plateaued and further fuzzing is unlikely to find more. Consider stopping this target.";
    default:
      return "Coverage plateaued during the run.";
  }
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
        <Input
          mono
          type="text"
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="flex-1"
        />
        <Button
          variant="outline"
          size="sm"
          onClick={onPick}
          title="Browse for file"
        >
          <FolderOpen size={14} />
        </Button>
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
