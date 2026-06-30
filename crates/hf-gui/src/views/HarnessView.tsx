import { useState, useEffect } from "react";
import { getTransport, pickFolder } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import { useTarget } from "../providers/TargetContext";
import type { TargetInventory } from "../types";
import { Button } from "../components/ui";
import {
  Crosshair, FolderOpen, Loader2, FileCode, Terminal, Database,
  CheckCircle2, XCircle, ArrowRight, Sparkles,
} from "lucide-react";

interface HarnessResult {
  source: string;
  target: string;
  engine: string;
  build_cmd: { compiler: string; args: string[] };
  status: string;
}

interface CompileResult {
  status: string;
  message: string;
}

interface SeedResult {
  seeds: { name: string; size: number; sha256: string }[];
}

type StepStatus = "idle" | "loading" | "done" | "error";

export function HarnessView({ embedded = false }: { embedded?: boolean }) {
  const { activeProject } = useProject();
  const { markDone } = usePipeline();
  const { target: selectedTarget, setTarget: setSelectedTarget, engine, setEngine, lang, setLang, setCompiled } = useTarget();
  // Embedded in the workflow, the project comes from the workflow's gate.
  const [localProject, setLocalProject] = useState(activeProject);
  const project = embedded ? activeProject : localProject;
  const [inventory, setInventory] = useState<TargetInventory | null>(null);
  const [harness, setHarness] = useState<HarnessResult | null>(null);
  const [compileResult, setCompileResult] = useState<CompileResult | null>(null);
  const [seeds, setSeeds] = useState<SeedResult["seeds"] | null>(null);

  const [harnessStatus, setHarnessStatus] = useState<StepStatus>("idle");
  const [compileStatus, setCompileStatus] = useState<StepStatus>("idle");
  const [seedStatus, setSeedStatus] = useState<StepStatus>("idle");

  async function browse() {
    const path = await pickFolder();
    if (path) setLocalProject(path);
  }

  // Auto-run discover when project is set.
  useEffect(() => {
    if (!project) return;
    let cancelled = false;
    getTransport().invoke<TargetInventory>("discover", { project, lang })
      .then((inv) => {
        if (cancelled) return;
        setInventory(inv);
        if (inv.candidates.length > 0) {
          setSelectedTarget(inv.candidates.sort((a, b) => b.fit_score - a.fit_score)[0].symbol);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [project, lang, setSelectedTarget]);

  async function generateHarness(target: string) {
    setHarnessStatus("loading");
    setCompileStatus("idle");
    setSeedStatus("idle");
    setHarness(null);
    setCompileResult(null);
    setSeeds(null);
    setCompiled(false);
    try {
      const result = await getTransport().invoke<HarnessResult>("harness_draft", {
        project, target, engine, lang,
      });
      setHarness(result);
      setHarnessStatus("done");
      markDone("harness");
    } catch {
      setHarnessStatus("error");
    }
  }

  async function compileHarness() {
    if (!harness) return;
    setCompileStatus("loading");
    try {
      const result = await getTransport().invoke<CompileResult>("harness_compile", {
        source: harness.source, project, engine, target: selectedTarget, lang,
      });
      setCompileResult(result);
      const compiled = result.status === "Compiled";
      setCompileStatus(compiled ? "done" : "error");
      if (compiled) {
        markDone("compile");
        setCompiled(true);
      }
    } catch (e) {
      setCompileResult({ status: "Failed", message: String(e) });
      setCompileStatus("error");
    }
  }

  async function generateSeeds() {
    setSeedStatus("loading");
    try {
      const result = await getTransport().invoke<SeedResult>("generate_seeds", { project, target: selectedTarget });
      setSeeds(result.seeds);
      setSeedStatus("done");
      markDone("seeds");
    } catch {
      setSeedStatus("error");
    }
  }

  async function runAll() {
    if (!selectedTarget) return;
    await generateHarness(selectedTarget);
    // Auto-compile and seed after harness is generated.
    setTimeout(async () => {
      await compileHarness();
      await generateSeeds();
    }, 100);
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      {!embedded && (
        <>
          <h1 className="text-xl font-semibold">Harness Generation</h1>
          <p className="text-sm text-text-secondary">
            Discover targets, generate harnesses, compile in sandbox, and create matching seed corpora.
          </p>

          {/* Project selection */}
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="/path/to/project"
              value={project}
              onChange={(e) => setLocalProject(e.target.value)}
              className="flex-1 px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
              style={{ fontFamily: "var(--font-mono)" }}
            />
            <Button variant="outline" size="sm" onClick={browse}>
              <FolderOpen size={14} />
            </Button>
          </div>
        </>
      )}

      {/* Target + Engine selection */}
      {inventory && inventory.candidates.length > 0 && (
        <div className="flex gap-3 items-end">
          <div className="flex flex-col gap-1 flex-1">
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Target</label>
            <select
              value={selectedTarget}
              onChange={(e) => { setSelectedTarget(e.target.value); setHarness(null); setCompileResult(null); setSeeds(null); }}
              className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
              style={{ fontFamily: "var(--font-mono)" }}
            >
              {inventory.candidates.sort((a, b) => b.fit_score - a.fit_score).map((c) => (
                <option key={c.id} value={c.symbol}>
                  {c.symbol} (fit: {c.fit_score.toFixed(2)})
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1 w-40">
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Engine</label>
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
          <div className="flex flex-col gap-1 w-32">
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Language</label>
            <select
              value={lang}
              onChange={(e) => setLang(e.target.value)}
              className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
            >
              <option value="c">C</option>
              <option value="cpp">C++</option>
            </select>
          </div>
          <Button
            variant="primary"
            onClick={runAll}
            disabled={!selectedTarget || harnessStatus === "loading"}
          >
            <Sparkles size={14} />
            Generate All
          </Button>
        </div>
      )}

      {/* Step pipeline */}
      {selectedTarget && (
        <div className="flex flex-col gap-3">
          {/* Step 1: Harness source */}
          <Step
            number={1}
            title="Generate Harness"
            icon={<FileCode size={16} />}
            status={harnessStatus}
            actionLabel="Generate"
            actionClick={() => generateHarness(selectedTarget)}
          >
            {harness && (
              <div className="mt-2">
                <div
                  className="rounded-md overflow-auto max-h-64"
                  style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}
                >
                  <pre className="text-xs p-3" style={{ fontFamily: "var(--font-mono)", lineHeight: 1.5, color: "var(--text-secondary)" }}>
                    {harness.source}
                  </pre>
                </div>
                <div className="flex gap-2 mt-2 text-xs text-text-muted">
                  <span>Compiler: <code style={{ color: "var(--accent)" }}>{harness.build_cmd.compiler}</code></span>
                  <span>Flags: <code style={{ color: "var(--text-secondary)" }}>{harness.build_cmd.args.join(" ")}</code></span>
                </div>
              </div>
            )}
          </Step>

          {/* Step 2: Compile */}
          <Step
            number={2}
            title="Compile in Sandbox"
            icon={<Terminal size={16} />}
            status={compileStatus}
            actionLabel="Compile"
            actionClick={compileHarness}
            disabled={!harness}
          >
            {compileResult && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                {compileResult.status === "Compiled" ? (
                  <CheckCircle2 size={14} style={{ color: "var(--success)" }} />
                ) : (
                  <XCircle size={14} style={{ color: "var(--error)" }} />
                )}
                <span style={{ color: compileResult.status === "Compiled" ? "var(--success)" : "var(--error)" }}>
                  {compileResult.message}
                </span>
              </div>
            )}
          </Step>

          {/* Step 3: Generate Seeds */}
          <Step
            number={3}
            title="Generate Seed Corpus"
            icon={<Database size={16} />}
            status={seedStatus}
            actionLabel="Generate Seeds"
            actionClick={generateSeeds}
          >
            {seeds && (
              <div className="mt-2">
                <div className="text-xs text-text-secondary mb-1">{seeds.length} seed(s) generated for "{selectedTarget}":</div>
                <div className="flex flex-wrap gap-1">
                  {seeds.map((s, i) => (
                    <span
                      key={i}
                      className="text-xs px-2 py-1 rounded-sm"
                      style={{ background: "var(--surface-code)", border: "1px solid var(--border)", fontFamily: "var(--font-mono)" }}
                    >
                      {s.name} <span className="text-text-muted">({s.size}b)</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Step>

          {/* Step 4: Ready to fuzz */}
          {compileStatus === "done" && seedStatus === "done" && (
            <div
              className="surface-card flex items-center gap-3"
              style={{ padding: "var(--space-md)", animation: "slideInUp 0.2s ease" }}
            >
              <CheckCircle2 size={20} style={{ color: "var(--success)" }} />
              <div className="flex-1">
                <span className="text-sm font-medium text-text-primary">Harness ready to fuzz</span>
                <p className="text-xs text-text-secondary mt-0.5">
                  Switch to the Run panel to start fuzzing {selectedTarget} with {engine}.
                </p>
              </div>
              <ArrowRight size={16} className="text-text-muted" />
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!inventory && !project && (
        <div className="surface-card flex flex-col items-center justify-center" style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}>
          <Crosshair size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} />
          <p className="text-sm text-text-muted">Select a project folder to discover fuzzing targets.</p>
        </div>
      )}
    </div>
  );
}

function Step({
  number, title, icon, status, actionLabel, actionClick, disabled, children,
}: {
  number: number; title: string; icon: React.ReactNode; status: StepStatus;
  actionLabel: string; actionClick: () => void; disabled?: boolean; children?: React.ReactNode;
}) {
  const colors: Record<StepStatus, string> = {
    idle: "var(--text-muted)",
    loading: "var(--warning)",
    done: "var(--success)",
    error: "var(--error)",
  };
  return (
    <div
      className="surface-card"
      style={{ padding: "var(--space-md)", opacity: disabled ? 0.6 : 1 }}
    >
      <div className="flex items-center gap-3">
        <div
          className="flex items-center justify-center rounded-full shrink-0"
          style={{
            width: "28px", height: "28px",
            background: status === "done" ? "rgba(111,207,151,0.1)" : "var(--surface-active)",
            border: `1px solid ${colors[status]}`,
            color: colors[status],
            fontSize: "12px", fontWeight: 600,
          }}
        >
          {status === "loading" ? <Loader2 size={14} className="animate-spin" /> :
           status === "done" ? <CheckCircle2 size={14} /> :
           status === "error" ? <XCircle size={14} /> :
           number}
        </div>
        <span className="flex items-center gap-2 text-sm font-medium text-text-primary flex-1">
          {icon}
          {title}
        </span>
        <Button
          variant="outline"
          size="sm"
          onClick={actionClick}
          disabled={disabled}
          loading={status === "loading"}
        >
          {actionLabel}
        </Button>
      </div>
      {children}
    </div>
  );
}