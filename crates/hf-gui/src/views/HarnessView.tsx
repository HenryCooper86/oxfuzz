import { useState, useEffect } from "react";
import { getTransport, pickFolder } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import { useTarget } from "../providers/TargetContext";
import type { TargetInventory, HarnessReviewItem } from "../types";
import { Button, Input, Select, ViewHeader } from "../components/ui";
import {
  Crosshair, FolderOpen, Loader2, FileCode, Terminal, Database,
  CheckCircle2, XCircle, ArrowRight, Sparkles, Archive, GitCompare,
} from "lucide-react";
import { lineDiff } from "../lib/diff";

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

interface SmokeResult {
  status: string;
  duration_secs: number;
  execs_per_sec: number;
  crashes: number;
  passed: boolean;
  error?: string;
}

interface PromotionResult {
  status: string;
  harness_id: string;
  message: string;
}

interface SeedResult {
  seeds: { name: string; size: number; sha256: string }[];
}

type StepStatus = "idle" | "loading" | "done" | "error";

export function HarnessView({
  embedded = false,
  stepPrefix,
}: {
  embedded?: boolean;
  // When embedded in the Fuzzing Workflow, the outer stage owns the top-level
  // numbering (harness is step 2), so these internal steps render as sub-steps
  // ("2.1"..."2.5") instead of a competing 1-5 that collides with the outer 3/4.
  stepPrefix?: string;
}) {
  const { activeProject } = useProject();
  const { markDone } = usePipeline();
  const { target: selectedTarget, setTarget: setSelectedTarget, engine, setEngine, lang, setLang, setCompiled } = useTarget();
  // Embedded in the workflow, the project comes from the workflow's gate.
  const [localProject, setLocalProject] = useState(activeProject);
  const project = embedded ? activeProject : localProject;
  const [inventory, setInventory] = useState<TargetInventory | null>(null);
  const [harness, setHarness] = useState<HarnessResult | null>(null);
  const [prevSource, setPrevSource] = useState<string | null>(null);
  const [showDiff, setShowDiff] = useState(false);
  const [compileResult, setCompileResult] = useState<CompileResult | null>(null);
  const [smokeResult, setSmokeResult] = useState<SmokeResult | null>(null);
  const [promotionResult, setPromotionResult] = useState<PromotionResult | null>(null);
  const [seeds, setSeeds] = useState<SeedResult["seeds"] | null>(null);
  // A harness already persisted for the selected target (e.g. built in the
  // Fuzzing Workflow). Hydrated from the store so this view reflects work done
  // elsewhere, not just what was generated in this component instance.
  const [existing, setExisting] = useState<HarnessReviewItem | null>(null);
  const [discoverError, setDiscoverError] = useState<string | null>(null);

  const [harnessStatus, setHarnessStatus] = useState<StepStatus>("idle");
  const [compileStatus, setCompileStatus] = useState<StepStatus>("idle");
  const [smokeStatus, setSmokeStatus] = useState<StepStatus>("idle");
  const [promotionStatus, setPromotionStatus] = useState<StepStatus>("idle");
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
        setDiscoverError(null);
        setInventory(inv);
        if (inv.candidates.length > 0) {
          setSelectedTarget([...inv.candidates].sort((a, b) => b.fit_score - a.fit_score)[0].symbol);
        }
      })
      .catch((e) => {
        // Don't leave the view silently blank -- tell the user discovery failed.
        if (!cancelled) setDiscoverError(String(e));
      });
    return () => { cancelled = true; };
  }, [project, lang, setSelectedTarget]);

  // Hydrate any harness already persisted for the selected target so a harness
  // built elsewhere (e.g. in the Fuzzing Workflow) is visible here too. The
  // review item carries only a source preview, so we surface it as an "existing
  // harness" banner rather than loading it as editable source.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!project || !selectedTarget) {
        if (!cancelled) setExisting(null);
        return;
      }
      try {
        const items = await getTransport().invoke<HarnessReviewItem[]>("harness_review_queue", {
          project,
          target: selectedTarget,
        });
        if (cancelled) return;
        const match = items.find((h) => h.target_symbol === selectedTarget) ?? null;
        setExisting(match);
        if (!harness) {
          const promoted = match?.status === "Promoted";
          setCompiled(promoted);
          if (promoted) setPromotionStatus("done");
          if (match?.smoke_passed) setSmokeStatus("done");
        }
      } catch {
        if (!cancelled) setExisting(null);
      }
    })();
    return () => { cancelled = true; };
  }, [project, selectedTarget, harness, setCompiled]);

  async function generateHarness(target: string): Promise<HarnessResult | null> {
    const prior = harness?.source ?? null;
    setHarnessStatus("loading");
    setCompileStatus("idle");
    setSmokeStatus("idle");
    setPromotionStatus("idle");
    setSeedStatus("idle");
    setHarness(null);
    setCompileResult(null);
    setSmokeResult(null);
    setPromotionResult(null);
    setSeeds(null);
    setCompiled(false);
    setShowDiff(false);
    try {
      const result = await getTransport().invoke<HarnessResult>("harness_draft", {
        project, target, engine, lang,
      });
      setHarness(result);
      // Keep the prior revision so the user can see what regeneration changed.
      setPrevSource(prior && prior !== result.source ? prior : null);
      setHarnessStatus("done");
      markDone("harness");
      return result;
    } catch {
      setHarnessStatus("error");
      return null;
    }
  }

  // Accepts the source explicitly so "Generate All" can compile the harness it
  // just produced without waiting for the `harness` state to settle (the old
  // setTimeout read a stale null and silently skipped compilation).
  async function compileHarness(source?: string): Promise<boolean> {
    const src = source ?? harness?.source;
    if (!src) return false;
    setCompileStatus("loading");
    try {
      const result = await getTransport().invoke<CompileResult>("harness_compile", {
        source: src, project, engine, target: selectedTarget, lang,
      });
      setCompileResult(result);
      const compiled = result.status === "Compiled";
      setCompileStatus(compiled ? "done" : "error");
      if (compiled) {
        markDone("compile");
        setCompiled(false);
      }
      return compiled;
    } catch (e) {
      setCompileResult({ status: "Failed", message: String(e) });
      setCompileStatus("error");
      return false;
    }
  }

  async function smokeHarness(): Promise<boolean> {
    setSmokeStatus("loading");
    setPromotionStatus("idle");
    setPromotionResult(null);
    setCompiled(false);
    try {
      const result = await getTransport().invoke<SmokeResult>("harness_smoke", {
        project, target: selectedTarget, engine, lang,
      });
      setSmokeResult(result);
      setSmokeStatus(result.status === "SmokePassed" ? "done" : "error");
      return result.passed;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setSmokeResult({ status: "Failed", duration_secs: 0, execs_per_sec: 0, crashes: 0, passed: false, error: message });
      setCompileResult((current) => current ?? { status: "Failed", message: String(error) });
      setSmokeStatus("error");
      return false;
    }
  }

  async function promoteHarness(): Promise<boolean> {
    setPromotionStatus("loading");
    try {
      const result = await getTransport().invoke<PromotionResult>("harness_promote", {
        project, target: selectedTarget, engine,
      });
      setPromotionResult(result);
      const promoted = result.status === "Promoted";
      setPromotionStatus(promoted ? "done" : "error");
      setCompiled(promoted);
      return promoted;
    } catch (error) {
      setPromotionResult({ status: "Failed", harness_id: "", message: String(error) });
      setPromotionStatus("error");
      setCompiled(false);
      return false;
    }
  }

  async function promoteWithFindings(): Promise<boolean> {
    setPromotionStatus("loading");
    try {
      const result = await getTransport().invoke<PromotionResult>("harness_promote_with_findings", {
        project, target: selectedTarget, engine,
      });
      setPromotionResult(result);
      const promoted = result.status === "Promoted";
      setPromotionStatus(promoted ? "done" : "error");
      setCompiled(promoted);
      return promoted;
    } catch (error) {
      setPromotionResult({ status: "Failed", harness_id: "", message: String(error) });
      setPromotionStatus("error");
      return false;
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
    const built = await generateHarness(selectedTarget);
    if (!built) return; // harness draft failed; don't proceed to compile/seed
    const compiled = await compileHarness(built.source);
    if (!compiled) return;
    await smokeHarness();
    await generateSeeds();
  }

  // Approval gating: a clean smoke run (or an existing smoke-passed harness) can
  // be approved for campaigns directly; a smoke run that surfaced crashes can
  // only be approved WITH known findings.
  const smokeCrashed = !!smokeResult && smokeResult.crashes > 0;
  const cleanApprovable = Boolean(smokeResult?.passed || (!harness && existing?.smoke_passed));

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      {!embedded && (
        <>
          <ViewHeader
            title="Harness Generation"
            description="Generate, sandbox-compile, smoke-qualify, review, and explicitly approve campaign harnesses."
          />

          {/* Project selection */}
          <div className="flex gap-2">
            <Input
              mono
              type="text"
              placeholder="/path/to/project"
              value={project}
              onChange={(e) => setLocalProject(e.target.value)}
              className="flex-1"
            />
            <Button variant="outline" size="sm" onClick={browse}>
              <FolderOpen size={14} />
            </Button>
          </div>
        </>
      )}

      {discoverError && (
        <div
          className="surface-card text-xs"
          style={{ padding: "var(--space-sm) var(--space-md)", color: "var(--danger, #e5484d)", borderColor: "var(--danger, #e5484d)" }}
        >
          Discovery failed: {discoverError}
        </div>
      )}

      {/* An existing harness for this target (e.g. built in the Fuzzing Workflow),
          surfaced so this view reflects work done elsewhere. Hidden once a fresh
          harness is generated in this session. */}
      {existing && !harness && (
        <div className="surface-card" style={{ padding: "var(--space-md)", animation: "slideInUp 0.2s ease" }}>
          <div className="flex items-center gap-2">
            <Archive size={16} className="text-text-muted" />
            <span className="text-sm font-medium text-text-primary flex-1">
              Existing harness for <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>{existing.target_symbol}</code>
            </span>
            <span
              className="text-xs px-2 py-0.5 rounded-sm"
              style={{ background: "var(--surface-active)", border: "1px solid var(--border)" }}
            >
              {existing.engine} · {existing.status}{existing.smoke_passed ? " · smoke ok" : ""}
            </span>
          </div>
          {existing.source_preview && (
            <pre
              className="text-xs p-3 mt-2 rounded-md overflow-auto max-h-40"
              style={{ background: "var(--surface-code)", border: "1px solid var(--border)", fontFamily: "var(--font-mono)", lineHeight: 1.5, color: "var(--text-secondary)" }}
            >
              {existing.source_preview}
            </pre>
          )}
          <p className="text-xs text-text-muted mt-2">
            Generated previously. Use "Generate" to produce a fresh, editable harness, or proceed to Run.
          </p>
        </div>
      )}

      {/* Target + Engine selection */}
      {inventory && inventory.candidates.length > 0 && (
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex flex-col gap-1 flex-1 min-w-0" style={{ minWidth: 180 }}>
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Target</label>
            <Select
              mono
              value={selectedTarget}
              onChange={(v) => {
                setSelectedTarget(v);
                setHarness(null);
                setCompileResult(null);
                setSmokeResult(null);
                setPromotionResult(null);
                setHarnessStatus("idle");
                setCompileStatus("idle");
                setSmokeStatus("idle");
                setPromotionStatus("idle");
                setSeedStatus("idle");
                setSeeds(null);
                setCompiled(false);
              }}
              options={[...inventory.candidates]
                .sort((a, b) => b.fit_score - a.fit_score)
                .map((c) => ({ value: c.symbol, label: `${c.symbol} (fit: ${c.fit_score.toFixed(2)})` }))}
            />
          </div>
          <div className="flex flex-col gap-1 w-40">
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Engine</label>
            <Select
              value={engine}
              onChange={(v) => setEngine(v)}
              options={[
                { value: "libfuzzer", label: "libFuzzer" },
                { value: "afl++", label: "AFL++" },
                { value: "honggfuzz", label: "honggfuzz" },
                { value: "clusterfuzzlite", label: "ClusterFuzzLite" },
              ].filter((option) => lang !== "rust" || option.value === "libfuzzer" || option.value === "clusterfuzzlite")}
            />
          </div>
          <div className="flex flex-col gap-1 w-32">
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Language</label>
            <Select
              value={lang}
              onChange={(v) => {
                setLang(v);
                if (v === "rust" && engine !== "libfuzzer" && engine !== "clusterfuzzlite") {
                  setEngine("libfuzzer");
                }
              }}
              options={[
                { value: "c", label: "C" },
                { value: "cpp", label: "C++" },
                { value: "rust", label: "Rust" },
              ]}
            />
          </div>
          <Button
            variant="primary"
            onClick={runAll}
            disabled={!selectedTarget || harnessStatus === "loading"}
          >
            <Sparkles size={14} />
            Prepare All
          </Button>
        </div>
      )}

      {/* Step pipeline */}
      {selectedTarget && (
        <div className="flex flex-col gap-3">
          {/* Step 1: Harness source */}
          <Step
            number={1}
            prefix={stepPrefix}
            title="Generate Harness"
            icon={<FileCode size={16} />}
            status={harnessStatus}
            actionLabel="Generate"
            actionClick={() => generateHarness(selectedTarget)}
          >
            {harness && (
              <div className="mt-2">
                {prevSource && (
                  <div className="flex items-center justify-end mb-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setShowDiff((d) => !d)}
                      title="Show what regeneration changed vs the previous harness"
                    >
                      <GitCompare size={12} />
                      {showDiff ? "Hide diff" : "Diff vs previous"}
                    </Button>
                  </div>
                )}
                <div
                  className="rounded-md overflow-auto max-h-64"
                  style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}
                >
                  {showDiff && prevSource ? (
                    <pre className="text-xs p-3" style={{ fontFamily: "var(--font-mono)", lineHeight: 1.5 }}>
                      {lineDiff(prevSource, harness.source).map((d, i) => (
                        <div
                          key={i}
                          style={{
                            background: d.type === "add" ? "rgba(111,207,151,0.12)" : d.type === "del" ? "rgba(229,72,77,0.12)" : "transparent",
                            color: d.type === "add" ? "var(--success)" : d.type === "del" ? "var(--error)" : "var(--text-secondary)",
                            whiteSpace: "pre-wrap",
                          }}
                        >
                          {d.type === "add" ? "+ " : d.type === "del" ? "- " : "  "}
                          {d.text}
                        </div>
                      ))}
                    </pre>
                  ) : (
                    <pre className="text-xs p-3" style={{ fontFamily: "var(--font-mono)", lineHeight: 1.5, color: "var(--text-secondary)" }}>
                      {harness.source}
                    </pre>
                  )}
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
            prefix={stepPrefix}
            title="Compile in Sandbox"
            icon={<Terminal size={16} />}
            status={compileStatus}
            actionLabel="Compile"
            actionClick={() => compileHarness()}
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

          {/* Step 3: Smoke qualification */}
          <Step
            number={3}
            prefix={stepPrefix}
            title="Smoke Qualification"
            icon={<Crosshair size={16} />}
            status={smokeStatus}
            actionLabel="Run Smoke Test"
            actionClick={smokeHarness}
            disabled={compileStatus !== "done" && (harness !== null || (existing?.status !== "Compiled" && existing?.status !== "SmokePassed"))}
          >
            {smokeResult && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                {smokeResult.passed ? (
                  <CheckCircle2 size={14} style={{ color: "var(--success)" }} />
                ) : (
                  <XCircle size={14} style={{ color: "var(--error)" }} />
                )}
                <span style={{ color: smokeResult.passed ? "var(--success)" : "var(--error)" }}>
                  {smokeResult.error
                    ? `Smoke test failed: ${smokeResult.error}`
                    : smokeResult.passed
                    ? `Clean smoke run: ${Math.round(smokeResult.execs_per_sec).toLocaleString()} execs/sec.`
                    : `Smoke found ${smokeResult.crashes} crash(es); triage before approval.`}
                </span>
              </div>
            )}
          </Step>

          {/* Step 4: Human approval. When smoke surfaced a crash the clean
              "Approve for Campaigns" path is gated -- but the actionable path is
              to approve WITH the known finding. Make that the primary (enabled)
              button so the step doesn't read as "stuck" behind a disabled one. */}
          <Step
            number={4}
            prefix={stepPrefix}
            title="Review and Approve"
            icon={<CheckCircle2 size={16} />}
            status={promotionStatus}
            actionLabel={smokeCrashed ? "Approve with Known Findings" : "Approve for Campaigns"}
            actionClick={smokeCrashed ? promoteWithFindings : promoteHarness}
            disabled={
              promotionStatus === "done" ||
              (smokeCrashed ? false : !cleanApprovable)
            }
          >
            <p className="mt-2 text-xs text-text-secondary">
              Approval binds this exact source, engine, target, and smoke evidence. Regenerating or recompiling creates a new revision that must be approved again.
            </p>
            {smokeCrashed && promotionStatus !== "done" && (
              <p className="mt-1 text-xs" style={{ color: "var(--warning)" }}>
                Smoke surfaced {smokeResult?.crashes} crash(es). Approving here records{" "}
                {smokeResult?.crashes === 1 ? "it" : "them"} as a known finding and promotes the
                harness; triage the crash from the Run / Triage step afterward.
              </p>
            )}
            {promotionResult && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                {promotionResult.status === "Promoted" ? (
                  <CheckCircle2 size={14} style={{ color: "var(--success)" }} />
                ) : (
                  <XCircle size={14} style={{ color: "var(--error)" }} />
                )}
                <span style={{ color: promotionResult.status === "Promoted" ? "var(--success)" : "var(--error)" }}>
                  {promotionResult.message}
                </span>
              </div>
            )}
          </Step>

          {/* Step 5: Generate Seeds */}
          <Step
            number={5}
            prefix={stepPrefix}
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

          {/* Step 6: Ready to fuzz */}
          {promotionStatus === "done" && seedStatus === "done" && (
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
  number, prefix, title, icon, status, actionLabel, actionClick, disabled, children,
}: {
  number: number; prefix?: string; title: string; icon: React.ReactNode; status: StepStatus;
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
           prefix ? `${prefix}.${number}` : number}
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
