import { useState, useEffect } from "react";
import { useI18n } from "../i18nContext";
import { getTransport, pickFolder } from "../lib";
import { useProject } from "../providers/project";
import { usePipeline } from "../providers/pipeline";
import { useTarget } from "../providers/target";
import type { TargetInventory, HarnessReviewItem } from "../types";
import { Button, Input, Select, ViewHeader, EmptyState } from "../components/ui";
import { SandboxBanner } from "../components/SandboxBanner";
import { BuildDoctorPanel } from "../components/BuildDoctorPanel";
import { HarnessTournamentPanel } from "../components/HarnessTournamentPanel";
import { OracleStudioPanel } from "../components/OracleStudioPanel";
import {
  Crosshair, FolderOpen, Loader2, FileCode, Terminal, Database,
  CheckCircle2, XCircle, ArrowRight, Sparkles, Archive, GitCompare, AlertTriangle,
} from "lucide-react";
import { lineDiff } from "../lib/diff";
import { useFuzzingSettings } from "../hooks/useFuzzingSettings";
import { enabledEngineOptions, fuzzingActionsEnabled } from "../lib/fuzzingSettings";
import { FuzzingPolicyNotice } from "../components/FuzzingPolicyNotice";
import { TargetSelectionRepairNotice } from "../components/TargetSelectionRepairNotice";
import { projectStorageKey } from "../lib/projectState";

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

/** Deterministic self-verification verdict attached to a smoke result. */
interface HarnessVerdict {
  level: "pass" | "suspect" | "fail";
  reasons: string[];
}

interface SmokeResult {
  status: string;
  duration_secs: number;
  execs_per_sec: number;
  crashes: number;
  passed: boolean;
  /** Present when the service ran its verification pass; absent on local errors. */
  verdict?: HarnessVerdict;
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
  const { t } = useI18n();
  const { activeProject, setActiveProject } = useProject();
  const { markDone } = usePipeline();
  const {
    target: selectedTarget,
    setTarget: setSelectedTarget,
    engine: selectedEngine,
    setEngine,
    lang,
    setLang,
    setCompiled,
    selectionRepair,
    storageError,
    canResetTargetSelections,
    resetTargetSelections,
    retryStorage,
  } = useTarget();
  const { settings: fuzzingSettings, loaded: fuzzingPolicyLoaded, error: fuzzingPolicyError } = useFuzzingSettings();
  const fuzzingEnabled = fuzzingActionsEnabled(fuzzingSettings);
  const engineOptions = fuzzingSettings
    ? enabledEngineOptions(fuzzingSettings, { language: lang })
    : [];
  const selectionBlocked = selectionRepair !== null || storageError !== null;
  const engine = selectionBlocked
    ? selectedEngine
    : engineOptions.some((option) => option.value === selectedEngine)
      ? selectedEngine
      : (engineOptions.find((option) => option.value === fuzzingSettings?.default_engine)
        ?? engineOptions[0])?.value ?? selectedEngine;
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
  // Error text for the two steps that don't carry a result object, so a failure
  // shows *why* instead of just a red circle.
  const [harnessError, setHarnessError] = useState<string | null>(null);
  const [seedError, setSeedError] = useState<string | null>(null);

  async function browse() {
    const path = await pickFolder();
    if (path) setLocalProject(path);
  }

  // Auto-run discover when project is set.
  useEffect(() => {
    if (!project || selectionBlocked) return;
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
  }, [project, lang, selectionBlocked, setSelectedTarget]);

  // Hydrate any harness already persisted for the selected target so a harness
  // built elsewhere (e.g. in the Fuzzing Workflow) is visible here too. The
  // review item carries only a source preview, so we surface it as an "existing
  // harness" banner rather than loading it as editable source.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (selectionBlocked || !project || !selectedTarget) {
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
          // Reflect an already-qualified harness (built in a prior session) in
          // the pipeline so the Progress panel / Workflow don't show it as unfinished.
          if (match?.smoke_passed) {
            markDone("harness");
            markDone("compile");
            markDone("smoke");
          }
          if (promoted) markDone("approve");
        }
      } catch {
        if (!cancelled) setExisting(null);
      }
    })();
    return () => { cancelled = true; };
  }, [project, selectedTarget, harness, selectionBlocked, setCompiled, markDone]);

  async function generateHarness(target: string): Promise<HarnessResult | null> {
    if (!fuzzingSettings || selectionBlocked) return null;
    const prior = harness?.source ?? null;
    setHarnessStatus("loading");
    setHarnessError(null);
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
    } catch (e) {
      setHarnessError(e instanceof Error ? e.message : String(e));
      setHarnessStatus("error");
      return null;
    }
  }

  // Accepts the source explicitly so "Generate All" can compile the harness it
  // just produced without waiting for the `harness` state to settle (the old
  // setTimeout read a stale null and silently skipped compilation).
  async function compileHarness(source?: string): Promise<boolean> {
    if (!fuzzingSettings || selectionBlocked) return false;
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
    if (!fuzzingSettings || selectionBlocked) return false;
    setSmokeStatus("loading");
    setPromotionStatus("idle");
    setPromotionResult(null);
    setCompiled(false);
    try {
      const result = await getTransport().invoke<SmokeResult>("harness_smoke", {
        project, target: selectedTarget, engine, lang,
      });
      setSmokeResult(result);
      // The smoke step is complete once it has run, whether it passed or
      // surfaced crashes (the latter is handled at the approval step).
      markDone("smoke");
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
    if (!fuzzingSettings || selectionBlocked) return false;
    setPromotionStatus("loading");
    try {
      const result = await getTransport().invoke<PromotionResult>("harness_promote", {
        project, target: selectedTarget, engine,
      });
      setPromotionResult(result);
      const promoted = result.status === "Promoted";
      if (promoted) markDone("approve");
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
    if (!fuzzingSettings || selectionBlocked) return false;
    setPromotionStatus("loading");
    try {
      const result = await getTransport().invoke<PromotionResult>("harness_promote_with_findings", {
        project, target: selectedTarget, engine,
      });
      setPromotionResult(result);
      const promoted = result.status === "Promoted";
      if (promoted) markDone("approve");
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
    if (!fuzzingSettings || selectionBlocked) return;
    setSeedStatus("loading");
    setSeedError(null);
    try {
      const result = await getTransport().invoke<SeedResult>("generate_seeds", { project, target: selectedTarget });
      setSeeds(result.seeds);
      setSeedStatus("done");
      markDone("seeds");
    } catch (e) {
      setSeedError(e instanceof Error ? e.message : String(e));
      setSeedStatus("error");
    }
  }

  async function runAll() {
    if (selectionBlocked || !selectedTarget) return;
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
      <SandboxBanner />
      {!fuzzingSettings && (
        <FuzzingPolicyNotice
          state={fuzzingPolicyLoaded ? "unavailable" : "loading"}
          error={fuzzingPolicyError}
        />
      )}
      {selectionBlocked && (
        <TargetSelectionRepairNotice
          repair={selectionRepair}
          storageError={storageError}
          activeSelectionKey={projectStorageKey(activeProject)}
          engineOptions={engineOptions}
          onSelectEngine={setEngine}
          onSwitchProject={setActiveProject}
          canResetTargetSelections={canResetTargetSelections}
          onResetTargetSelections={resetTargetSelections}
          onRetryStorage={retryStorage}
        />
      )}
      {!embedded && (
        <>
          <ViewHeader
            title={t("title.harness")}
            description={t("harness.description")}
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
          {t("harness.discoveryFailed", { error: discoverError })}
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
              {t("harness.existingHarnessFor")} <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>{existing.target_symbol}</code>
            </span>
            <span
              className="text-xs px-2 py-0.5 rounded-sm"
              style={{ background: "var(--surface-active)", border: "1px solid var(--border)" }}
            >
              {existing.engine} · {existing.status}{existing.smoke_passed ? ` · ${t("harness.smokeOk")}` : ""}
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
            {t("harness.generatedPreviously")}
          </p>
        </div>
      )}

      {/* Target + Engine selection */}
      {inventory && inventory.candidates.length > 0 && (
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex flex-col gap-1 flex-1 min-w-0" style={{ minWidth: 180 }}>
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("harness.target")}</label>
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
                .map((c) => ({ value: c.symbol, label: `${c.symbol} (${t("harness.fit")}: ${c.fit_score.toFixed(2)})` }))}
            />
          </div>
          <div className="flex flex-col gap-1 w-40">
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("harness.engine")}</label>
            <Select
              value={selectionBlocked ? "" : engine}
              onChange={(v) => setEngine(v)}
              options={engineOptions}
            />
          </div>
          <div className="flex flex-col gap-1 w-32">
            <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("harness.language")}</label>
            <Select
              value={lang}
              onChange={(v) => {
                setLang(v);
                if (selectionBlocked) return;
                const supported = fuzzingSettings
                  ? enabledEngineOptions(fuzzingSettings, { language: v })
                  : [];
                if (!supported.some((option) => option.value === engine) && supported[0]) {
                  setEngine(supported[0].value);
                }
              }}
              options={[
                { value: "c", label: "C" },
                { value: "cpp", label: "C++" },
                { value: "rust", label: "Rust" },
                { value: "go", label: "Go" },
                { value: "python", label: "Python" },
              ]}
            />
          </div>
          <Button
            variant="primary"
            onClick={runAll}
            disabled={selectionBlocked || !selectedTarget || engineOptions.length === 0 || harnessStatus === "loading"}
            title={t("harness.buildSmokeTitle")}
          >
            <Sparkles size={14} />
            {t("harness.buildSmokeTest")}
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
            title={t("harness.stepGenerateTitle")}
            errorText={harnessError}
            icon={<FileCode size={16} />}
            status={harnessStatus}
            actionLabel={t("common.generate")}
            actionClick={() => generateHarness(selectedTarget)}
            disabled={selectionBlocked || !fuzzingEnabled}
          >
            {harness && (
              <div className="mt-2">
                {prevSource && (
                  <div className="flex items-center justify-end mb-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setShowDiff((d) => !d)}
                      title={t("harness.diffTitle")}
                    >
                      <GitCompare size={12} />
                      {showDiff ? t("harness.hideDiff") : t("harness.diffVsPrevious")}
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
                  <span>{t("harness.compilerLabel")}: <code style={{ color: "var(--accent)" }}>{harness.build_cmd.compiler}</code></span>
                  <span>{t("harness.flagsLabel")}: <code style={{ color: "var(--text-secondary)" }}>{harness.build_cmd.args.join(" ")}</code></span>
                </div>
              </div>
            )}
          </Step>

          {/* Step 2: Compile */}
          <Step
            number={2}
            prefix={stepPrefix}
            title={t("harness.stepCompileTitle")}
            icon={<Terminal size={16} />}
            status={compileStatus}
            actionLabel={t("harness.compile")}
            actionClick={() => compileHarness()}
            disabled={selectionBlocked || !fuzzingSettings || !harness}
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
            {/* A failed compile is exactly when missing build context matters,
                so the diagnosis appears at the point of failure. */}
            {compileResult && compileResult.status !== "Compiled" && project && (
              <div className="mt-3">
                <BuildDoctorPanel project={project} />
              </div>
            )}
            {/* Evaluating several candidates is a choice about the compile step,
                so it sits alongside it rather than in its own view. */}
            {project && selectedTarget && (
              <div className="mt-3">
                <HarnessTournamentPanel
                  project={project}
                  target={selectedTarget}
                  engine={engine}
                  lang={lang}
                />
              </div>
            )}
            {/* An oracle is an alternative harness for the same target, so it
                belongs with the other harness choices. */}
            {selectedTarget && (
              <div className="mt-3">
                <OracleStudioPanel target={selectedTarget} />
              </div>
            )}
          </Step>

          {/* Step 3: Smoke qualification */}
          <Step
            number={3}
            prefix={stepPrefix}
            title={t("harness.stepSmokeTitle")}
            icon={<Crosshair size={16} />}
            status={smokeStatus}
            actionLabel={t("harness.runSmokeTest")}
            actionClick={smokeHarness}
            disabled={selectionBlocked || !fuzzingSettings || (compileStatus !== "done" && (harness !== null || (existing?.status !== "Compiled" && existing?.status !== "SmokePassed")))}
          >
            {smokeResult && (
              <div className="mt-2 text-xs">
                <div className="flex items-center gap-2">
                  {smokeResult.passed ? (
                    <CheckCircle2 size={14} style={{ color: "var(--success)" }} />
                  ) : (
                    <XCircle size={14} style={{ color: "var(--error)" }} />
                  )}
                  <span style={{ color: smokeResult.passed ? "var(--success)" : "var(--error)" }}>
                    {smokeResult.error
                      ? t("harness.smokeFailed", { error: smokeResult.error })
                      : smokeResult.passed
                      ? t("harness.smokeClean", { rate: Math.round(smokeResult.execs_per_sec).toLocaleString() })
                      : t("harness.smokeCrashes", { n: smokeResult.crashes })}
                  </span>
                </div>
                {/* A "suspect" verdict is the hollow pass: the smoke reported
                    passed=true yet a signal (near-zero execs) says the harness
                    never drove the target. Surface it so a hollow pass is not
                    approved for a full campaign on the strength of the green check. */}
                {smokeResult.verdict?.level === "suspect" && (
                  <div className="mt-1 flex items-start gap-2" style={{ color: "var(--warning)" }}>
                    <AlertTriangle size={14} style={{ marginTop: 1, flexShrink: 0 }} />
                    <span>{smokeResult.verdict.reasons.join("; ")}</span>
                  </div>
                )}
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
            title={t("harness.stepApproveTitle")}
            icon={<CheckCircle2 size={16} />}
            status={promotionStatus}
            actionLabel={smokeCrashed ? t("harness.approveWithFindings") : t("harness.approveForCampaigns")}
            actionClick={smokeCrashed ? promoteWithFindings : promoteHarness}
            disabled={
              selectionBlocked ||
              !fuzzingSettings ||
              promotionStatus === "done" ||
              (smokeCrashed ? false : !cleanApprovable)
            }
          >
            <p className="mt-2 text-xs text-text-secondary">
              {t("harness.approvalBinds")}
            </p>
            {smokeCrashed && promotionStatus !== "done" && (
              <p className="mt-1 text-xs" style={{ color: "var(--warning)" }}>
                {t("harness.approveFindingsNotice", { n: smokeResult?.crashes ?? 0 })}
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
            title={t("harness.stepSeedsTitle")}
            errorText={seedError}
            icon={<Database size={16} />}
            status={seedStatus}
            actionLabel={t("harness.generateSeeds")}
            actionClick={generateSeeds}
            disabled={selectionBlocked || !fuzzingSettings}
          >
            {seeds && (
              <div className="mt-2">
                <div className="text-xs text-text-secondary mb-1">{t("harness.seedsGenerated", { n: seeds.length, target: selectedTarget })}</div>
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
                <span className="text-sm font-medium text-text-primary">{t("harness.readyToFuzz")}</span>
                <p className="text-xs text-text-secondary mt-0.5">
                  {t("harness.readyToFuzzHint", { target: selectedTarget, engine })}
                </p>
              </div>
              <ArrowRight size={16} className="text-text-muted" />
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!inventory && !project && (
        <EmptyState
          icon={<Crosshair size={20} />}
          hint={t("harness.emptyHint")}
        />
      )}
    </div>
  );
}

function Step({
  number, prefix, title, icon, status, actionLabel, actionClick, disabled, errorText, children,
}: {
  number: number; prefix?: string; title: string; icon: React.ReactNode; status: StepStatus;
  actionLabel: string; actionClick: () => void; disabled?: boolean; errorText?: string | null; children?: React.ReactNode;
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
      {errorText && (
        <div className="mt-2 flex items-start gap-2 text-xs">
          <XCircle size={14} style={{ color: "var(--error)", flexShrink: 0, marginTop: 1 }} />
          <span className="font-mono" style={{ color: "var(--error)", wordBreak: "break-word" }}>{errorText}</span>
        </div>
      )}
      {children}
    </div>
  );
}
