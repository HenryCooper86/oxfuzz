import { useState, useEffect, useRef } from "react";
import { useI18n } from "../i18nContext";
import { pickFolder, pickFile, getTransport } from "../lib";
import { useProject } from "../providers/project";
import { usePipeline } from "../providers/pipeline";
import { usePrefs } from "../providers/prefs";
import { useRunOutput } from "../providers/runOutput";
import { useTarget } from "../providers/target";
import { Button, Input, Select, ViewHeader } from "../components/ui";
import { SandboxBanner } from "../components/SandboxBanner";
import { Play, Activity, AlertTriangle, FolderOpen, Square, RotateCw, RotateCcw } from "lucide-react";
import type { HarnessReviewItem, ViewType } from "../types";
import { useFuzzingSettings } from "../hooks/useFuzzingSettings";
import { enabledEngineOptions } from "../lib/fuzzingSettings";
import { FuzzingPolicyNotice } from "../components/FuzzingPolicyNotice";
import { TargetSelectionRepairNotice } from "../components/TargetSelectionRepairNotice";

export function RunView({
  embedded = false,
  onNavigate,
}: {
  embedded?: boolean;
  onNavigate?: (view: ViewType) => void;
}) {
  const { t } = useI18n();
  const { activeProject, setActiveProject } = useProject();
  const { markDone, markSkipped } = usePipeline();
  const { sandboxArch } = usePrefs();
  const {
    target,
    setTarget,
    engine: selectedEngine,
    setEngine,
    compiled,
    selectionRepair,
    storageError,
  } = useTarget();
  // Run output (log/stats/summary/running) lives in a shared, always-mounted
  // context, so a run keeps streaming and is preserved when you navigate away.
  const { log, stats: liveStats, summary, running, cancelling, runFuzzer, runSyzkaller, cancelRun } = useRunOutput();
  const { settings: fuzzingSettings, loaded: fuzzingPolicyLoaded, error: fuzzingPolicyError } = useFuzzingSettings();
  // Embedded in the workflow, the project comes from the workflow's gate.
  const [localProject, setLocalProject] = useState(activeProject);
  const project = embedded ? activeProject : localProject;
  const [durationOverride, setDurationOverride] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const engineOptions = fuzzingSettings
    ? enabledEngineOptions(fuzzingSettings, { includeSyzkaller: true })
    : [];
  const selectionBlocked = selectionRepair !== null || storageError !== null;
  const engine = selectionBlocked
    ? selectedEngine
    : engineOptions.some((option) => option.value === selectedEngine)
      ? selectedEngine
      : (engineOptions.find((option) => option.value === fuzzingSettings?.default_engine)
        ?? engineOptions[0])?.value ?? selectedEngine;
  const duration = durationOverride ?? (fuzzingSettings ? String(fuzzingSettings.default_duration_secs) : "");

  // Suggest the project's harnessed targets so the standalone Run view isn't a
  // blank free-text field (you can only fuzz a target that has a harness).
  const [targetSuggestions, setTargetSuggestions] = useState<string[]>([]);
  useEffect(() => {
    let cancelled = false;
    // Resolve to [] when there's no project instead of setting state
    // synchronously in the effect body (which would cascade renders).
    const load = project && !selectionBlocked
      ? getTransport().invoke<HarnessReviewItem[]>("harness_review_queue", { project })
      : Promise.resolve<HarnessReviewItem[]>([]);
    load
      .then((items) => {
        if (!cancelled) setTargetSuggestions([...new Set(items.map((i) => i.target_symbol))].sort());
      })
      .catch(() => {
        if (!cancelled) setTargetSuggestions([]);
      });
    return () => {
      cancelled = true;
    };
  }, [project, selectionBlocked]);

  // syzkaller (kernel fuzzing) campaign artifacts.
  const [kernelImage, setKernelImage] = useState("");
  const [diskImage, setDiskImage] = useState("");
  const [sshKey, setSshKey] = useState("");
  const [managerCfg, setManagerCfg] = useState("");
  const [vmCount, setVmCount] = useState("2");

  const isSyz = engine === "syzkaller";

  // Target and engine are sourced directly from the shared validated context,
  // so Harness and Run cannot disagree about a persisted repair state.

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
  const [harnessApproved, setHarnessApproved] = useState(compiled);
  useEffect(() => {
    // syzkaller has no harness binary; the badge is hidden for it anyway.
    if (selectionBlocked || isSyz) return;
    let cancelled = false;
    Promise.all([
      getTransport().invoke<{ harness_built: boolean }>("artifact_summary", { project: project ?? "", target: target ?? "" }),
      getTransport().invoke<HarnessReviewItem[]>("harness_review_queue", { project: project ?? "", target: target ?? "" }),
    ])
      .then(([artifacts, harnesses]) => {
        if (!cancelled) {
          setHarnessBuilt(Boolean(artifacts.harness_built));
          setHarnessApproved(harnesses.some((item) =>
            item.target_symbol === target
            && item.status === "Promoted"
            && normalizeEngine(item.engine) === normalizeEngine(engine),
          ));
        }
      })
      .catch(() => {
        if (!cancelled) {
          setHarnessBuilt(false);
          setHarnessApproved(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [project, target, engine, isSyz, selectionBlocked, summary]);

  async function browse() {
    const path = await pickFolder();
    if (path) {
      setLocalProject(path);
      setActiveProject(path); // persist immediately so it survives navigation
    }
  }

  async function run() {
    if (selectionBlocked) return;
    const policy = fuzzingSettings;
    if (!policy) return;
    if (!project) return;
    // Non-kernel engines require a target symbol.
    if (!isSyz && !target) return;
    setActiveProject(project);
    try {
      const crashes = isSyz
        ? await runSyzkaller({
            project,
            arch: sandboxArch,
            duration: Math.max(
              1,
              Math.floor(Number(duration) || policy.default_duration_secs),
            ),
            kernel_image: kernelImage || null,
            disk_image: diskImage || null,
            ssh_key: sshKey || null,
            manager_cfg: managerCfg || null,
            vm_count: Number(vmCount) || 2,
          })
        : await runFuzzer({
            project,
            target,
            engine,
            duration: Math.max(
              1,
              Math.floor(Number(duration) || policy.default_duration_secs),
            ),
          });
      markDone("run");
      // If the run found no crashes, there is nothing to triage.
      if (crashes === 0) markSkipped("triage");
    } catch {
      // The error is already surfaced in the run output log.
      // `activeEngine` is cleared centrally in RunOutputContext's run paths.
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      {!embedded && (
        <ViewHeader
          title={t("title.run")}
          description={isSyz ? t("run.descSyz") : t("run.descStd")}
        />
      )}

      {!isSyz && <SandboxBanner />}

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
          engineOptions={engineOptions}
          onSelectEngine={setEngine}
        />
      )}

      <div className="grid grid-cols-2 gap-3">
        {!embedded && (
          <div className="flex flex-col gap-1">
            <Label>{t("run.project")}</Label>
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
                title={t("run.browseFolder")}
              >
                <FolderOpen size={14} />
              </Button>
            </div>
          </div>
        )}
        {!isSyz && (
          <div className="flex flex-col gap-1">
            <Label>
              {t("run.targetSymbol")}
              {harnessApproved && harnessBuilt ? (
                <span style={{ color: "var(--success)", marginLeft: "8px" }}>{t("run.approved")}</span>
              ) : harnessBuilt ? (
                <span style={{ color: "var(--warning)", marginLeft: "8px" }}>{t("run.approvalRequired")}</span>
              ) : (
                target && <span style={{ color: "var(--text-muted)", marginLeft: "8px" }}>{t("run.notBuilt")}</span>
              )}
            </Label>
            <Input
              mono
              type="text"
              list="run-target-suggestions"
              placeholder={targetSuggestions[0] ?? "parse_value"}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            <datalist id="run-target-suggestions">
              {targetSuggestions.map((s) => (
                <option key={s} value={s} />
              ))}
            </datalist>
          </div>
        )}
        <div className="flex flex-col gap-1">
          <Label>{t("run.engine")}</Label>
          <Select
            value={selectionBlocked ? "" : engine}
            onChange={setEngine}
            options={engineOptions}
          />
        </div>
        <div className="flex flex-col gap-1">
          <Label>{t("run.duration")}</Label>
          <Input
            type="number"
            min={1}
            max={fuzzingSettings?.sandbox.max_duration_secs}
            value={duration}
            onChange={(e) => setDurationOverride(e.target.value)}
          />
        </div>
      </div>

      {isSyz && (
        <div
          className="surface-card flex flex-col gap-3"
          style={{ padding: "var(--space-md)", animation: "slideInUp 0.2s ease" }}
        >
          <div className="flex flex-col gap-1">
            <span className="text-xs font-semibold text-text-primary">{t("run.kernelArtifacts")}</span>
            <span className="text-xs text-text-muted">
              {t("run.kernelArtifactsHint")}
            </span>
          </div>
          <FileField label={t("run.kernelImage")} placeholder="/path/to/bzImage" value={kernelImage}
            onChange={setKernelImage} onPick={() => pickFile(t("run.selectKernelImage")).then((p) => p && setKernelImage(p))} />
          <FileField label={t("run.rootfsImage")} placeholder="/path/to/rootfs.img" value={diskImage}
            onChange={setDiskImage} onPick={() => pickFile(t("run.selectRootfsImage")).then((p) => p && setDiskImage(p))} />
          <FileField label={t("run.sshKey")} placeholder="/path/to/id_rsa" value={sshKey}
            onChange={setSshKey} onPick={() => pickFile(t("run.selectSshKey")).then((p) => p && setSshKey(p))} />
          <FileField label={t("run.managerCfg")} placeholder="/path/to/manager.cfg" value={managerCfg}
            onChange={setManagerCfg} onPick={() => pickFile(t("run.selectManagerCfg")).then((p) => p && setManagerCfg(p))} />
          <div className="flex flex-col gap-1" style={{ maxWidth: "160px" }}>
            <Label>{t("run.vmCount")}</Label>
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
          disabled={selectionBlocked || !fuzzingSettings || running || !project || (!isSyz && (!target || !harnessBuilt || !harnessApproved))}
          loading={running}
        >
          {!running && <Play size={14} />}
          {running ? t("run.running") : isSyz ? t("run.launchCampaign") : t("run.runFuzzer")}
        </Button>

        {/* Stop is offered for any in-flight run. Web mode cancels the exact
            service-owned run id; desktop mode signals its active local run. */}
        {running && (
          <Button
            variant="danger"
            className="self-start"
            onClick={() => void cancelRun()}
            loading={cancelling}
            title={t("run.cancelTitle")}
          >
            {!cancelling && <Square size={14} />}
            {cancelling ? t("run.stopping") : t("common.stop")}
          </Button>
        )}
      </div>

      {/* No target for this project yet (e.g. opened Run straight from Projects):
          the run button is disabled, so point the user at where to get one. */}
      {!isSyz && !target && project && !running && (
        <div className="surface-card text-sm" style={{ padding: "var(--space-md)", borderLeft: "3px solid var(--warning, #d9a441)" }}>
          {t("run.noTargetSelected")}
          {onNavigate ? (
            <>
              {" "}
              <button
                onClick={() => onNavigate("harness")}
                className="underline"
                style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", padding: 0 }}
              >
                {t("run.discoverFirst")}
              </button>
              .
            </>
          ) : (
            <>{" "}{t("run.discoverFirstHint")}</>
          )}
        </div>
      )}

      {!isSyz && target && project && !running && (!harnessBuilt || !harnessApproved) && (
        <div className="surface-card text-sm" style={{ padding: "var(--space-md)", borderLeft: "3px solid var(--warning, #d9a441)" }}>
          {!harnessBuilt
            ? t("run.harnessMissing")
            : t("run.harnessNotApproved")}
          {onNavigate ? (
            <>
              {" "}
              <button
                onClick={() => onNavigate("harness")}
                className="underline"
                style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", padding: 0 }}
              >
                {t("run.openHarnessQual")}
              </button>
              .
            </>
          ) : (
            <>{" "}{t("run.openHarnessHint")}</>
          )}
        </div>
      )}

      {/* Live stats while fuzzing (updates in place from streamed events). */}
      {running && !isSyz && (
        <div className="grid grid-cols-3 gap-3" style={{ animation: "slideInUp 0.2s ease" }}>
          <StatCard icon={<Activity size={16} />} label={t("run.edgesCovered")} value={liveStats.edges} color="var(--success)" />
          <StatCard icon={<AlertTriangle size={16} />} label={t("run.crashes")} value={liveStats.crashes} color="var(--error)" />
          <StatCard icon={<Play size={16} />} label={t("run.execsPeak")} value={liveStats.execs} color="var(--accent)" />
        </div>
      )}

      {summary && !running && (
        <div className="grid grid-cols-3 gap-3" style={{ animation: "slideInUp 0.2s ease" }}>
          <StatCard icon={<Activity size={16} />} label={isSyz ? t("run.coverage") : t("run.edgesCovered")} value={summary.edges} color="var(--success)" />
          <StatCard icon={<AlertTriangle size={16} />} label={t("run.crashes")} value={summary.crashes} color="var(--error)" />
          <StatCard icon={<Play size={16} />} label={isSyz ? t("run.executed") : t("run.execsPerSec")} value={summary.execs} color="var(--accent)" />
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
              {t("run.coverageStalled")}
            </div>
            <div className="text-xs text-text-secondary" style={{ lineHeight: 1.5 }}>
              {t(stagnationHint(summary.stagnation))}
            </div>
          </div>
          {summary.stagnation === "new_harness" && onNavigate && (
            <Button variant="outline" size="sm" onClick={() => onNavigate("harness")}>
              <RotateCw size={14} /> {t("run.regenerateHarness")}
            </Button>
          )}
        </div>
      )}

      {summary && !running && summary.autoRevert && (
        <div
          className="surface-card flex items-center gap-3"
          style={{
            padding: "var(--space-md)",
            borderLeft: `3px solid ${summary.autoRevert.reverted ? "var(--accent)" : "var(--warning, var(--accent))"}`,
            animation: "slideInUp 0.2s ease",
          }}
        >
          {summary.autoRevert.reverted ? (
            <RotateCcw size={18} style={{ color: "var(--accent)", flexShrink: 0 }} />
          ) : (
            <AlertTriangle size={18} style={{ color: "var(--warning, var(--accent))", flexShrink: 0 }} />
          )}
          <div className="flex-1">
            <div className="text-sm" style={{ fontWeight: 600 }}>
              {summary.autoRevert.reverted ? t("run.autoReverted") : t("run.coverageRegression")}
            </div>
            <div className="text-xs text-text-secondary" style={{ lineHeight: 1.5 }}>
              {t("run.autoRevertDrop", {
                pct: summary.autoRevert.drop_pct.toFixed(1),
                regressed: summary.autoRevert.regressed_edges,
                previous: summary.autoRevert.previous_edges,
              })}
              {" "}
              {summary.autoRevert.reverted ? (
                <>
                  {t("run.autoRevertRestoredPre")}
                  <code>{summary.autoRevert.to_rev.slice(0, 8)}</code>
                  {t("run.autoRevertRestoredPost")}
                </>
              ) : (
                <>
                  {t("run.autoRevertNotifyPre")}
                  <code>{summary.autoRevert.to_rev.slice(0, 8)}</code>
                  {t("run.autoRevertNotifyMid")}
                  <strong>{t("run.notEmphasis")}</strong>
                  {t("run.autoRevertNotifyPost")}
                </>
              )}
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

function normalizeEngine(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Translation key for the user-facing guidance on a backend
 *  coverage-stagnation proposal. */
function stagnationHint(proposal: string): string {
  switch (proposal) {
    case "new_harness":
      return "run.stallNewHarness";
    case "custom_mutator":
      return "run.stallCustomMutator";
    case "stop":
      return "run.stallStop";
    default:
      return "run.stallDefault";
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
  const { t } = useI18n();
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
          title={t("run.browseFile")}
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
