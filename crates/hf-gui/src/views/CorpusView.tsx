import { useCallback, useEffect, useRef, useState } from "react";
import { Database, FolderOpen, Plus, Scissors, Sparkles, Sprout } from "lucide-react";
import { CoverageExperimentPanel } from "../components/CoverageExperimentPanel";
import type { ExperimentAdvice } from "../types/coverageExperiments";
import { CoverageBlockerPanel } from "../components/CoverageBlockerPanel";
import { PathActions } from "../components/PathActions";
import { Button, ViewHeader } from "../components/ui";
import { useI18n } from "../i18nContext";
import { getTransport, isTauriEnvironment, onDataChanged, pickFolder } from "../lib";
import { useConfirm } from "../providers/confirm";
import { useProject } from "../providers/project";
import { useTarget } from "../providers/target";
import type { CorpusEntry, ViewType } from "../types";

interface CorpusCapability { available: boolean; reason_code: string | null; reason: string | null }
interface CorpusCapabilities { seed_survival: CorpusCapability; coverage_prune: CorpusCapability; minimize: CorpusCapability }
interface CorpusInventory { inputs: number; bytes: number }
interface CorpusImportOutcome { inspected: number; eligible: number; duplicates: number; skipped: number; added: number; added_bytes: number; before: CorpusInventory; after: CorpusInventory }
interface ReductionOutcome { before: number; after: number; before_bytes: number; after_bytes: number }
interface SurvivalReport { total: number; survives: number; dies_at_entry: number; not_measured: number; survival_ratio: number | null }

export function CorpusView({ embedded = false, onNavigate }: { embedded?: boolean; onNavigate?: (view: ViewType) => void }) {
  const { activeProject } = useProject();
  const { target, lang } = useTarget();
  const project = activeProject || ".";
  return <CorpusWorkspace key={`${project}\u0000${target}`} project={project} target={target} lang={lang || "c"} embedded={embedded} onNavigate={onNavigate} />;
}

function CorpusWorkspace({ project, target, lang, embedded, onNavigate }: { project: string; target: string; lang: string; embedded: boolean; onNavigate?: (view: ViewType) => void }) {
  const { t } = useI18n();
  const [experimentAdvice, setExperimentAdvice] = useState<ExperimentAdvice | null>(null);
  const confirm = useConfirm();
  const desktop = isTauriEnvironment();
  const [entries, setEntries] = useState<CorpusEntry[]>([]);
  const [capabilities, setCapabilities] = useState<CorpusCapabilities | null>(null);
  const [inventoryStatus, setInventoryStatus] = useState<"loading" | "ready" | "unavailable">(target ? "loading" : "unavailable");
  const [capabilityStatus, setCapabilityStatus] = useState<"loading" | "ready" | "unavailable">(target ? "loading" : "unavailable");
  const [loading, setLoading] = useState<string | null>(null);
  const [inventoryError, setInventoryError] = useState<string | null>(null);
  const [capabilityError, setCapabilityError] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [importSource, setImportSource] = useState("");
  const [survival, setSurvival] = useState<SurvivalReport | null>(null);
  const mounted = useRef(true);
  const hasInventory = useRef(false);
  const listGeneration = useRef(0);
  const capabilityGeneration = useRef(0);
  const evidenceGeneration = useRef(0);
  const operationSequence = useRef(0);
  const activeOperation = useRef<number | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      listGeneration.current += 1;
      capabilityGeneration.current += 1;
      activeOperation.current = null;
    };
  }, []);

  const refreshList = useCallback(async () => {
    const generation = ++listGeneration.current;
    await Promise.resolve();
    if (!mounted.current || generation !== listGeneration.current) return false;
    if (!hasInventory.current) setInventoryStatus("loading");
    setInventoryError(null);
    try {
      const result = await getTransport().invoke<CorpusEntry[]>("corpus_list", { project, target });
      if (mounted.current && generation === listGeneration.current) {
        setEntries(result);
        hasInventory.current = true;
        setInventoryStatus("ready");
        setInventoryError(null);
      }
      return true;
    } catch (caught) {
      if (mounted.current && generation === listGeneration.current) {
        setInventoryStatus(hasInventory.current ? "ready" : "unavailable");
        setInventoryError(String(caught));
      }
      return false;
    }
  }, [project, target]);

  const refreshCapabilities = useCallback(async () => {
    const generation = ++capabilityGeneration.current;
    await Promise.resolve();
    if (!mounted.current || generation !== capabilityGeneration.current) return false;
    setCapabilityStatus("loading");
    setCapabilityError(null);
    try {
      const result = await getTransport().invoke<CorpusCapabilities>("corpus_capabilities", { project, target });
      if (mounted.current && generation === capabilityGeneration.current) {
        setCapabilities(result);
        setCapabilityStatus("ready");
        setCapabilityError(null);
      }
      return true;
    } catch (caught) {
      if (mounted.current && generation === capabilityGeneration.current) {
        setCapabilityStatus("unavailable");
        setCapabilityError(String(caught));
      }
      return false;
    }
  }, [project, target]);

  const refreshScope = useCallback(async () => {
    await Promise.all([refreshList(), refreshCapabilities()]);
  }, [refreshCapabilities, refreshList]);

  useEffect(() => {
    if (!target) return;
    const timer = window.setTimeout(() => void refreshScope(), 0);
    return () => window.clearTimeout(timer);
  }, [target, refreshScope]);

  useEffect(() => {
    if (!target) return undefined;
    return onDataChanged(() => {
      evidenceGeneration.current += 1;
      setSurvival(null);
      void refreshScope();
    });
  }, [target, refreshScope]);

  const startOperation = useCallback((operation: string) => {
    if (activeOperation.current !== null) return null;
    const token = ++operationSequence.current;
    activeOperation.current = token;
    setLoading(operation);
    setOperationError(null);
    setNotice(null);
    return token;
  }, []);
  const isCurrent = useCallback((token: number) => mounted.current && activeOperation.current === token, []);
  const finishOperation = useCallback((token: number) => {
    if (!isCurrent(token)) return;
    activeOperation.current = null;
    setLoading(null);
  }, [isCurrent]);

  const runOperation = useCallback(async <T,>({ command, args = {}, confirmation, refresh = false, completed }: {
    command: string;
    args?: Record<string, unknown>;
    confirmation?: { title: string; message: string; label: string };
    refresh?: boolean;
    completed?: (result: T) => void;
  }) => {
    const token = startOperation(command);
    if (token === null) return;
    const measurementGeneration = evidenceGeneration.current;
    try {
      if (confirmation) {
        const approved = await confirm({ title: confirmation.title, message: confirmation.message, confirmLabel: confirmation.label, danger: true });
        if (!isCurrent(token) || !approved) return;
      }
      if (command === "seed_survival") setSurvival(null);
      const result = await getTransport().invoke<T>(command, { project, target, ...args });
      if (!isCurrent(token)) return;
      if (command === "seed_survival" && measurementGeneration !== evidenceGeneration.current) return;
      completed?.(result);
      if (refresh) {
        evidenceGeneration.current += 1;
        setSurvival(null);
        await refreshScope();
      }
    } catch (caught) {
      if (isCurrent(token)) setOperationError(String(caught));
    } finally {
      finishOperation(token);
    }
  }, [confirm, finishOperation, isCurrent, project, refreshScope, startOperation, target]);

  const refreshFromButton = useCallback(async () => {
    const token = startOperation("corpus_list");
    if (token === null) return;
    evidenceGeneration.current += 1;
    setSurvival(null);
    try {
      await refreshScope();
    } finally {
      finishOperation(token);
    }
  }, [finishOperation, refreshScope, startOperation]);

  const generateAi = useCallback(() => {
    void runOperation<{ seeds?: { name: string }[] }>({
      command: "generate_seeds_llm",
      args: { lang, count: 12 },
      refresh: true,
      completed: (result) => setNotice(t("corpus.generatedSeeds", { n: result.seeds?.length ?? 0 })),
    });
  }, [lang, runOperation, t]);
  const chooseImportSource = useCallback(async () => {
    if (!desktop) return;
    const token = startOperation("choose_import_source");
    if (token === null) return;
    try {
      const selected = await pickFolder(t("corpus.chooseDirectory"));
      if (isCurrent(token) && selected) setImportSource(selected);
    } catch (caught) {
      if (isCurrent(token)) setOperationError(String(caught));
    } finally {
      finishOperation(token);
    }
  }, [desktop, finishOperation, isCurrent, startOperation, t]);

  const busy = loading !== null;
  const inputBytes = entries.reduce((sum, entry) => sum + entry.size, 0);
  const survivalCapability = capabilities?.seed_survival;
  const pruneCapability = capabilities?.coverage_prune;
  const minimizeCapability = capabilities?.minimize;
  const capabilityReason = (capability: CorpusCapability | undefined) => capability?.reason ?? (capabilityStatus === "loading" ? t("corpus.capabilitiesLoading") : t("corpus.unavailable"));
  const reductionNotice = (result: ReductionOutcome) => setNotice(t("corpus.reductionResult", { before: result.before, after: result.after, beforeBytes: result.before_bytes, afterBytes: result.after_bytes }));

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      {target && <CoverageBlockerPanel key={`${project}:${target}`} project={project} target={target} lang={lang} onExperimentAdvice={setExperimentAdvice} />}
      {target && <CoverageExperimentPanel project={project} target={target} advice={experimentAdvice} onNavigate={onNavigate} />}
      <div className="flex items-center justify-between gap-3">
        {embedded ? <span /> : <ViewHeader title={t("corpus.title")} description={t("corpus.description")} />}
        <div className="flex flex-wrap justify-end gap-2">
          <ActionButton icon={<Sparkles size={14} />} label={t("corpus.generateWithAi")} loading={loading === "generate_seeds_llm"} disabled={!target || busy} onClick={generateAi} />
          <ActionButton icon={<Plus size={14} />} label={t("corpus.seed")} loading={loading === "corpus_seed"} disabled={!target || busy} onClick={() => void runOperation({ command: "corpus_seed", refresh: true, completed: () => setNotice(t("corpus.seeded")) })} />
          <ActionButton icon={<Sprout size={14} />} label={t("corpus.grow")} loading={loading === "corpus_grow"} disabled={!target || busy} onClick={() => void runOperation({ command: "corpus_grow", refresh: true, completed: () => setNotice(t("corpus.grown")) })} />
          <ActionButton icon={<Database size={14} />} label={t("corpus.list")} loading={loading === "corpus_list"} disabled={!target || busy} onClick={() => void refreshFromButton()} />
        </div>
      </div>

      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
        <div className="text-sm font-medium">{t("corpus.importTitle")}</div>
        <p className="text-xs text-text-muted">{t(desktop ? "corpus.importDesktopHelp" : "corpus.importServerHelp")}</p>
        <div className="flex flex-wrap gap-2">
          <input name="corpus-import-source" className="input flex-1" value={importSource} onChange={(event) => setImportSource(event.target.value)} placeholder={t(desktop ? "corpus.directoryPath" : "corpus.serverDirectoryPath")} />
          {desktop && <ActionButton icon={<FolderOpen size={14} />} label={t("corpus.chooseDirectory")} loading={false} disabled={busy} onClick={() => void chooseImportSource()} />}
          <ActionButton icon={<Plus size={14} />} label={t("corpus.import")} loading={loading === "corpus_import"} disabled={!target || busy || !importSource.trim()} onClick={() => void runOperation<CorpusImportOutcome>({ command: "corpus_import", args: { source: importSource.trim() }, refresh: true, completed: (result) => setNotice(t("corpus.importResult", { added: result.added, bytes: result.added_bytes, duplicates: result.duplicates, skipped: result.skipped })) })} />
        </div>
      </section>

      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
        <div className="text-sm font-medium">{t("corpus.advancedTitle")}</div>
        <p className="text-xs text-text-muted">{t("corpus.advancedHelp")}</p>
        <div className="flex flex-wrap gap-2">
          <ActionButton icon={<Database size={14} />} label={t("corpus.measureSurvival")} loading={loading === "seed_survival"} disabled={!target || busy || capabilityStatus !== "ready" || !survivalCapability?.available} title={capabilityReason(survivalCapability)} onClick={() => void runOperation<SurvivalReport>({ command: "seed_survival", completed: setSurvival })} />
          <ActionButton icon={<Scissors size={14} />} label={t("corpus.pruneBytes")} loading={loading === "corpus_prune"} disabled={!target || busy} onClick={() => void runOperation<ReductionOutcome>({ command: "corpus_prune", refresh: true, confirmation: { title: t("corpus.pruneBytesConfirmTitle"), message: t("corpus.pruneBytesConfirmMessage"), label: t("corpus.pruneBytes") }, completed: reductionNotice })} />
          <ActionButton icon={<Scissors size={14} />} label={t("corpus.pruneCoverage")} loading={loading === "corpus_prune_coverage"} disabled={!target || busy || capabilityStatus !== "ready" || !pruneCapability?.available} title={capabilityReason(pruneCapability)} onClick={() => void runOperation<ReductionOutcome>({ command: "corpus_prune_coverage", refresh: true, confirmation: { title: t("corpus.pruneCoverageConfirmTitle"), message: t("corpus.pruneCoverageConfirmMessage"), label: t("corpus.pruneCoverage") }, completed: reductionNotice })} />
          <ActionButton icon={<Scissors size={14} />} label={t("corpus.minimize")} loading={loading === "corpus_minimize"} disabled={!target || busy || capabilityStatus !== "ready" || !minimizeCapability?.available} title={capabilityReason(minimizeCapability)} onClick={() => void runOperation<ReductionOutcome>({ command: "corpus_minimize", refresh: true, confirmation: { title: t("corpus.minimizeConfirmTitle"), message: t("corpus.minimizeConfirmMessage"), label: t("corpus.minimize") }, completed: reductionNotice })} />
        </div>
        {capabilities && (!survivalCapability?.available || !minimizeCapability?.available) && <div className="text-xs text-text-muted">{!survivalCapability?.available && <p>{t("corpus.aflUnavailable")}: {capabilityReason(survivalCapability)}</p>}{!minimizeCapability?.available && <p>{t("corpus.libFuzzerUnavailable")}: {capabilityReason(minimizeCapability)}</p>}</div>}
        {survival && <div className="text-xs text-text-secondary"><p>{t("corpus.survivalRatio")}: {survival.survival_ratio === null ? t("corpus.unknown") : `${Math.round(survival.survival_ratio * 100)}%`}</p><p>{t("corpus.survives")}: {survival.survives}; {t("corpus.diesAtEntry")}: {survival.dies_at_entry}; {t("corpus.notMeasured")}: {survival.not_measured}</p></div>}
      </section>

      {target && <div className="text-xs text-text-muted">
        {inventoryStatus === "ready" && t("corpus.inventory", { inputs: entries.length, bytes: inputBytes })}
        {inventoryStatus === "loading" && t("corpus.inventoryLoading")}
        {inventoryStatus === "unavailable" && t("corpus.inventoryUnavailable")}
      </div>}
      {[inventoryError, capabilityError, operationError].filter((message): message is string => Boolean(message)).map((message) => <div key={message} className="surface-card text-xs" style={{ padding: "var(--space-sm) var(--space-md)", color: "var(--danger, #e5484d)", borderColor: "var(--danger, #e5484d)" }}>{message}</div>)}
      {notice && !inventoryError && !capabilityError && !operationError && <div className="text-xs text-text-muted" style={{ paddingLeft: "2px" }}>{notice}</div>}
      {!target && <div className="surface-card flex flex-col items-center justify-center" style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}><Database size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} /><p className="text-sm text-text-muted">{t("corpus.noTargetSelected")}</p><p className="text-xs text-text-muted mt-1">{t("corpus.noTargetHint")}</p></div>}
      {target && inventoryStatus === "ready" && entries.length === 0 && !busy && <div className="surface-card flex flex-col items-center justify-center" style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}><Database size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} /><p className="text-sm text-text-muted">{t("corpus.emptyForBefore")}<span style={{ fontFamily: "var(--font-mono)" }}>{target}</span>{t("corpus.emptyForAfter")}</p><p className="text-xs text-text-muted mt-1">{t("corpus.emptyHint")}</p></div>}
      {entries.length > 0 && <div className="surface-card overflow-x-auto" style={{ animation: "slideInUp 0.2s ease" }}><table className="w-full text-sm" style={{ minWidth: 480 }}><thead><tr className="border-b border-border"><th className="text-left text-xs text-text-muted uppercase px-3 py-2">{t("corpus.colFile")}</th><th className="text-left text-xs text-text-muted uppercase px-3 py-2">SHA256</th><th className="text-left text-xs text-text-muted uppercase px-3 py-2">{t("corpus.colSource")}</th><th className="text-right text-xs text-text-muted uppercase px-3 py-2">{t("corpus.colSize")}</th><th className="px-3 py-2" /></tr></thead><tbody>{entries.map((entry) => <tr key={entry.path} className="border-b border-border"><td className="px-3 py-2 font-mono text-xs text-text-primary">{entry.path.split("/").pop()}</td><td className="px-3 py-2 font-mono text-xs text-text-muted">{entry.sha256.slice(0, 16)}...</td><td className="px-3 py-2 text-xs text-text-secondary">{entry.source}</td><td className="px-3 py-2 text-right text-xs text-text-secondary">{entry.size}b</td><td className="px-3 py-2 text-right"><PathActions path={entry.path} /></td></tr>)}</tbody></table></div>}
    </div>
  );
}

function ActionButton({ icon, label, loading, disabled, title, onClick }: { icon: React.ReactNode; label: string; loading: boolean; disabled?: boolean; title?: string; onClick: () => void }) {
  return <Button variant="outline" size="sm" onClick={onClick} loading={loading} disabled={disabled} title={title}>{!loading && icon}{label}</Button>;
}
