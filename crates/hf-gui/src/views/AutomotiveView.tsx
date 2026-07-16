import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  CarFront,
  FileText,
  FileSearch,
  History,
  RefreshCw,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { useI18n } from "../i18nContext";
import { emitDataChanged, getTransport, isTauriEnvironment, pickFile } from "../lib";
import {
  analyzeAutomotiveCapture,
  generateAutomotiveReport,
  getAutomotiveSettings,
  inspectAutomotiveCapabilities,
  listAutomotiveOperations,
  type AutomotiveCapabilitiesResult,
  type AutomotiveCaptureAnalysisResult,
  type AutomotiveCampaignReport,
  type AutomotiveOperationOutcome,
  type AutomotiveOperationSummary,
  type AutomotiveProtocol,
  type AutomotiveSettings,
} from "../lib/automotive";
import { AUTOMOTIVE_PROTOCOL_OPTIONS } from "../lib/automotiveSettings";
import { useProject } from "../providers/project";
import { useToast } from "../components/ui/toastContext";
import { AutomotiveReplayWorkspace } from "../components/AutomotiveReplayWorkspace";
import {
  Badge,
  Button,
  EmptyState,
  LoadingState,
  Select,
  ViewHeader,
} from "../components/ui";

const ReportPreview = lazy(() =>
  import("../components/ReportPreview").then((module) => ({ default: module.ReportPreview })),
);

function displayPathName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

function displayTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString();
}

function statusVariant(
  status: AutomotiveOperationSummary["status"],
): "default" | "success" | "error" | "warning" {
  if (status === "done") return "success";
  if (status === "failed") return "error";
  if (status === "running") return "warning";
  return "default";
}

export function AutomotiveView() {
  const { t } = useI18n();
  const { activeProject } = useProject();
  const { toast } = useToast();
  const desktop = isTauriEnvironment();
  const [settings, setSettings] = useState<AutomotiveSettings | null>(null);
  const [operations, setOperations] = useState<AutomotiveOperationSummary[]>([]);
  const [capabilityOutcome, setCapabilityOutcome] = useState<
    AutomotiveOperationOutcome<AutomotiveCapabilitiesResult> | null
  >(null);
  const [analysisOutcome, setAnalysisOutcome] = useState<
    AutomotiveOperationOutcome<AutomotiveCaptureAnalysisResult> | null
  >(null);
  const [capturePath, setCapturePath] = useState("");
  const [protocol, setProtocol] = useState<AutomotiveProtocol>("can");
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [loadingOperations, setLoadingOperations] = useState(false);
  const [busy, setBusy] = useState<"capabilities" | "analysis" | null>(null);
  const [reporting, setReporting] = useState<"deterministic" | "ai" | null>(null);
  const [report, setReport] = useState<AutomotiveCampaignReport | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [reportFormats, setReportFormats] = useState<string[]>(["md", "html"]);
  const [error, setError] = useState<string | null>(null);
  const operationsRequestRef = useRef(0);
  const operationsProjectRef = useRef("");

  const refreshOperations = useCallback(async () => {
    const requestId = ++operationsRequestRef.current;
    if (!activeProject) {
      operationsProjectRef.current = "";
      setOperations([]);
      setLoadingOperations(false);
      return;
    }
    if (operationsProjectRef.current !== activeProject) {
      operationsProjectRef.current = activeProject;
      setOperations([]);
    }
    setLoadingOperations(true);
    try {
      const next = await listAutomotiveOperations(activeProject, 50);
      if (operationsRequestRef.current === requestId) setOperations(next);
    } catch (reason) {
      if (operationsRequestRef.current === requestId) setError(String(reason));
    } finally {
      if (operationsRequestRef.current === requestId) setLoadingOperations(false);
    }
  }, [activeProject]);

  useEffect(() => {
    let active = true;
    queueMicrotask(async () => {
      setLoadingSettings(true);
      setError(null);
      try {
        const next = await getAutomotiveSettings();
        if (!active) return;
        setSettings(next);
        setProtocol((current) => next.allowed_protocols.includes(current)
          ? current
          : next.allowed_protocols[0]);
      } catch (reason) {
        if (active) setError(String(reason));
      } finally {
        if (active) setLoadingSettings(false);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    getTransport()
      .invoke<string[]>("report_formats")
      .then(setReportFormats)
      .catch(() => setReportFormats(["md", "html"]));
  }, []);

  useEffect(() => {
    queueMicrotask(() => void refreshOperations());
    return () => {
      operationsRequestRef.current += 1;
    };
  }, [refreshOperations]);

  useEffect(() => {
    queueMicrotask(() => {
      setCapabilityOutcome(null);
      setAnalysisOutcome(null);
      setCapturePath("");
      setReport(null);
      setPreviewOpen(false);
    });
  }, [activeProject]);

  async function selectCapture() {
    if (!desktop) return;
    const selected = await pickFile(t("automotive.capturePickerTitle"));
    if (selected) {
      setCapturePath(selected);
      setAnalysisOutcome(null);
    }
  }

  async function inspectCapabilities() {
    if (!activeProject || !settings?.enabled || busy) return;
    setBusy("capabilities");
    setError(null);
    try {
      const outcome = await inspectAutomotiveCapabilities(activeProject);
      setCapabilityOutcome(outcome);
      toast({
        title: t("automotive.capabilitiesLoaded"),
        description: t("automotive.evidenceRetained", { path: outcome.artifact_dir }),
        variant: "success",
      });
      await refreshOperations();
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({
        title: t("automotive.capabilitiesFailed"),
        description: message,
        variant: "error",
      });
    } finally {
      setBusy(null);
    }
  }

  async function analyzeCapture() {
    if (
      !desktop
      || !activeProject
      || !capturePath
      || !settings?.enabled
      || !settings.allowed_modes.includes("offline_pcap")
      || busy
    ) return;
    setBusy("analysis");
    setError(null);
    try {
      const outcome = await analyzeAutomotiveCapture({
        projectRoot: activeProject,
        protocol,
        capturePath,
      });
      setAnalysisOutcome(outcome);
      toast({
        title: t("automotive.analysisComplete"),
        description: t("automotive.evidenceRetained", { path: outcome.artifact_dir }),
        variant: "success",
      });
      await refreshOperations();
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({
        title: t("automotive.analysisFailed"),
        description: message,
        variant: "error",
      });
    } finally {
      setBusy(null);
    }
  }

  async function composeReport(includeAi: boolean) {
    if (!activeProject || reporting) return;
    setReporting(includeAi ? "ai" : "deterministic");
    setError(null);
    try {
      const next = await generateAutomotiveReport(activeProject, includeAi);
      setReport(next);
      setPreviewOpen(true);
      try {
        await getTransport().invoke("save_report_draft", {
          title: `Automotive campaign report — ${next.project_name}`,
          project: activeProject,
          target: null,
          status: "Draft",
          content: next.markdown,
        });
        emitDataChanged();
      } catch (reason) {
        setError(t("automotive.report.draftFailed", { error: String(reason) }));
      }
      toast({
        title: t("automotive.report.composed"),
        description: next.ai_status === "applied"
          ? t("automotive.report.aiApplied")
          : t("automotive.report.deterministic"),
        variant: "success",
      });
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({
        title: t("automotive.report.failed"),
        description: message,
        variant: "error",
      });
    } finally {
      setReporting(null);
    }
  }

  async function exportReport(format: string) {
    if (!report) return;
    try {
      if (desktop) {
        const saved = await getTransport().invoke<string | null>("export_markdown", {
          content: report.markdown,
          title: `Automotive campaign report — ${report.project_name}`,
          format,
        });
        if (saved) {
          toast({
            title: t("automotive.report.exported"),
            description: saved,
            variant: "success",
          });
        }
      } else if (format === "md") {
        const blob = new Blob([report.markdown], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = `automotive_campaign_${report.project_name.replace(/[^a-zA-Z0-9_-]/g, "_")}.md`;
        anchor.click();
        URL.revokeObjectURL(url);
      } else {
        toast({
          title: t("automotive.report.exportUnavailable"),
          description: t("automotive.report.exportDesktopOnly", { format: format.toUpperCase() }),
          variant: "default",
        });
      }
    } catch (reason) {
      toast({
        title: t("automotive.report.exportFailed"),
        description: String(reason),
        variant: "error",
      });
    }
  }

  if (loadingSettings) return <LoadingState label={t("automotive.loadingPolicy")} />;

  if (!activeProject) {
    return (
      <EmptyState
        icon={<CarFront size={24} />}
        title={t("automotive.noProject")}
        hint={t("automotive.noProjectHint")}
      />
    );
  }

  const capabilities = capabilityOutcome?.result.data;
  const analysis = analysisOutcome?.result.data;
  const offlineAllowed = settings?.allowed_modes.includes("offline_pcap") ?? false;
  const virtualConfigured = Boolean(
    settings?.enabled
      && settings.allowed_modes.includes("virtual_can")
      && settings.virtual_interfaces.length > 0,
  );
  const physicalConfigured = Boolean(
    settings?.enabled
      && settings.allowed_modes.includes("physical_bench")
      && settings.physical_bench.enabled
      && settings.physical_bench.interfaces.length > 0,
  );

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <ViewHeader
          title={t("automotive.title")}
          description={t("automotive.description")}
        />
        <Button
          variant="outline"
          size="sm"
          loading={loadingOperations}
          onClick={() => void refreshOperations()}
        >
          {!loadingOperations && <RefreshCw size={13} />}
          {t("automotive.refreshHistory")}
        </Button>
      </div>

      {!settings?.enabled && (
        <div
          role="alert"
          className="surface-card flex items-start gap-3 text-12px text-text-secondary"
          style={{ padding: "var(--space-md)", borderColor: "var(--warning)" }}
        >
          <ShieldAlert size={18} className="shrink-0 text-warning" />
          <div>
            <div className="font-semibold text-text-primary">
              {t("automotive.disabledTitle")}
            </div>
            <div>{t("automotive.disabledHint")}</div>
          </div>
        </div>
      )}

      {!desktop && (
        <div
          role="note"
          className="surface-card flex items-start gap-3 text-12px text-text-secondary"
          style={{ padding: "var(--space-md)" }}
        >
          <FileSearch size={18} className="shrink-0 text-text-muted" />
          <span>{t("automotive.desktopCaptureOnly")}</span>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="surface-card text-12px text-error"
          style={{ padding: "var(--space-sm) var(--space-md)", borderColor: "var(--error)" }}
        >
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
          <div className="flex items-center gap-2">
            <FileSearch size={17} className="text-accent" />
            <h2 className="text-sm font-semibold">{t("automotive.offlineAnalysis")}</h2>
            <Badge variant="success">{t("automotive.noLiveTraffic")}</Badge>
          </div>
          <p className="text-12px text-text-secondary">
            {t("automotive.offlineAnalysisDesc")}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Select
              value={protocol}
              onChange={(next) => setProtocol(next as AutomotiveProtocol)}
              options={AUTOMOTIVE_PROTOCOL_OPTIONS.filter((option) =>
                settings?.allowed_protocols.includes(option.value) ?? false,
              )}
              className="min-w-32"
            />
            <Button
              variant="outline"
              onClick={() => void selectCapture()}
              disabled={!desktop || !settings?.enabled || !offlineAllowed}
            >
              <Upload size={14} />
              {capturePath ? t("automotive.replaceCapture") : t("automotive.selectCapture")}
            </Button>
            <Button
              variant="primary"
              loading={busy === "analysis"}
              disabled={
                !desktop
                || !capturePath
                || !settings?.enabled
                || !offlineAllowed
                || busy !== null
              }
              onClick={() => void analyzeCapture()}
            >
              {t("automotive.analyzeCapture")}
            </Button>
          </div>
          {capturePath && (
            <div className="rounded-md bg-surface-primary px-3 py-2 text-12px font-mono text-text-secondary">
              <span title={capturePath}>{displayPathName(capturePath)}</span>
            </div>
          )}
          {analysis && (
            <div className="rounded-md border border-border bg-surface-primary p-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="success">{analysis.protocol}</Badge>
                <span className="text-12px text-text-secondary">
                  {t("automotive.eventsDecoded", { count: analysis.event_count })}
                </span>
                <span className="text-12px text-text-secondary">
                  {t("automotive.statesObserved", { count: analysis.state_signatures.length })}
                </span>
              </div>
              <div className="mt-2 break-all text-11px font-mono text-text-muted">
                {analysis.transcript_hash}
              </div>
              {analysis.state_signatures.length > 0 && (
                <div className="mt-3 flex flex-col gap-2">
                  {analysis.state_signatures.map((signature) => (
                    <div key={signature.digest} className="rounded border border-border px-2 py-1.5">
                      <div className="text-11px font-mono text-text-primary">
                        {signature.protocol} · {signature.digest.slice(0, 16)}
                      </div>
                      <div className="text-11px text-text-muted">
                        {Object.entries(signature.observations)
                          .map(([key, observed]) => `${key}=${observed}`)
                          .join(", ") || t("automotive.noStateMetadata")}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>

        <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Activity size={17} className="text-accent" />
              <h2 className="text-sm font-semibold">{t("automotive.capabilities")}</h2>
            </div>
            <Button
              variant="outline"
              size="sm"
              loading={busy === "capabilities"}
              disabled={!settings?.enabled || busy !== null}
              onClick={() => void inspectCapabilities()}
            >
              {t("automotive.inspectCapabilities")}
            </Button>
          </div>
          <p className="text-12px text-text-secondary">
            {t("automotive.capabilitiesDesc")}
          </p>
          {!capabilities ? (
            <div className="rounded-md border border-dashed border-border px-3 py-6 text-center text-12px text-text-muted">
              {t("automotive.capabilitiesEmpty")}
            </div>
          ) : (
            <div className="flex flex-col gap-3 rounded-md border border-border bg-surface-primary p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold">{capabilities.adapter_name}</span>
                <Badge variant="accent">{capabilities.adapter_version}</Badge>
                <span className="text-11px text-text-muted">
                  {t("automotive.schemas", { versions: capabilities.schema_versions.join(", ") })}
                </span>
              </div>
              <div>
                <div className="mb-1 text-11px font-semibold uppercase text-text-muted">
                  {t("automotive.advertisedCapabilities")}
                </div>
                <div className="flex flex-wrap gap-1">
                  {capabilities.capabilities.map((capability) => (
                    <Badge key={capability}>{capability}</Badge>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 text-11px text-text-secondary">
                <span>{t("automotive.protocolCount", { count: capabilities.protocols.length })}</span>
                <span>{t("automotive.modeCount", { count: capabilities.modes.length })}</span>
                <span>{t("automotive.eventLimit", { count: capabilities.limits.max_events })}</span>
                <span>{t("automotive.rateLimit", { count: capabilities.limits.max_rate_per_second })}</span>
              </div>
            </div>
          )}
        </section>
      </div>

      {settings && (
        <AutomotiveReplayWorkspace
          key={activeProject}
          projectRoot={activeProject}
          protocol={protocol}
          settings={settings}
          onOperation={refreshOperations}
        />
      )}

      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <FileText size={18} className="mt-0.5 shrink-0 text-accent" />
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-semibold">{t("automotive.report.title")}</h2>
                <Badge variant="accent">{t("automotive.report.evidenceBacked")}</Badge>
                {report?.ai_status === "applied" && (
                  <Badge variant="success">{t("automotive.report.aiApplied")}</Badge>
                )}
                {report?.ai_status === "fallback" && (
                  <Badge variant="warning">{t("automotive.report.aiFallback")}</Badge>
                )}
                {report && report.ai_status !== "applied" && report.ai_status !== "fallback" && (
                  <Badge>{t("automotive.report.deterministicLabel")}</Badge>
                )}
              </div>
              <p className="mt-1 max-w-3xl text-12px text-text-secondary">
                {t("automotive.report.description")}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {report && (
              <Button variant="ghost" onClick={() => setPreviewOpen(true)}>
                {t("automotive.report.preview")}
              </Button>
            )}
            <Button
              variant="outline"
              loading={reporting === "deterministic"}
              disabled={reporting !== null}
              onClick={() => void composeReport(false)}
            >
              {t("automotive.report.compose")}
            </Button>
            <Button
              variant="primary"
              loading={reporting === "ai"}
              disabled={reporting !== null || operations.length === 0}
              onClick={() => void composeReport(true)}
            >
              {t("automotive.report.composeAi")}
            </Button>
          </div>
        </div>
        {report && (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              [t("automotive.report.operations"), report.operation_count],
              [t("automotive.report.failures"), report.failed_operation_count],
              [t("automotive.report.states"), report.unique_state_count],
              [t("automotive.report.promoted"), report.promoted_state_count],
            ].map(([label, value]) => (
              <div key={String(label)} className="rounded-md border border-border bg-surface-primary p-3">
                <div className="text-lg font-semibold text-text-primary">{value}</div>
                <div className="text-11px text-text-muted">{label}</div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-2 gap-4" aria-label={t("automotive.readiness")}>
        <div className="surface-card flex items-start gap-3" style={{ padding: "var(--space-md)" }}>
          <ShieldAlert size={18} className="shrink-0 text-warning" />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold">{t("automotive.virtualTitle")}</h2>
              <Badge variant={virtualConfigured ? "warning" : "default"}>
                {virtualConfigured
                  ? t("automotive.policyConfigured")
                  : t("automotive.notConfigured")}
              </Badge>
            </div>
            <p className="mt-1 text-12px text-text-secondary">
              {t("automotive.virtual.policyGated")}
            </p>
          </div>
        </div>
        <div className="surface-card flex items-start gap-3" style={{ padding: "var(--space-md)" }}>
          <ShieldAlert size={18} className="shrink-0 text-error" />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold">{t("automotive.physicalTitle")}</h2>
              <Badge variant={physicalConfigured ? "warning" : "default"}>
                {physicalConfigured
                  ? t("automotive.policyConfigured")
                  : t("automotive.disabledByDefault")}
              </Badge>
            </div>
            <p className="mt-1 text-12px text-text-secondary">
              {t("automotive.physical.approvalRequired")}
            </p>
          </div>
        </div>
      </section>

      <section className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <History size={16} className="text-text-muted" />
          <h2 className="text-sm font-semibold">{t("automotive.operationHistory")}</h2>
          <span className="text-12px text-text-muted">{operations.length}</span>
        </div>
        {loadingOperations && operations.length === 0 ? (
          <LoadingState label={t("automotive.loadingHistory")} />
        ) : operations.length === 0 ? (
          <EmptyState
            icon={<History size={22} />}
            title={t("automotive.noOperations")}
            hint={t("automotive.noOperationsHint")}
          />
        ) : (
          <div className="flex flex-col gap-2">
            {operations.map((operation) => (
              <article
                key={operation.id}
                className="surface-card flex flex-col gap-2"
                style={{ padding: "var(--space-sm) var(--space-md)" }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={statusVariant(operation.status)}>{operation.status}</Badge>
                  <span className="text-12px font-semibold text-text-primary">
                    {operation.operation}
                  </span>
                  <Badge>{operation.mode}</Badge>
                  {operation.protocol && <Badge variant="accent">{operation.protocol}</Badge>}
                  <span className="ml-auto text-11px text-text-muted">
                    {displayTimestamp(operation.started_at)}
                  </span>
                </div>
                {operation.error && (
                  <div role="alert" className="text-11px text-error">{operation.error}</div>
                )}
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-11px text-text-muted">
                  <span>{t("automotive.artifactDirectory", { path: operation.artifact_dir })}</span>
                  {operation.transcript_sha256 && (
                    <span className="font-mono">
                      {t("automotive.transcript", {
                        digest: operation.transcript_sha256.slice(0, 16),
                      })}
                    </span>
                  )}
                  <span>{t("automotive.stateCount", { count: operation.state_signatures.length })}</span>
                </div>
                {operation.state_signatures.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {operation.state_signatures.map((signature) => (
                      <Badge key={`${operation.id}-${signature.digest}`}>
                        {signature.protocol}:{signature.digest.slice(0, 10)}
                      </Badge>
                    ))}
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
      {report && previewOpen && (
        <Suspense fallback={<LoadingState label={t("automotive.report.loadingPreview")} />}>
          <ReportPreview
            markdown={report.markdown}
            formats={reportFormats}
            onClose={() => setPreviewOpen(false)}
            onExport={(format) => void exportReport(format)}
          />
        </Suspense>
      )}
    </div>
  );
}
