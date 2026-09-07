import { useCallback, useEffect, useRef, useState } from "react";
import { Stethoscope } from "lucide-react";
import { Badge, Button } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import { BuildProfileEditor } from "./BuildProfileEditor";
import type { BuildDiagnosisRecord, BuildPlan, BuildPlanRunOutcome, BuildProfileView, ProjectBuildDiagnosis } from "../types";

function PlanEvidence({ plan }: { plan: BuildPlan }) {
  const { t } = useI18n();
  return <div className="mt-2 flex flex-col gap-1 text-xs">
    <strong>{t("buildDoctor.planTitle")}</strong>
    <span>{t("buildDoctor.component")}: {plan.component_root}</span>
    <span>{t("buildDoctor.expectedArtifact")}: {plan.expected_artifact}</span>
    <span className="break-all">{t("buildDoctor.image")}: {plan.sandbox_image_tag} / {plan.sandbox_image_id}</span>
    <span className="break-all">{t("buildDoctor.digest")}: {plan.profile_sha256}</span>
    {plan.steps.map((step, index) => <div key={index}>
      <span>{step.purpose} ({t("buildDoctor.workingDir")}: {step.working_dir})</span>
      <pre className="overflow-auto whitespace-pre-wrap font-mono">{JSON.stringify(step.argv)}</pre>
    </div>)}
  </div>;
}

function DiagnosisEvidence({ diagnosis, showPlan = false }: { diagnosis: ProjectBuildDiagnosis; showPlan?: boolean }) {
  const { t } = useI18n();
  const terminal = diagnosis.terminal;
  return <div className="mt-2 flex flex-col gap-1 text-xs">
    <Badge variant={diagnosis.profile_state === "ready" ? "success" : diagnosis.profile_state === "unconfigured" ? "default" : "warning"}>
      {t(`buildDoctor.profileState.${diagnosis.profile_state}`)}
    </Badge>
    {diagnosis.profile_state === "unconfigured" && <p>{t("buildDoctor.unconfiguredHelp")} {t(diagnosis.legacy_build_context_available ? "buildDoctor.legacyAvailable" : "buildDoctor.legacyAbsent")}</p>}
    {diagnosis.profile && <p>{t("buildDoctor.component")}: {diagnosis.profile.component_root} · {t("buildDoctor.database")}: {diagnosis.profile.compile_database_path}</p>}
    {diagnosis.detected.map((entry) => <p key={entry.build_system}>
      {t(`buildDoctor.system.${entry.build_system}`)}: {t(`buildDoctor.status.${entry.status}`)} · {entry.markers.join(", ")}
      {entry.missing_tool && ` · ${t("buildDoctor.missingTool", { tool: entry.missing_tool })}`}
    </p>)}
    {diagnosis.dependency_statuses.map(({ dependency, available }) => <p key={`${dependency.kind}:${dependency.name}`}>
      {dependency.kind}:{dependency.name} — {t(available ? "buildDoctor.dependencyAvailable" : "buildDoctor.dependencyMissing")}
    </p>)}
    {diagnosis.reasons.map((reason, index) => <p key={index}>{reason}</p>)}
    {showPlan && diagnosis.profile && <details><summary>{t("buildDoctor.capturedProfile")}</summary><pre className="whitespace-pre-wrap overflow-auto">{JSON.stringify(diagnosis.profile, null, 2)}</pre></details>}
    {showPlan && diagnosis.plan && <PlanEvidence plan={diagnosis.plan} />}
    {terminal && <div>
      <strong>{t(`buildDoctor.runStatus.${terminal.status}`)}</strong>
      {terminal.step_index !== null && <p>{t("buildDoctor.failedStep", { index: String(terminal.step_index + 1), code: String(terminal.exit_code ?? "—") })}</p>}
      {terminal.failure_message && <p>{terminal.failure_message}</p>}
      {terminal.failure_code && <code>{terminal.failure_code}</code>}
      <pre className="whitespace-pre-wrap overflow-auto">{terminal.stdout}{"\n"}{terminal.stderr}</pre>
      {terminal.output_truncated && <p>{t("buildDoctor.outputTruncated")}</p>}
    </div>}
  </div>;
}

interface Props { project: string; onGenerationBlocked?: (project: string, blocked: boolean) => void }

export function BuildDoctorPanel(props: Props) {
  return <ProjectBuildDoctor key={props.project} {...props} />;
}

function ProjectBuildDoctor({ project, onGenerationBlocked }: Props) {
  const { t } = useI18n();
  const [diagnosis, setDiagnosis] = useState<ProjectBuildDiagnosis | null>(null);
  const [profile, setProfile] = useState<BuildProfileView | null>(null);
  const [currentProfile, setCurrentProfile] = useState<BuildProfileView | null | undefined>(undefined);
  const [currentDiagnosis, setCurrentDiagnosis] = useState<ProjectBuildDiagnosis | null>(null);
  const [history, setHistory] = useState<BuildDiagnosisRecord[]>([]);
  const [outcome, setOutcome] = useState<BuildPlanRunOutcome | null>(null);
  const [confirmedDigest, setConfirmedDigest] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const scope = useRef(0);

  const refresh = useCallback(async (token: number, mutationProfile?: BuildProfileView | null) => {
    const transport = getTransport();
    const results = await Promise.allSettled([
      transport.invoke<ProjectBuildDiagnosis>("build_diagnose", { project }),
      transport.invoke<BuildProfileView | null>("build_profile", { project }),
    ]);
    if (token !== scope.current) return;
    const [current, saved] = results;
    const knownProfile = saved.status === "fulfilled" ? saved.value : mutationProfile;
    setCurrentProfile(knownProfile);
    if (knownProfile !== undefined) setProfile(knownProfile);
    if (current.status === "fulfilled") setDiagnosis(current.value);
    setCurrentDiagnosis(current.status === "fulfilled" && knownProfile !== undefined
      && (current.value.profile?.profile_sha256 ?? null) === (knownProfile?.profile_sha256 ?? null)
      ? current.value : null);
    const errors = results.flatMap((result) => result.status === "rejected" ? [String(result.reason)] : []);
    try {
      // Diagnosis persists an operation; read history after that operation settles.
      const retained = await transport.invoke<BuildDiagnosisRecord[]>("build_history", { project, limit: 20 });
      if (token !== scope.current) return;
      setHistory(retained);
    } catch (failure) {
      if (token !== scope.current) return;
      errors.push(String(failure));
    }
    setError(errors.length ? errors.join("\n") : null);
  }, [project]);

  useEffect(() => {
    const token = ++scope.current;
    void refresh(token).finally(() => { if (token === scope.current) setBusy(false); });
    return () => { scope.current += 1; };
  }, [refresh]);

  const generationBlocked = busy || currentProfile === undefined || (currentProfile !== null && currentDiagnosis?.profile_state !== "ready");
  useEffect(() => { onGenerationBlocked?.(project, generationBlocked); }, [project, generationBlocked, onGenerationBlocked]);

  async function perform(operation?: () => Promise<BuildProfileView | null>) {
    const token = ++scope.current;
    setBusy(true); setError(null); setConfirmedDigest(null); setCurrentDiagnosis(null);
    try {
      const changedProfile = operation ? await operation() : undefined;
      if (token !== scope.current) return;
      if (changedProfile !== undefined) { setProfile(changedProfile); setCurrentProfile(changedProfile); }
      await refresh(token, changedProfile);
    } catch (failure) {
      if (token === scope.current) {
        await refresh(token);
        if (token === scope.current) setError(String(failure));
      }
    } finally {
      if (token === scope.current) setBusy(false);
    }
  }

  async function run(plan: BuildPlan) {
    if (confirmedDigest !== plan.profile_sha256) return;
    const token = ++scope.current;
    const expectedProfileSha256 = confirmedDigest;
    setBusy(true); setError(null); setConfirmedDigest(null); setCurrentDiagnosis(null);
    try {
      const result = await getTransport().invoke<BuildPlanRunOutcome>("build_run", { project, expectedProfileSha256 });
      if (token !== scope.current) return;
      setOutcome(result);
      await refresh(token);
    } catch (failure) {
      if (token === scope.current) {
        // A stale reviewed digest still refreshes the diagnosis, without approving its new plan.
        await refresh(token);
        if (token === scope.current) setError(String(failure));
      }
    } finally { if (token === scope.current) setBusy(false); }
  }

  return <section className="rounded-md border border-border p-3" aria-label={t("buildDoctor.title")}>
    <div className="flex items-center justify-between gap-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold"><Stethoscope size={14} />{t("buildDoctor.title")}</h3>
      <Button variant="outline" size="sm" disabled={busy} onClick={() => void perform()}>{t("buildDoctor.diagnose")}</Button>
    </div>
    <p className="text-xs text-text-muted mt-1">{t("buildDoctor.advisory")}</p>
    {busy && <p role="status" className="text-xs mt-2">{t("buildDoctor.pending")}</p>}
    {currentDiagnosis && <DiagnosisEvidence diagnosis={currentDiagnosis} />}
    {!busy && !currentDiagnosis && (currentProfile === null
      ? <p className="text-xs mt-2">{t("buildDoctor.profileState.unconfigured")}: {t("buildDoctor.unconfiguredHelp")}</p>
      : <p className="text-xs mt-2">{t("buildDoctor.currentUnavailable")}</p>)}
    {!currentDiagnosis && diagnosis && <details className="text-xs mt-2"><summary>{t("buildDoctor.previousDiagnosis")}</summary><DiagnosisEvidence diagnosis={diagnosis} showPlan /></details>}
    <div className="flex gap-2 mt-2">
      <Button size="sm" variant="outline" disabled={busy} onClick={() => setEditing((value) => !value)}>{t("buildDoctor.editProfile")}</Button>
      <Button size="sm" variant="outline" disabled={busy || !profile} onClick={() => void perform(() => getTransport().invoke<null>("build_profile_clear", { project }))}>{t("buildDoctor.clearProfile")}</Button>
    </div>
    {editing && <BuildProfileEditor key={profile?.profile_sha256 ?? "unconfigured"} profile={profile} busy={busy} onSave={(fields) => perform(() => getTransport().invoke<BuildProfileView>("build_profile_set", { project, ...fields }))} />}
    {currentDiagnosis?.plan && <div className="mt-2 border-t border-border pt-2">
      <PlanEvidence plan={currentDiagnosis.plan} />
      <label className="flex gap-2 text-xs mt-2"><input type="checkbox" disabled={busy} checked={confirmedDigest === currentDiagnosis.plan.profile_sha256} onChange={(event) => setConfirmedDigest(event.target.checked ? currentDiagnosis.plan!.profile_sha256 : null)} />{t("buildDoctor.confirmRun")}</label>
      <Button size="sm" variant="primary" disabled={busy || confirmedDigest !== currentDiagnosis.plan.profile_sha256} onClick={() => void run(currentDiagnosis.plan!)}>{t("buildDoctor.runPlan")}</Button>
    </div>}
    {outcome && <div className="mt-2"><strong className="text-xs">{t("buildDoctor.runResult")}: {t(`buildDoctor.runStatus.${outcome.status}`)}</strong><DiagnosisEvidence diagnosis={outcome.diagnosis} /></div>}
    {error && <p role="alert" className="text-xs whitespace-pre-wrap mt-2" style={{ color: "var(--error)" }}>{error}</p>}
    <details className="mt-3 text-xs"><summary>{t("buildDoctor.history")} ({history.length})</summary>
      {history.length === 0 && <p>{t("buildDoctor.noHistory")}</p>}
      {history.map((record) => <article key={record.id} className="mt-2 border-t border-border pt-2">
        <p>{record.created_at} · {t(`buildDoctor.operation.${record.diagnosis.operation}`)} · {t(`buildDoctor.historyStatus.${record.status}`)}</p>
        <DiagnosisEvidence diagnosis={record.diagnosis} showPlan />
      </article>)}
    </details>
  </section>;
}
