import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldQuestion } from "lucide-react";
import { Badge, Button, Textarea } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import type {
  RemediationDraftView,
  RemediationOperationStatus,
  RemediationOperationView,
  VerificationStageEvidence,
  VerificationStageStatus,
} from "../types";

/// Matches `hf_crash::remediation::MAX_PATCH_BYTES`. The service revalidates
/// the bound; this only keeps the editor from submitting an obvious overrun.
const MAX_PATCH_BYTES = 1_048_576;
const DEFAULT_FOLLOW_UP_SECONDS = 300;
const POLL_INTERVAL_MS = 3000;

/// The five required stages, in the order the service runs them.
const STAGE_KEYS = [
  "original_replay",
  "patch_build",
  "patched_replay",
  "regression",
  "follow_up_fuzz",
] as const;

type StageKey = (typeof STAGE_KEYS)[number];

/// Service-owned statuses mapped to a badge tone. The panel styles what the
/// service decided; it never computes a determination of its own.
const STATUS_TONE: Record<RemediationOperationStatus, "default" | "accent" | "success" | "error" | "warning"> = {
  draft: "default",
  approved: "accent",
  running: "accent",
  verified: "success",
  rejected: "error",
  inconclusive: "warning",
};

const STAGE_TONE: Record<VerificationStageStatus, "default" | "success" | "error" | "warning"> = {
  passed: "success",
  failed: "error",
  inconclusive: "warning",
  skipped: "default",
};

/// A terminal operation has finished its sandbox run and stops polling.
const TERMINAL_STATUSES: readonly RemediationOperationStatus[] = ["verified", "rejected", "inconclusive"];

function isTerminal(status: RemediationOperationStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

function shortDigest(digest: string): string {
  return digest.slice(0, 12);
}

export function PatchToProofPanel({
  findingId,
  runId,
}: {
  findingId: string;
  runId: string;
}) {
  const { t } = useI18n();
  const [patch, setPatch] = useState("");
  const [followUpSeconds, setFollowUpSeconds] = useState(DEFAULT_FOLLOW_UP_SECONDS);
  const [operation, setOperation] = useState<RemediationOperationView | null>(null);
  const [operationId, setOperationId] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(async (id: string) => {
    try {
      const view = await getTransport().invoke<RemediationOperationView>("remediation_operation", {
        operationId: id,
      });
      if (mounted.current) setOperation(view);
      return view;
    } catch (e) {
      if (mounted.current) setError(String(e));
      return null;
    }
  }, []);

  // Durable status polling: the workflow outlives this component, so the panel
  // re-reads the persisted row instead of tracking progress in memory.
  useEffect(() => {
    if (!operationId) return;
    if (operation && isTerminal(operation.status)) return;
    const timer = setInterval(() => {
      void refresh(operationId);
    }, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [operationId, operation, refresh]);

  async function createDraft() {
    setBusy(true);
    setError(null);
    try {
      const draft = await getTransport().invoke<RemediationDraftView>("create_remediation_operation", {
        runId,
        findingId,
        patch,
        followUpFuzzSeconds: followUpSeconds,
        computeUsdPerHour: 0,
        modelCostUsd: 0,
      });
      setOperationId(draft.operation_id);
      await refresh(draft.operation_id);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function approve(id: string) {
    setBusy(true);
    setError(null);
    try {
      // The desktop shell has no per-user identity, so approvals are attributed
      // to the desktop operator, matching the other desktop approval paths.
      await getTransport().invoke("approve_remediation_operation", {
        operationId: id,
        operator: "desktop-operator",
      });
      await refresh(id);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function startVerification(id: string) {
    setBusy(true);
    setError(null);
    try {
      await getTransport().invoke("start_remediation_verification", { operationId: id });
      await refresh(id);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const patchTooLarge = new TextEncoder().encode(patch).length > MAX_PATCH_BYTES;

  return (
    <section
      className="rounded-md border border-border"
      style={{ padding: "var(--space-sm)", background: "var(--surface-code)" }}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold">
          <ShieldQuestion size={14} style={{ color: "var(--accent)" }} />
          {t("patchToProof.title")}
        </div>
        {operation && <Badge variant={STATUS_TONE[operation.status]}>{t(`patchToProof.status.${operation.status}`)}</Badge>}
      </div>
      <p className="text-xs text-text-muted mt-1">{t("patchToProof.advisory")}</p>

      {!operation && (
        <div className="mt-3 flex flex-col gap-2">
          <label className="text-xs text-text-secondary" htmlFor="patch-to-proof-diff">
            {t("patchToProof.patchLabel")}
          </label>
          <Textarea
            id="patch-to-proof-diff"
            mono
            rows={8}
            value={patch}
            placeholder={t("patchToProof.patchPlaceholder")}
            onChange={(event) => setPatch(event.target.value)}
          />
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-xs text-text-secondary" htmlFor="patch-to-proof-followup">
              {t("patchToProof.followUpLabel")}
            </label>
            <input
              id="patch-to-proof-followup"
              type="number"
              min={1}
              max={3600}
              value={followUpSeconds}
              onChange={(event) => setFollowUpSeconds(Number(event.target.value))}
              className="w-24 px-2 py-1 text-11px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary outline-none"
            />
            <Button
              variant="outline"
              size="sm"
              className="ml-auto"
              disabled={patch.trim().length === 0 || patchTooLarge}
              loading={busy}
              onClick={() => void createDraft()}
            >
              {t("patchToProof.createDraft")}
            </Button>
          </div>
          {patchTooLarge && <p className="text-xs" style={{ color: "var(--error)" }}>{t("patchToProof.patchTooLarge")}</p>}
        </div>
      )}

      {operation && (
        <div className="mt-3 flex flex-col gap-3">
          <div className="rounded-sm border border-border" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-text-secondary mr-auto">{t("patchToProof.reviewScope")}</span>
              <span className="text-xs text-text-muted">
                {t("patchToProof.currentStage")}: {t(`patchToProof.stage.${operation.current_stage}`)}
              </span>
            </div>
            <div className="grid gap-x-4 gap-y-1 mt-2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 200px), 1fr))" }}>
              {[
                ["patchToProof.digest.patch", operation.binding.patch_sha256],
                ["patchToProof.digest.reproducer", operation.binding.reproducer_sha256],
                ["patchToProof.digest.harness", operation.binding.harness_sha256],
                ["patchToProof.digest.originalBinary", operation.binding.original_binary_sha256],
                ["patchToProof.digest.image", operation.binding.sandbox_image_sha256],
                ["patchToProof.digest.spec", operation.binding.verification_spec_sha256],
              ].map(([key, digest]) => (
                <div key={key} className="flex items-baseline gap-2">
                  <span className="text-xs text-text-muted">{t(key)}</span>
                  <span className="text-xs font-mono text-text-secondary" title={digest}>
                    {shortDigest(digest)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {operation.status === "draft" && (
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-xs text-text-muted mr-auto">{t("patchToProof.approveHint")}</p>
              <Button variant="outline" size="sm" loading={busy} onClick={() => void approve(operation.operation_id)}>
                {t("patchToProof.approve")}
              </Button>
            </div>
          )}

          {operation.status === "approved" && (
            <div className="flex flex-col gap-2">
              <label className="flex items-start gap-2 text-xs text-text-secondary">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                {t("patchToProof.confirmVerify")}
              </label>
              <Button
                variant="primary"
                size="sm"
                className="self-start"
                disabled={!confirmed}
                loading={busy}
                onClick={() => void startVerification(operation.operation_id)}
              >
                {t("patchToProof.startVerification")}
              </Button>
            </div>
          )}

          {operation.status === "running" && (
            <p className="text-xs text-text-muted">{t("patchToProof.runningHint")}</p>
          )}

          {operation.verification && (
            <div className="flex flex-col gap-1">
              <span className="text-xs font-medium text-text-secondary">{t("patchToProof.stages")}</span>
              {STAGE_KEYS.map((key) => (
                <StageRow key={key} stageKey={key} stage={stageEvidence(operation, key)} />
              ))}
              <span className="text-xs text-text-muted font-mono mt-1" title={operation.verification.verification_id}>
                {t("patchToProof.evidenceId")} {shortDigest(operation.verification.verification_id)}
              </span>
            </div>
          )}

          {operation.failure_code && (
            <p className="text-xs" style={{ color: "var(--warning)" }}>
              {t(`patchToProof.failure.${operation.failure_code}`)}
              {operation.failure_message ? ` -- ${operation.failure_message}` : ""}
            </p>
          )}
        </div>
      )}

      {error && <p className="text-xs mt-2" style={{ color: "var(--error)" }}>{error}</p>}
    </section>
  );
}

/// Read one stage straight from the persisted service evidence.
function stageEvidence(
  operation: RemediationOperationView,
  key: StageKey,
): VerificationStageEvidence | null {
  const verification = operation.verification;
  if (!verification) return null;
  switch (key) {
    case "original_replay":
      return verification.original_replay;
    case "patch_build":
      return verification.patch_build;
    case "patched_replay":
      return verification.patched_replay;
    case "regression":
      return verification.regression;
    case "follow_up_fuzz":
      return verification.follow_up_fuzz;
  }
}

function StageRow({ stageKey, stage }: { stageKey: StageKey; stage: VerificationStageEvidence | null }) {
  const { t } = useI18n();
  if (!stage) return null;
  const detail = t(`patchToProof.detail.${stage.detail_code}`);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-xs text-text-secondary" style={{ minWidth: "9rem" }}>
        {t(`patchToProof.stage.${stageKey}`)}
      </span>
      <Badge variant={STAGE_TONE[stage.status]}>{t(`patchToProof.stageStatus.${stage.status}`)}</Badge>
      <span className="text-xs text-text-muted">
        {detail === `patchToProof.detail.${stage.detail_code}` ? stage.detail_code : detail}
      </span>
      {stage.cases > 0 && (
        <span className="text-xs text-text-muted font-mono">
          {t("patchToProof.cases")} {stage.cases}
        </span>
      )}
      {stage.failures > 0 && (
        <span className="text-xs font-mono" style={{ color: "var(--error)" }}>
          {t("patchToProof.failures")} {stage.failures}
        </span>
      )}
    </div>
  );
}
