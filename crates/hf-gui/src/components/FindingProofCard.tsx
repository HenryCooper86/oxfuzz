import { ShieldCheck } from "lucide-react";
import { Badge } from "./ui";
import { useI18n, type TParams } from "../i18nContext";
import type {
  FindingEvidenceReference,
  FindingProofCard as FindingProofCardView,
  FindingProofClaim,
  FindingProofStatus,
} from "../types";

type Translate = (key: string, params?: TParams) => string;

interface ClaimRow {
  key: string;
  label: string;
  claim: FindingProofClaim<string>;
}

function localized(t: Translate, key: string, fallback: string): string {
  const value = t(key);
  return value === key ? fallback : value;
}

function statusVariant(status: FindingProofStatus): "success" | "warning" | "default" {
  if (status === "supported") return "success";
  if (status === "not_verified") return "warning";
  return "default";
}

function evidenceLabel(t: Translate, reference: FindingEvidenceReference): string {
  return `${t(`findingProof.evidence.${reference.kind}`)} ${reference.record_id.slice(0, 8)}`;
}

export function FindingProofCard({
  proof,
  unavailable = false,
}: {
  proof?: FindingProofCardView;
  unavailable?: boolean;
}) {
  const { t } = useI18n();
  if (!proof) {
    if (!unavailable) return null;
    return (
      <section className="rounded-md border border-border" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
        <div className="flex items-center gap-2 text-xs font-semibold">
          <ShieldCheck size={14} className="text-text-muted" />
          {t("findingProof.title")}
        </div>
        <p className="text-xs text-text-muted mt-2">{t("findingProof.loadUnavailable")}</p>
      </section>
    );
  }

  const claims: ClaimRow[] = [
    { key: "faultOrigin", label: t("findingProof.faultOrigin"), claim: proof.fault_origin },
    {
      key: "deterministicReproduction",
      label: t("findingProof.deterministicReproduction"),
      claim: proof.deterministic_reproduction,
    },
    {
      key: "casrExploitability",
      label: t("findingProof.casrExploitability"),
      claim: proof.casr_exploitability,
    },
    {
      key: "externalReachability",
      label: t("findingProof.externalReachability"),
      claim: proof.external_reachability,
    },
    {
      key: "fixVerification",
      label: t("findingProof.fixVerification"),
      claim: proof.fix_verification,
    },
  ];

  return (
    <section className="rounded-md border border-border" style={{ padding: "var(--space-sm)", background: "var(--surface-code)" }}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold">
          <ShieldCheck size={14} style={{ color: "var(--accent)" }} />
          {t("findingProof.title")}
        </div>
        <span className="text-xs text-text-muted">v{proof.schema_version}</span>
      </div>
      <p className="text-xs text-text-muted mt-1">{t("findingProof.advisory")}</p>
      <div
        className="grid gap-2 mt-3"
        style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 210px), 1fr))" }}
      >
        {claims.map(({ key, label, claim }) => (
          <div key={key} className="rounded-sm border border-border" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-text-secondary mr-auto">{label}</span>
              <Badge variant="default">{t(`findingProof.value.${claim.determination}`)}</Badge>
              <Badge variant={statusVariant(claim.status)}>{t(`findingProof.status.${claim.status}`)}</Badge>
            </div>
            <p className="text-xs text-text-muted mt-1">
              {localized(t, `findingProof.detail.${claim.detail_code}`, claim.detail)}
            </p>
            {claim.evidence.length > 0 && (
              <div className="flex flex-wrap gap-x-3 gap-y-1 mt-1">
                {claim.evidence.map((reference) => (
                  <span
                    key={`${reference.kind}:${reference.record_id}`}
                    className="text-xs text-text-muted font-mono"
                    title={reference.record_id}
                  >
                    {evidenceLabel(t, reference)}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
