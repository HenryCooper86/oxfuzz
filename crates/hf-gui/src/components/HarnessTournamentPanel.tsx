import { useState } from "react";
import { Trophy } from "lucide-react";
import { Badge, Button } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import type {
  HarnessCandidateEvidence,
  HarnessTournamentResult,
  VerdictLevel,
} from "../types";

const DEFAULT_CANDIDATES = 3;
const DEFAULT_MAX_REPAIRS = 1;

/// Service verdicts mapped to a badge tone. The panel styles what the service
/// observed; it never recomputes a ranking.
const VERDICT_TONE: Record<VerdictLevel, "success" | "warning" | "error"> = {
  Pass: "success",
  Suspect: "warning",
  Fail: "error",
};

export function HarnessTournamentPanel({
  project,
  target,
  engine,
  lang,
}: {
  project: string;
  target: string;
  engine: string;
  lang: string;
}) {
  const { t } = useI18n();
  const [result, setResult] = useState<HarnessTournamentResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const outcome = await getTransport().invoke<HarnessTournamentResult>("harness_tournament", {
        project,
        target,
        engine,
        lang,
        candidates: DEFAULT_CANDIDATES,
        maxRepairs: DEFAULT_MAX_REPAIRS,
      });
      setResult(outcome);
    } catch (e) {
      setResult(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  // Render in the service's ranking order, best first.
  const ordered: HarnessCandidateEvidence[] =
    result?.ranking
      .map((index) => result.candidates.find((candidate) => candidate.index === index))
      .filter((candidate): candidate is HarnessCandidateEvidence => candidate !== undefined) ?? [];

  return (
    <section
      className="rounded-md border border-border"
      style={{ padding: "var(--space-sm)", background: "var(--surface-code)" }}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold">
          <Trophy size={14} style={{ color: "var(--accent)" }} />
          {t("harnessTournament.title")}
        </div>
        <Button
          variant="outline"
          size="sm"
          loading={busy}
          disabled={!project || !target}
          onClick={() => void run()}
        >
          {t("harnessTournament.run")}
        </Button>
      </div>
      <p className="text-xs text-text-muted mt-1">{t("harnessTournament.advisory")}</p>

      {result && (
        <div className="flex flex-col gap-2 mt-3">
          {result.candidates.map((candidate) => {
            const isWinner = result.winner_index === candidate.index;
            const position = ordered.findIndex((entry) => entry.index === candidate.index);
            return (
              <div
                key={candidate.index}
                className="rounded-sm border border-border"
                style={{
                  padding: "var(--space-sm)",
                  background: "var(--surface-secondary)",
                  borderColor: isWinner ? "var(--accent)" : undefined,
                }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium text-text-secondary mr-auto">
                    #{position >= 0 ? position + 1 : "-"} {t(`harnessTournament.origin.${candidate.origin}`)}
                  </span>
                  {isWinner && <Badge variant="accent">{t("harnessTournament.winner")}</Badge>}
                  <Badge variant={candidate.compiled ? "success" : "error"}>
                    {t(candidate.compiled ? "harnessTournament.compiled" : "harnessTournament.compileFailed")}
                  </Badge>
                  {candidate.smoke && (
                    <Badge variant={VERDICT_TONE[candidate.smoke.verdict]}>
                      {t(`harnessTournament.verdict.${candidate.smoke.verdict}`)}
                    </Badge>
                  )}
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1 text-xs text-text-muted font-mono">
                  <span>
                    {t("harnessTournament.repairs")}: {candidate.repairs_used}
                  </span>
                  {candidate.smoke && (
                    <span>
                      {t("harnessTournament.execs")}: {candidate.smoke.execs_per_sec.toFixed(0)}/s
                    </span>
                  )}
                  <span title={candidate.source_sha256}>
                    {candidate.source_sha256.slice(0, 12)}
                  </span>
                </div>
                {candidate.compile_error && (
                  <pre
                    className="text-xs font-mono mt-1"
                    style={{
                      background: "var(--surface-primary)",
                      padding: "var(--space-xs)",
                      borderRadius: "var(--radius-sm)",
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {candidate.compile_error}
                  </pre>
                )}
              </div>
            );
          })}
          <p className="text-xs text-text-muted">{t("harnessTournament.noPromotion")}</p>
        </div>
      )}

      {error && <p className="text-xs mt-2" style={{ color: "var(--error)" }}>{error}</p>}
    </section>
  );
}
