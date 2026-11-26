import "../../i18n.parityBinary";
import { useEffect, useState } from "react";
import { Cpu } from "lucide-react";
import { Badge, Button } from "../ui";
import { useI18n } from "../../i18nContext";
import {
  binarySession,
  binarySessions,
  formatCount as count,
  type BinaryFuzzOutcome,
  type BinarySessionSummary,
} from "../../lib/parityBinary";
import { formatDuration } from "../../lib/duration";
import { BinaryFindingList } from "./BinaryFindings";

/**
 * Binary-only findings in Triage. They live in each session's report, not in
 * the crash table, so this section reads the reports and stays apart from the
 * source findings above it. Renders nothing when the project has no sessions.
 */
export function BinaryTriageSection({ project }: { project: string }) {
  const { t, locale } = useI18n();
  const [sessions, setSessions] = useState<BinarySessionSummary[]>([]);
  const [open, setOpen] = useState<BinaryFuzzOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    binarySessions(project)
      .then((found) => { if (live) setSessions(Array.isArray(found) ? found : []); })
      .catch(() => { if (live) setSessions([]); }); // sessions cannot be read here (web mode): the section stays hidden
    return () => { live = false; };
  }, [project]);

  async function toggle(session: BinarySessionSummary) {
    if (open?.session === session.session) { setOpen(null); return; }
    setError(null);
    try {
      setOpen(await binarySession(project, session.session));
    } catch (e) {
      setError(`${t("binary.loadFailed")}: ${String(e)}`);
    }
  }

  if (sessions.length === 0) return null;
  const withFindings = sessions.filter((session) => session.findings > 0);
  return (
    <section className="surface-card overflow-hidden" aria-label={t("binary.triageSection")}>
      <div className="hf-form-section flex flex-col gap-1">
        <h2 className="text-sm font-semibold flex items-center gap-2 text-text-primary">
          <Cpu size={16} className="text-text-muted" />{t("binary.triageSection")}
          <Badge variant={withFindings.length > 0 ? "error" : "default"}>{withFindings.length}/{sessions.length}</Badge>
        </h2>
        <p className="text-xs text-text-secondary">{t("binary.triageHint")}</p>
      </div>
      <ul className="hf-form-section flex flex-col gap-2" style={{ margin: 0, listStyle: "none" }}>
        {sessions.map((session) => {
          const expanded = open?.session === session.session;
          return (
            <li key={session.session} className="flex flex-col gap-2">
              <div className="hf-history-row">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap text-sm">
                    <span className="font-semibold text-text-primary">{session.binary_name || session.binary_sha256.slice(0, 12)}</span>
                    {session.findings > 0
                      ? <Badge variant="error">{t("binary.findingsCount", { distinct: session.distinct_findings, confirmed: session.confirmed })}</Badge>
                      : <Badge>{t("binary.noFindingsShort")}</Badge>}
                  </div>
                  <p className="text-xs text-text-muted font-mono" style={{ marginTop: 2 }}>
                    {session.finished_at ? new Date(session.finished_at).toLocaleString(locale) : "-"} · {formatDuration(session.duration_secs)} · {count(session.execs_done)} execs
                  </p>
                </div>
                {session.findings > 0 && (
                  <Button variant="outline" size="sm" className="shrink-0" aria-expanded={expanded} onClick={() => void toggle(session)}>
                    {t(expanded ? "binary.hideFindings" : "binary.showFindings")}
                  </Button>
                )}
              </div>
              {expanded && open && <BinaryFindingList project={project} outcome={open} />}
            </li>
          );
        })}
      </ul>
      {error && <p role="alert" className="hf-form-section text-xs text-error">{error}</p>}
    </section>
  );
}
