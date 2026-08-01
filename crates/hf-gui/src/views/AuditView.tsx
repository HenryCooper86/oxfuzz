import { useCallback, useEffect, useState } from "react";
import { getTransport, onDataChanged } from "../lib";
import { useI18n } from "../i18nContext";
import { useProject } from "../providers/project";
import { ViewHeader, EmptyState, Button } from "../components/ui";
import { PolicyDecisionList, type PolicyDecision } from "../components/PolicyDecisionList";
import { RotateCcw, AlertTriangle, ScrollText } from "lucide-react";

interface AutoRevertEvent {
  id: string;
  ts: string;
  project_root: string;
  target: string;
  run_id: string;
  from_rev: string;
  to_rev: string;
  previous_edges: number;
  regressed_edges: number;
  drop_pct: number;
  reverted: boolean;
}

function fmtTime(ts: string): string {
  const d = new Date(ts);
  return isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// A durable timeline of every auto-revert policy firing: a harness revision
// regressed coverage past the threshold, so the previous revision was restored
// (applied) or flagged (notify-only). Persisted in the store, so it survives
// restarts (unlike the run-journal WAL, which is compacted).
export function AuditView() {
  const { t } = useI18n();
  const { activeProject } = useProject();
  const [scope, setScope] = useState<"all" | "project">(activeProject ? "project" : "all");
  const [events, setEvents] = useState<AutoRevertEvent[]>([]);
  const [decisions, setDecisions] = useState<PolicyDecision[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    const project = scope === "project" ? activeProject || undefined : undefined;
    // allSettled (not all): the two sources are independent, so one rejecting
    // (e.g. an older backend without /policy/decisions, or a transient error)
    // must not blank the other's already-working data.
    const [eventsResult, decisionsResult] = await Promise.allSettled([
      getTransport().invoke<AutoRevertEvent[]>("auto_revert_events", {
        project,
        limit: 200,
      }),
      // Decisions are not project-scoped in the service: the guardrail trail
      // records actions that have no project, so scoping would silently drop
      // them.
      getTransport().invoke<PolicyDecision[]>("policy_decisions", { limit: 200 }),
    ]);

    if (eventsResult.status === "fulfilled") {
      setEvents(eventsResult.value ?? []);
    } else {
      setEvents([]);
    }
    if (decisionsResult.status === "fulfilled") {
      setDecisions(decisionsResult.value ?? []);
    } else {
      setDecisions([]);
    }

    const failures: string[] = [];
    if (eventsResult.status === "rejected") {
      failures.push(t("audit.loadError", { error: String(eventsResult.reason) }));
    }
    if (decisionsResult.status === "rejected") {
      failures.push(t("audit.loadErrorDecisions", { error: String(decisionsResult.reason) }));
    }
    setError(failures.length > 0 ? failures.join(" ") : null);

    setLoading(false);
  }, [scope, activeProject, t]);

  useEffect(() => {
    queueMicrotask(() => void load());
    return onDataChanged(() => void load());
  }, [load]);

  const applied = events.filter((e) => e.reverted).length;
  const flagged = events.length - applied;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader
        title={t("audit.title")}
        description={t("audit.description")}
      />

      {error && (
        <div
          className="surface-card flex items-center justify-between gap-3"
          style={{ padding: "var(--space-sm) var(--space-md)", borderColor: "var(--error)" }}
        >
          <span className="text-xs min-w-0 truncate" style={{ color: "var(--error)" }}>
            {error}
          </span>
          <Button variant="outline" size="sm" onClick={() => void load()}>
            {t("common.retry")}
          </Button>
        </div>
      )}

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-medium">{t("audit.decisionsTitle")}</h3>
        <div className="text-xs text-text-muted">{t("audit.decisionsAllProjects")}</div>
        {loading ? (
          <div className="text-xs text-text-muted">{t("audit.loading")}</div>
        ) : (
          <PolicyDecisionList decisions={decisions} emptyLabel={t("audit.decisionsEmpty")} />
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-medium">{t("audit.revertsTitle")}</h3>
        {activeProject && (
          <div className="flex items-center gap-1 text-xs">
            <Button variant={scope === "project" ? "primary" : "outline"} size="sm" onClick={() => setScope("project")}>
              {t("audit.thisProject")}
            </Button>
            <Button variant={scope === "all" ? "primary" : "outline"} size="sm" onClick={() => setScope("all")}>
              {t("audit.allProjects")}
            </Button>
          </div>
        )}
      </div>

      {events.length > 0 && (
        <div className="flex items-center gap-4 text-xs text-text-muted">
          <span>
            {t("audit.firings", { n: events.length })}
          </span>
          <span className="inline-flex items-center gap-1" style={{ color: "var(--accent)" }}>
            <RotateCcw size={12} /> {t("audit.revertedCount", { n: applied })}
          </span>
          <span className="inline-flex items-center gap-1" style={{ color: "var(--warning, var(--accent))" }}>
            <AlertTriangle size={12} /> {t("audit.flaggedCount", { n: flagged })}
          </span>
        </div>
      )}

      {loading ? (
        <div className="text-xs text-text-muted">{t("audit.loading")}</div>
      ) : events.length === 0 ? (
        <EmptyState
          icon={<ScrollText size={28} />}
          title={t("audit.emptyTitle")}
          hint={t("audit.emptyHint")}
        />
      ) : (
        <div className="flex flex-col gap-1.5">
          {events.map((e) => {
            const name = e.project_root.split("/").filter(Boolean).pop() || e.project_root;
            const color = e.reverted ? "var(--accent)" : "var(--warning, var(--accent))";
            return (
              <div
                key={e.id}
                className="surface-card flex items-start gap-3"
                style={{ padding: "var(--space-sm) var(--space-md)", borderLeft: `3px solid ${color}` }}
              >
                {e.reverted ? (
                  <RotateCcw size={16} style={{ color, flexShrink: 0, marginTop: 2 }} />
                ) : (
                  <AlertTriangle size={16} style={{ color, flexShrink: 0, marginTop: 2 }} />
                )}
                <div className="flex flex-col min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium truncate">{name}</span>
                    <span className="text-xs text-text-muted truncate" style={{ fontFamily: "var(--font-mono)" }}>
                      {e.target}
                    </span>
                    <span
                      className="text-xs rounded-full"
                      style={{ padding: "0 8px", border: `1px solid ${color}`, color }}
                    >
                      {e.reverted ? t("audit.revertedBadge") : t("audit.flaggedBadge")}
                    </span>
                  </div>
                  <span className="text-xs text-text-secondary" style={{ lineHeight: 1.5 }}>
                    {t("audit.coverageDropped", { pct: e.drop_pct.toFixed(1), regressed: e.regressed_edges, previous: e.previous_edges })}{" "}
                    {t("audit.harnessPrefix")}<code>{e.from_rev.slice(0, 8)}</code> {e.reverted ? t("audit.restoredBaseline") : t("audit.comparableLastGood")}{" "}
                    <code>{e.to_rev.slice(0, 8)}</code>.
                  </span>
                </div>
                <span className="text-xs text-text-muted whitespace-nowrap" style={{ marginTop: 2 }}>
                  {fmtTime(e.ts)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
