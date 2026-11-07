import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import { useToast } from "./ui/toastContext";
import { Button } from "./ui/Button";

// A pending guardrail approval request (mirrors `hf_service::approval::
// PermissionRequest`, delivered as a Tauri event or over SSE in web mode).
interface PermissionRequest {
  id: string;
  action: string;
  reason: string;
  risk: string;
  timeout_secs: number;
}

// Mirrors `hf_service::approval::PermissionClosed`.
interface PermissionClosed {
  id: string;
}

interface QueuedRequest extends PermissionRequest {
  deadline: number;
}

const RISK_COLOR: Record<string, string> = {
  low: "var(--text-secondary)",
  medium: "var(--warning)",
  high: "var(--error)",
  critical: "var(--error)",
};

function formatRemaining(ms: number): string {
  const secs = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
}

/**
 * The human approval gate for agent actions, mounted once in the app shell so a
 * request is visible from every view. Requests queue in arrival order. Deny is
 * the default: it has initial focus and Escape selects it. A request the user
 * does not answer is denied by the backend at its deadline, and the prompt
 * drops it without sending anything.
 */
export function ApprovalPrompt() {
  const { t } = useI18n();
  const { toast } = useToast();
  const [queue, setQueue] = useState<QueuedRequest[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const denyRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let active = true;
    const unlisteners: Array<() => void> = [];
    const keep = (u: () => void) => {
      if (active) unlisteners.push(u);
      else u();
    };
    const transport = getTransport();
    transport
      .listen<PermissionRequest>("chat:permission_request", (ev) => {
        const request = ev.payload;
        setQueue((q) => [...q, { ...request, deadline: Date.now() + request.timeout_secs * 1000 }]);
        setNow(Date.now());
      })
      .then(keep)
      .catch(() => {
        // Without a subscription no prompt can appear; the backend then denies
        // every request at its deadline, which is the safe outcome.
      });
    // The backend withdraws a request it no longer waits for (answered
    // elsewhere, timed out, or its chat turn was stopped).
    transport
      .listen<PermissionClosed>("chat:permission_closed", (ev) => {
        setQueue((q) => q.filter((r) => r.id !== ev.payload.id));
      })
      .then(keep)
      .catch(() => {
        // A withdrawn prompt then stays until its deadline; answering it is
        // refused by the backend as no longer pending.
      });
    return () => {
      active = false;
      unlisteners.forEach((u) => u());
    };
  }, []);

  // Tick once a second while anything is pending, and drop requests whose
  // deadline has passed (the backend has already denied them).
  useEffect(() => {
    if (queue.length === 0) return;
    const timer = setInterval(() => {
      const current = Date.now();
      setNow(current);
      setQueue((q) => q.filter((r) => r.deadline > current));
    }, 1000);
    return () => clearInterval(timer);
  }, [queue.length]);

  const head = queue[0];
  const headId = head?.id;

  // Each new request at the front of the queue starts with Deny focused.
  useEffect(() => {
    if (headId) denyRef.current?.focus();
  }, [headId]);

  const answer = useCallback(
    async (approved: boolean) => {
      if (!head) return;
      setQueue((q) => q.filter((r) => r.id !== head.id));
      try {
        await getTransport().invoke("chat_answer_permission", { id: head.id, approved });
      } catch (e) {
        toast({ title: t("chat.permissionDecisionFailed"), description: String(e), variant: "error" });
      }
    },
    [head, t, toast],
  );

  if (!head) return null;
  const tier = ["low", "medium", "high", "critical"].includes(head.risk) ? head.risk : "high";

  return (
    <div
      className="fixed inset-0 z-9999 flex items-center justify-center"
      style={{ background: "rgba(0,0,0,0.5)", backdropFilter: "blur(2px)" }}
    >
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="approval-prompt-title"
        aria-describedby="approval-prompt-detail"
        className="surface-card flex flex-col gap-3"
        style={{ width: "min(480px, 92vw)", padding: "var(--space-lg)", boxShadow: "var(--shadow-lg)", animation: "dialogContentIn 0.15s ease" }}
        onKeyDown={(e) => {
          if (e.key === "Escape") void answer(false);
        }}
      >
        <div className="flex items-center gap-2">
          <ShieldAlert size={18} style={{ color: RISK_COLOR[tier] }} />
          <span id="approval-prompt-title" className="text-sm font-semibold">{t("approval.title")}</span>
          <span className="ml-auto text-xs font-medium" style={{ color: RISK_COLOR[tier] }}>
            {t("approval.risk", { tier: t(`approval.risk.${tier}`) })}
          </span>
        </div>
        <div id="approval-prompt-detail" className="flex flex-col gap-2">
          <code className="text-xs rounded-sm px-2 py-1" style={{ background: "var(--surface-secondary)", overflowWrap: "anywhere" }}>
            {head.action}
          </code>
          <p className="text-xs text-text-secondary m-0" style={{ overflowWrap: "anywhere" }}>{head.reason}</p>
          <p className="text-xs text-text-muted m-0">
            {t("approval.autoDeny", { time: formatRemaining(head.deadline - now) })}
            {queue.length > 1 && <> · {t("approval.queued", { n: queue.length - 1 })}</>}
          </p>
        </div>
        <div className="flex items-center justify-end gap-2 mt-1">
          <Button ref={denyRef} variant="outline" size="sm" onClick={() => void answer(false)}>
            {t("chat.deny")}
          </Button>
          <Button variant="primary" size="sm" onClick={() => void answer(true)}>
            {t("common.approve")}
          </Button>
        </div>
      </div>
    </div>
  );
}
