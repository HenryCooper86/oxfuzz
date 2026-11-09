import { useState, useRef, useEffect, useCallback } from "react";
import { Send, Square, Loader2, Crosshair, FolderPlus, FolderOpen, ChevronDown, X, Bot, RotateCcw, History, GitBranch, Maximize2, Minimize2, Sparkles, ListChecks, Trash2 } from "lucide-react";
import { getTransport, pickFolder } from "../lib";
import { Button, IconButton } from "../components/ui";
import { useToast } from "../components/ui/toastContext";
import { useConfirm } from "../providers/confirm";
import { useListboxNav } from "../hooks/useListboxNav";
import { useProject } from "../providers/project";
import { usePrefs } from "../providers/prefs";
import { useI18n } from "../i18nContext";
import { MarkdownContent } from "../components/MarkdownContent";
import {
  applyMode,
  composerLayout,
  formatToolCall,
  summarizeToolResult,
  normalizeAssistantContent,
  toCanonicalChatMessages,
  type CanonicalChatMessage,
  type CanonicalChatTurn,
  type ChatMode,
} from "./chatHelpers";

type ChatMessage = CanonicalChatMessage;

interface ModelInfo {
  id: string;
  provider_type: string;
  model: string;
}

// A user-callable agent the chat can be routed to.
interface CallableAgent {
  id: string;
  name: string;
  user_callable?: boolean;
}

const ACTIVE_AGENT_KEY = "hf_active_agent";
// The provider id picked to answer chat turns; absent means automatic routing.
const CHAT_PROVIDER_KEY = "hf_chat_provider";

function readStoredProvider(): string {
  try {
    return localStorage.getItem(CHAT_PROVIDER_KEY) ?? "";
  } catch {
    return "";
  }
}

// Picker label for a provider: its model, qualified by the provider id when
// another configured provider serves the same model.
function providerLabel(info: ModelInfo, all: ModelInfo[]): string {
  const shared = all.filter((other) => other.model === info.model).length > 1;
  return shared ? `${info.model} (${info.id})` : info.model;
}

// One running turn, named by the id sent with it so Stop cancels exactly it.
interface RunningTurn {
  id: string;
  cancelled: boolean;
  // Stop was pressed for this turn, whatever the backend answered. A cancel
  // that arrives before the turn registers answers not_running, and the turn
  // is then refused as cancelled: that failure is the user's Stop.
  stopRequested: boolean;
}

// Whether a failed turn is the backend's cancellation (ClassifiedError::Cancelled).
function isCancellation(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /\bcancelled\b/i.test(message);
}
const CHAT_MODE_KEY = "hf_chat_mode";
// Maps a project path (or "" for no active project) to its persistent chat
// session id, so the AI Assistant keeps a separate, resumable history per
// project instead of mixing them into one session.
const PROJECT_SESSIONS_KEY = "hf_project_sessions_v1";

function loadProjectSessions(): Record<string, string> {
  try {
    const raw = localStorage.getItem(PROJECT_SESSIONS_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : {};
    return parsed && typeof parsed === "object" ? (parsed as Record<string, string>) : {};
  } catch {
    return {};
  }
}

function setProjectSession(projectKey: string, sessionId: string | null) {
  const map = loadProjectSessions();
  if (sessionId) map[projectKey] = sessionId;
  else delete map[projectKey];
  try {
    localStorage.setItem(PROJECT_SESSIONS_KEY, JSON.stringify(map));
  } catch {
    /* ignore quota / private-mode errors */
  }
}

async function loadCanonicalHistory(sessionId: string): Promise<ChatMessage[]> {
  const turns = await getTransport().invoke<CanonicalChatTurn[]>("chat_history", { sessionId });
  return toCanonicalChatMessages(turns);
}

interface CheckpointView {
  checkpoint_id: string;
  turn_number: number;
  message_count_before: number;
  preview: string;
}

interface BranchView {
  id: string;
  title: string;
  depth: number;
  is_main: boolean;
  active: boolean;
}

// Mirrors hf_agent::AgentEvent (serde tag = "type", snake_case).
type AgentEvent =
  | { type: "started" }
  | { type: "thinking"; text: string }
  | { type: "tool_call"; name: string; args: unknown }
  | { type: "tool_result"; name: string; summary: string }
  | { type: "complete"; content: string }
  | { type: "error"; message: string };

export function ChatView() {
  const { activeProject, recentProjects, setActiveProject } = useProject();
  const { toast } = useToast();
  const confirm = useConfirm();
  const { sendOnEnter } = usePrefs();
  const { t } = useI18n();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [models, setModels] = useState<ModelInfo[]>([]);
  // "" selects automatic routing; any other value is a provider id that must
  // answer the turn (the backend fails the turn rather than substitute one).
  const [providerId, setProviderId] = useState<string>(readStoredProvider);
  const [stopping, setStopping] = useState(false);
  const turnRef = useRef<RunningTurn | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loadedProject, setLoadedProject] = useState<string | null>(null);
  const sessionReady = loadedProject === activeProject;
  const projectRef = useRef(activeProject);
  useEffect(() => {
    projectRef.current = activeProject;
  }, [activeProject]);
  // The session currently on screen. A turn that settles after the operator
  // moved to another session must not overwrite that session's view.
  const sessionRef = useRef<string | null>(null);
  useEffect(() => {
    sessionRef.current = sessionId;
  }, [sessionId]);
  const [agents, setAgents] = useState<CallableAgent[]>([]);
  const [agentId, setAgentId] = useState<string>(() => localStorage.getItem(ACTIVE_AGENT_KEY) || "orchestrator");
  const [pickerOpen, setPickerOpen] = useState(false);
  const [checkpoints, setCheckpoints] = useState<CheckpointView[]>([]);
  const [branchesOpen, setBranchesOpen] = useState(false);
  const [branches, setBranches] = useState<BranchView[]>([]);
  // Composer mode: "auto" sends the message as-is; "plan" asks the agent to
  // outline a step-by-step plan before acting (a prompt prefix -- no new
  // backend). Persisted across sessions.
  const [mode, setMode] = useState<ChatMode>(() => (localStorage.getItem(CHAT_MODE_KEY) as ChatMode) || "auto");
  const [expanded, setExpanded] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const taRef = useRef<HTMLTextAreaElement>(null);

  if (loadedProject !== null && loadedProject !== activeProject) {
    setLoadedProject(null);
    setMessages([]);
    setPickerOpen(false);
    setBranchesOpen(false);
  }

  useEffect(() => {
    localStorage.setItem(CHAT_MODE_KEY, mode);
  }, [mode]);

  // Resolve the per-project chat session and load its history. Keyed on the
  // active project so switching projects swaps to that project's own
  // conversation (created on first use) instead of blending histories. Falls
  // back to frontend-replayed history when no database is configured.
  useEffect(() => {
    let cancelled = false;
    const projectKey = activeProject || "";
    (async () => {
      const existing = loadProjectSessions()[projectKey];
      const T = getTransport();
      let id: string | null = existing ?? null;
      let history: ChatMessage[] = [];
      if (id) {
        try {
          history = await loadCanonicalHistory(id);
        } catch {
          // The cached id may point at a session deleted by another surface or
          // a restored database. Forget it before creating a replacement.
          setProjectSession(projectKey, null);
          id = null;
        }
      }
      if (!id) {
        try {
          id = await T.invoke<string | null>("create_session");
          if (id) setProjectSession(projectKey, id);
        } catch {
          /* no DB configured; chat still works via replayed history */
        }
      }
      if (cancelled) return;
      setSessionId(id);
      setMessages(history);
      setLoadedProject(activeProject);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeProject]);

  // Clear the current project's conversation: delete the session server-side,
  // forget the mapping, mint a fresh session, and empty the thread.
  const clearHistory = useCallback(async () => {
    if (busy) return;
    if (!(await confirm({ title: t("chat.clearHistoryTitle"), message: t("chat.clearHistoryMessage"), danger: true, confirmLabel: t("common.clear") }))) return;
    const projectKey = activeProject || "";
    const T = getTransport();
    if (sessionId) {
      try {
        await T.invoke("delete_session", { sessionId });
      } catch (error) {
        toast({
          title: t("chat.clearHistoryTitle"),
          description: String(error),
          variant: "error",
        });
        return;
      }
    }
    setProjectSession(projectKey, null);
    setMessages([]);
    try {
      const id = await T.invoke<string | null>("create_session");
      setSessionId(id);
      if (id) setProjectSession(projectKey, id);
    } catch {
      setSessionId(null);
    }
  }, [busy, activeProject, sessionId, confirm, toast, t]);

  // Populate the provider picker from the configured provider pool
  // (config/providers.toml). A remembered provider that is no longer
  // configured falls back to automatic routing in the picker, never sent.
  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<ModelInfo[]>("list_models")
      .then((list) => {
        if (cancelled) return;
        const configured = list.filter((m) => m.id && m.model);
        setModels(configured);
        setProviderId((current) => (configured.some((m) => m.id === current) ? current : ""));
      })
      .catch(() => {
        if (!cancelled) setModels([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    try {
      if (providerId) localStorage.setItem(CHAT_PROVIDER_KEY, providerId);
      else localStorage.removeItem(CHAT_PROVIDER_KEY);
    } catch {
      /* ignore quota / private-mode errors */
    }
  }, [providerId]);

  // Load the roster of user-callable agents so the chat can be routed to one.
  // Defaults to the orchestrator; falls back to the first available agent.
  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<CallableAgent[]>("list_agents")
      .then((list) => {
        if (cancelled) return;
        const callable = list.filter((a) => a.user_callable !== false);
        setAgents(callable);
        setAgentId((cur) => {
          if (callable.some((a) => a.id === cur)) return cur;
          if (callable.some((a) => a.id === "orchestrator")) return "orchestrator";
          return callable[0]?.id ?? cur;
        });
      })
      .catch(() => {
        /* agents view will surface errors; chat still works with the default id */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Persist the active-agent choice across sessions.
  useEffect(() => {
    localStorage.setItem(ACTIVE_AGENT_KEY, agentId);
  }, [agentId]);

  const scrollToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      if (scrollRef.current) {
        scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
      }
    });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Auto-grow the composer textarea to fit its content (up to a cap), then
  // scroll internally -- so long/multi-line input is never clipped by a fixed
  // one-line box.
  useEffect(() => {
    const ta = taRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    const layout = composerLayout({
      scrollHeight: ta.scrollHeight,
      expanded,
      viewportHeight: window.innerHeight,
    });
    ta.style.height = `${layout.height}px`;
    ta.style.overflowY = layout.scroll ? "auto" : "hidden";
  }, [input, expanded]);

  async function attachProjectFolder() {
    if (busy) return;
    const path = await pickFolder();
    if (path) setActiveProject(path);
  }

  // Undo the most recent turn: truncate the persisted transcript (when a
  // session is active) and drop the last exchange from the visible thread.
  async function rollbackLast() {
    if (busy || messages.length < 2) return;
    if (sessionId) {
      try {
        await getTransport().invoke("chat_rollback", { sessionId });
        setMessages(await loadCanonicalHistory(sessionId));
      } catch (e) {
        toast({ title: t("chat.rollbackNotSaved"), description: String(e), variant: "error" });
      }
      return;
    }
    setMessages((m) => m.slice(0, -2));
  }

  // Open the per-turn checkpoint picker (load the turn list from the backend).
  async function openPicker() {
    if (!sessionId) return;
    try {
      setCheckpoints(await getTransport().invoke<CheckpointView[]>("chat_checkpoints", { sessionId }));
      setPickerOpen(true);
    } catch {
      setCheckpoints([]);
    }
  }

  // Roll back to a specific turn: remove that turn and everything after it.
  async function rollbackTo(cp: CheckpointView) {
    setPickerOpen(false);
    if (sessionId) {
      try {
        await getTransport().invoke("chat_rollback_to", { sessionId, checkpointId: cp.checkpoint_id });
        setMessages(await loadCanonicalHistory(sessionId));
      } catch (e) {
        toast({ title: t("chat.rollbackNotSaved"), description: String(e), variant: "error" });
      }
    }
  }

  // Fork the current conversation into a new branch and switch to it. The
  // visible thread stays (the branch starts as a copy); future turns diverge.
  async function branchFromHere() {
    if (!sessionId || busy) return;
    try {
      const id = await getTransport().invoke<string>("chat_branch", {
        sessionId,
        forkCount: messages.filter((message) => message.role !== "system").length,
        title: null,
      });
      const history = await loadCanonicalHistory(id);
      setSessionId(id);
      setProjectSession(activeProject || "", id);
      setMessages(history);
    } catch (e) {
      toast({ title: t("chat.branchFailed"), description: String(e), variant: "error" });
    }
  }

  // Open the branch switcher (load the conversation tree).
  async function openBranches() {
    if (!sessionId) return;
    try {
      setBranches(await getTransport().invoke<BranchView[]>("chat_branches", { sessionId }));
      setBranchesOpen(true);
    } catch {
      setBranches([]);
    }
  }

  // Switch to another branch: load its transcript into the thread.
  async function switchBranch(b: BranchView) {
    setBranchesOpen(false);
    if (b.active) return;
    try {
      const history = await loadCanonicalHistory(b.id);
      setSessionId(b.id);
      setProjectSession(activeProject || "", b.id);
      setMessages(history);
    } catch (e) {
      toast({ title: t("chat.switchBranchFailed"), description: String(e), variant: "error" });
    }
  }

  async function send() {
    const text = input.trim();
    if (!text || busy || !sessionReady) return;

    const now = () => new Date().toLocaleTimeString();
    const msg: ChatMessage = { role: "user", content: text, timestamp: now() };
    // Snapshot prior turns as agent history before appending the new message.
    const history = messages
      .filter((m) => m.role === "user" || m.role === "assistant")
      .map((m) => ({ role: m.role, content: m.content }));
    setMessages((m) => [...m, msg]);
    setInput("");
    setBusy(true);
    const turn: RunningTurn = { id: crypto.randomUUID(), cancelled: false, stopRequested: false };
    turnRef.current = turn;

    const isCurrentConversation = () =>
      projectRef.current === activeProject && sessionRef.current === sessionId;
    const transport = getTransport();
    let unlisten: (() => void) | undefined;
    try {
      // Stream live tool activity from the autonomous agent as system lines.
      unlisten = await transport.listen<AgentEvent>("chat:event", (ev) => {
        if (!isCurrentConversation()) return;
        const e = ev.payload;
        if (e.type === "tool_call") {
          setMessages((m) => [
            ...m,
            { role: "system", content: t("chat.callingTool", { call: formatToolCall(e.name, e.args) }), timestamp: now() },
          ]);
        } else if (e.type === "tool_result") {
          const { headline, detail } = summarizeToolResult(e.name, e.summary);
          setMessages((m) => [...m, { role: "system", content: headline, detail, timestamp: now() }]);
        }
        // "thinking" events are the model's internal reasoning -- not shown as
        // chat messages.
      });

      const responseText = await transport.invoke<string>("chat_agent", {
        message: applyMode(text, mode),
        displayMessage: text,
        project: activeProject || null,
        history,
        sessionId,
        agentId,
        provider: providerId || null,
        turnId: turn.id,
      });
      if (!isCurrentConversation()) return;
      if (sessionId) {
        // The persisted display transcript is authoritative. Reloading also
        // removes transient tool-progress rows from the visible conversation.
        const canonical = await loadCanonicalHistory(sessionId);
        if (isCurrentConversation()) setMessages(canonical);
      } else {
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            content:
              (responseText ? normalizeAssistantContent(responseText) : "") ||
              t("chat.noResponse"),
            timestamp: now(),
          },
        ]);
      }
    } catch (err) {
      if (turn.cancelled || (turn.stopRequested && isCancellation(err))) {
        // A stopped turn is rolled back by the backend: show the stored
        // conversation again and hand the text back for editing.
        let canonical: ChatMessage[] | null = null;
        if (sessionId) {
          try {
            canonical = await loadCanonicalHistory(sessionId);
          } catch {
            /* fall back to dropping this turn's rows locally */
          }
        }
        if (!isCurrentConversation()) return;
        setMessages((current) => canonical ?? (current.includes(msg) ? current.slice(0, current.indexOf(msg)) : current));
        setInput((current) => (current.trim() ? current : text));
        return;
      }
      if (!isCurrentConversation()) return;
      let canonical: ChatMessage[] | null = null;
      if (sessionId) {
        try {
          canonical = await loadCanonicalHistory(sessionId);
        } catch {
          const projectKey = activeProject || "";
          setProjectSession(projectKey, null);
          setSessionId(null);
          try {
            const replacement = await transport.invoke<string | null>("create_session");
            setSessionId(replacement);
            if (replacement) setProjectSession(projectKey, replacement);
          } catch {
            /* frontend-only fallback remains available */
          }
        }
      }
      const errorMessage: ChatMessage = {
        role: "assistant",
        content: t("chat.agentError", { error: err instanceof Error ? err.message : String(err) }),
        timestamp: now(),
      };
      setMessages((current) => [
        ...(canonical ?? current),
        {
          ...errorMessage,
        },
      ]);
    } finally {
      if (unlisten) unlisten();
      if (turnRef.current === turn) turnRef.current = null;
      setStopping(false);
      setBusy(false);
    }
  }

  // Ask the backend to cancel the running turn. The view returns to idle when
  // the turn's request settles, after the backend has stopped it.
  async function stop() {
    const turn = turnRef.current;
    if (!turn || turn.cancelled) return;
    turn.cancelled = true;
    turn.stopRequested = true;
    setStopping(true);
    try {
      const outcome = await getTransport().invoke<string>("chat_cancel", { turnId: turn.id });
      if (outcome === "not_running") {
        // The answer was already committed; it arrives as a normal reply.
        // Either way there is nothing left to wait on: release the button.
        turn.cancelled = false;
        if (turnRef.current === turn) setStopping(false);
      }
    } catch (error) {
      turn.cancelled = false;
      if (turnRef.current === turn) setStopping(false);
      toast({ title: t("chat.stopFailed"), description: String(error), variant: "error" });
    }
  }

  function onKeyDown(e: React.KeyboardEvent) {
    // WebKit can report the IME confirmation as keyCode 229 after compositionend.
    if (e.key !== "Enter" || e.nativeEvent.isComposing || e.keyCode === 229) return;
    if (sendOnEnter && !e.shiftKey) {
      e.preventDefault();
      send();
    } else if (!sendOnEnter && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      send();
    }
  }

  const hasText = input.trim().length > 0;

  return (
    <div className="flex flex-col h-full" style={{ animation: "fadeIn 0.2s ease" }}>
      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-1" style={{ paddingBottom: "var(--space-md)" }}>
        {!sessionReady && <p role="status">{t("chat.loadingHistory")}</p>}
        {sessionReady && messages.length === 0 && (
          <div
            className="flex flex-col items-center justify-center h-full text-center"
            style={{ padding: "var(--space-xl) var(--space-md)" }}
          >
            <img
              src="/logo-256x256.png"
              alt="oxfuzz"
              width={84}
              height={84}
              draggable={false}
              style={{ marginBottom: "18px", filter: "drop-shadow(0 0 24px var(--accent-glow))" }}
            />
            <h2
              className="mb-1"
              style={{ fontFamily: "var(--font-display)", fontStyle: "italic", fontSize: "22px", fontWeight: 500 }}
            >
              {t("welcome.title")}
            </h2>
            <p className="text-sm text-text-secondary max-w-md" style={{ lineHeight: 1.6 }}>
              {t("welcome.tagline")}
              <br />
              {t("welcome.pick")}
            </p>

            <div className="mt-6">
              <WelcomeProjectSelector
                activeProject={activeProject}
                recentProjects={recentProjects}
                onSelect={setActiveProject}
                onBrowse={attachProjectFolder}
              />
            </div>

            <div className="flex flex-wrap gap-2 mt-6 justify-center max-w-lg">
              {[
                { action: "Discover targets", key: "welcome.chip.discover" },
                { action: "Generate harness", key: "welcome.chip.harness" },
                { action: "Run a fuzzer", key: "welcome.chip.run" },
                { action: "Triage crashes", key: "welcome.chip.triage" },
                { action: "Manage corpus", key: "welcome.chip.corpus" },
              ].map((c) => (
                <Button
                  key={c.key}
                  variant="outline"
                  size="sm"
                  // Send the English action to the agent for deterministic intent;
                  // display the translated label.
                  onClick={() => setInput(c.action)}
                >
                  {t(c.key)}
                </Button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div
            key={i}
            className="flex flex-col"
            style={{ marginBottom: "var(--space-sm)", animation: "slideInUp 0.2s ease" }}
          >
            {m.role === "user" ? (
              <div className="flex justify-end">
                <div
                  className="max-w-[80%] rounded-lg"
                  style={{
                    background: "var(--accent-subtle)",
                    border: "1px solid var(--border)",
                    padding: "var(--space-sm) var(--space-md)",
                  }}
                >
                  <p
                    className="text-sm text-text-primary whitespace-pre-wrap"
                    style={{ overflowWrap: "anywhere" }}
                  >
                    {m.content}
                  </p>
                  <span className="text-xs text-text-muted mt-1 block" style={{ fontSize: "10px" }}>
                    {m.timestamp}
                  </span>
                </div>
              </div>
            ) : (
              <div className="flex gap-2 items-start">
                <div
                  className="flex items-center justify-center shrink-0 rounded-full"
                  style={{
                    width: "28px",
                    height: "28px",
                    background: "var(--surface-active)",
                    border: "1px solid var(--border)",
                  }}
                >
                  <Crosshair size={14} style={{ color: "var(--accent)" }} />
                </div>
                <div className="flex flex-col gap-1 max-w-[80%] min-w-0">
                  <div
                    className="rounded-lg"
                    style={{
                      background: "var(--surface-secondary)",
                      border: "1px solid var(--border)",
                      padding: "var(--space-sm) var(--space-md)",
                    }}
                  >
                    {m.role === "assistant" ? (
                      <MarkdownContent text={m.content} />
                    ) : m.detail ? (
                      <details className="text-xs text-text-secondary">
                        <summary style={{ cursor: "pointer", overflowWrap: "anywhere" }}>{m.content}</summary>
                        <pre
                          className="mt-1 overflow-x-auto"
                          style={{ fontFamily: "var(--font-mono)", fontSize: "11px", maxHeight: "240px", overflowY: "auto" }}
                        >
                          {m.detail}
                        </pre>
                      </details>
                    ) : (
                      <p
                        className="text-sm text-text-primary whitespace-pre-wrap"
                        style={{ lineHeight: 1.5, overflowWrap: "anywhere" }}
                      >
                        {m.content}
                      </p>
                    )}
                  </div>
                  <span className="text-xs text-text-muted" style={{ fontSize: "10px" }}>
                    {m.timestamp}
                  </span>
                </div>
              </div>
            )}
          </div>
        ))}

        {busy && (
          <div
            className="flex gap-2 items-center text-text-muted text-sm"
            style={{ padding: "var(--space-sm) var(--space-md)" }}
          >
            <Loader2 size={14} className="animate-spin" />
            <span>{stopping ? t("chat.stopping") : t("chat.thinking")}</span>
          </div>
        )}
      </div>

      {/* Composer */}
      <div style={{ padding: "var(--space-sm) var(--space-md) var(--space-md)" }}>
        <div
          className="flex flex-col"
          style={{
            background: "var(--surface-secondary)",
            border: "1px solid var(--border)",
            borderRadius: "16px",
            padding: "10px 12px 8px",
          }}
        >
          {activeProject && (
            <div className="flex items-center gap-1.5 mb-2 self-start">
              <span
                className="inline-flex items-center gap-1.5 text-xs rounded-md"
                style={{
                  background: "var(--surface-active)",
                  border: "1px solid var(--border)",
                  color: "var(--text-secondary)",
                  padding: "3px 8px",
                  fontFamily: "var(--font-mono)",
                }}
                title={activeProject}
              >
                <FolderPlus size={12} style={{ color: "var(--accent)" }} />
                {activeProject.split("/").pop() || activeProject}
                <button
                  onClick={() => setActiveProject("")}
                  disabled={busy}
                  className="inline-flex items-center"
                  style={{
                    background: "none",
                    border: "none",
                    color: "var(--text-muted)",
                    cursor: busy ? "default" : "pointer",
                    opacity: busy ? 0.5 : 1,
                    padding: 0,
                  }}
                  title={t("chat.removeAttachment")}
                  aria-label={t("chat.removeAttachment")}
                >
                  <X size={12} />
                </button>
              </span>
            </div>
          )}

          <textarea
            ref={taRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder={mode === "plan" ? t("composer.placeholderPlan") : t("composer.placeholder")}
            rows={3}
            className="w-full text-sm bg-transparent border-none outline-none text-text-primary resize-none"
            style={{
              fontFamily: "var(--font-sans)",
              lineHeight: 1.5,
              // Height is driven by the auto-grow effect (min/max enforced there);
              // wrap long words so a single long token can't force overflow.
              overflowWrap: "anywhere",
              padding: "4px 2px",
            }}
          />

          {/* Toolbar */}
          <div className="flex items-center justify-between mt-1">
            <div className="flex items-center gap-1">
              <ModeToggle mode={mode} onChange={setMode} />
              <ToolbarIconButton
                icon={<FolderPlus size={17} />}
                title={t("chat.attachProject")}
                onClick={attachProjectFolder}
                disabled={busy}
              />
              {agents.length > 0 && (
                <AgentDropdown agents={agents} value={agentId} onSelect={setAgentId} />
              )}
              {messages.length >= 2 && !busy && sessionReady && (
                <ToolbarIconButton
                  icon={<RotateCcw size={16} />}
                  title={t("chat.undoLastTurn")}
                  onClick={rollbackLast}
                />
              )}
              {messages.length > 0 && !busy && sessionReady && (
                <ToolbarIconButton
                  icon={<Trash2 size={16} />}
                  title={t("chat.clearHistoryTooltip")}
                  onClick={() => void clearHistory()}
                />
              )}
              {sessionId && messages.length >= 2 && !busy && sessionReady && (
                <div className="relative">
                  <ToolbarIconButton
                    icon={<History size={16} />}
                    title={t("chat.rollBackTooltip")}
                    onClick={() => (pickerOpen ? setPickerOpen(false) : void openPicker())}
                  />
                  {pickerOpen && (
                    <div
                      className="absolute bottom-full mb-2 left-0 z-20 rounded-md border border-border shadow-lg overflow-hidden"
                      style={{ background: "var(--surface-secondary)", width: "300px", maxHeight: "260px" }}
                    >
                      <div className="text-xs text-text-muted px-3 py-2 border-b border-border" style={{ fontWeight: 600, letterSpacing: "0.04em" }}>
                        {t("chat.rollBackToBefore")}
                      </div>
                      <div className="overflow-y-auto" style={{ maxHeight: "220px" }}>
                        {checkpoints.length === 0 && (
                          <div className="text-xs text-text-muted px-3 py-3">{t("chat.noEarlierTurns")}</div>
                        )}
                        {checkpoints.map((cp) => (
                          <button
                            key={cp.checkpoint_id}
                            onClick={() => void rollbackTo(cp)}
                            className="flex items-start gap-2 w-full text-left px-3 py-2 hover:bg-surface-hover border-b border-border last:border-0"
                          >
                            <span className="text-xs font-mono shrink-0" style={{ color: "var(--accent)", minWidth: "44px" }}>
                              {t("chat.turnN", { n: cp.turn_number })}
                            </span>
                            <span className="text-xs text-text-secondary truncate">{cp.preview || t("chat.noPreview")}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {sessionId && messages.length >= 2 && !busy && sessionReady && (
                <div className="relative">
                  <ToolbarIconButton
                    icon={<GitBranch size={16} />}
                    title={t("chat.branchesTooltip")}
                    onClick={() => (branchesOpen ? setBranchesOpen(false) : void openBranches())}
                  />
                  {branchesOpen && (
                    <div
                      className="absolute bottom-full mb-2 left-0 z-20 rounded-md border border-border shadow-lg overflow-hidden"
                      style={{ background: "var(--surface-secondary)", width: "280px" }}
                    >
                      <button
                        onClick={() => {
                          setBranchesOpen(false);
                          void branchFromHere();
                        }}
                        className="flex items-center gap-2 w-full text-left px-3 py-2 hover:bg-surface-hover border-b border-border text-xs font-medium"
                        style={{ color: "var(--accent)" }}
                      >
                        <GitBranch size={13} /> {t("chat.branchFromHere")}
                      </button>
                      <div className="text-xs text-text-muted px-3 py-1.5 border-b border-border" style={{ fontWeight: 600, letterSpacing: "0.04em" }}>
                        {t("chat.conversationTree")}
                      </div>
                      <div className="overflow-y-auto" style={{ maxHeight: "180px" }}>
                        {branches.map((b) => (
                          <button
                            key={b.id}
                            onClick={() => void switchBranch(b)}
                            className="flex items-center w-full text-left px-3 py-2 hover:bg-surface-hover border-b border-border last:border-0 text-xs"
                            style={{ background: b.active ? "var(--surface-active)" : "transparent" }}
                          >
                            <span style={{ width: `${b.depth * 12}px` }} />
                            <span className="truncate" style={{ color: b.active ? "var(--accent)" : "var(--text-secondary)" }}>
                              {b.is_main ? "● " : "└ "}
                              {b.title}
                              {b.active ? t("chat.currentBranchSuffix") : ""}
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
            <div className="flex items-center gap-2">
              <ToolbarIconButton
                icon={expanded ? <Minimize2 size={15} /> : <Maximize2 size={15} />}
                title={expanded ? t("chat.collapseInput") : t("chat.expandInput")}
                onClick={() => setExpanded((e) => !e)}
              />
              {models.length > 0 ? (
                <Dropdown
                  value={providerId}
                  options={[
                    { value: "", label: t("chat.modelAuto"), title: t("chat.modelAutoHint") },
                    ...models.map((m) => ({ value: m.id, label: providerLabel(m, models), title: m.id })),
                  ]}
                  onSelect={setProviderId}
                  subtle
                />
              ) : (
                <span
                  className="text-xs text-text-muted"
                  style={{ padding: "5px 8px" }}
                  title={t("chat.configureProvider")}
                >
                  {t("chat.noProvider")}
                </span>
              )}
              {busy ? (
                <button
                  onClick={stop}
                  disabled={stopping}
                  title={stopping ? t("chat.stopping") : t("chat.stop")}
                  aria-label={t("chat.stop")}
                  className="inline-flex items-center justify-center rounded-full transition-all duration-150 outline-none disabled:opacity-55"
                  style={{
                    width: "30px",
                    height: "30px",
                    background: "var(--surface-active)",
                    color: "var(--text-primary)",
                    border: "1px solid var(--border)",
                    cursor: stopping ? "default" : "pointer",
                  }}
                >
                  {stopping ? <Loader2 size={15} className="animate-spin" /> : <Square size={13} fill="currentColor" />}
                </button>
              ) : (
                <button
                  onClick={send}
                  disabled={!hasText || !sessionReady}
                  title={t("chat.send")}
                  aria-label={t("chat.send")}
                  className="inline-flex items-center justify-center rounded-full transition-all duration-150 outline-none disabled:opacity-55"
                  style={{
                    width: "30px",
                    height: "30px",
                    background: hasText ? "var(--accent)" : "transparent",
                    color: hasText ? "var(--accent-contrast)" : "var(--text-secondary)",
                    border: "none",
                    cursor: !hasText ? "default" : "pointer",
                  }}
                >
                  <Send size={15} />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function WelcomeProjectSelector({
  activeProject,
  recentProjects,
  onSelect,
  onBrowse,
}: {
  activeProject: string;
  recentProjects: string[];
  onSelect: (path: string) => void;
  onBrowse: () => void;
}) {
  const [open, setOpen] = useState(false);
  const { triggerRef, menuRef, onMenuKey, onTriggerKey } = useListboxNav(open, () => setOpen(false));
  const { t } = useI18n();
  const name = activeProject ? activeProject.split("/").pop() || activeProject : t("common.noProject");
  return (
    <div className="relative inline-block">
      <button
        ref={triggerRef}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => onTriggerKey(e, () => setOpen(true))}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="inline-flex items-center gap-2 rounded-lg transition-colors duration-150"
        style={{
          padding: "10px 14px",
          minWidth: "260px",
          background: "var(--surface-secondary)",
          border: "1px solid var(--border)",
          cursor: "pointer",
          color: "var(--text-primary)",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "var(--surface-secondary)")}
      >
        <FolderOpen size={15} style={{ color: "var(--accent)" }} />
        <span className="flex-1 text-left text-sm truncate">{name}</span>
        <ChevronDown size={15} className="text-text-muted" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0" style={{ zIndex: 40 }} onClick={() => setOpen(false)} />
          <div
            ref={menuRef}
            role="listbox"
            onKeyDown={onMenuKey}
            className="absolute left-0 right-0 mt-1 rounded-lg overflow-hidden text-left"
            style={{
              background: "var(--surface-primary)",
              border: "1px solid var(--border)",
              boxShadow: "0 8px 24px rgba(0,0,0,0.3)",
              zIndex: 50,
            }}
          >
            {recentProjects.length === 0 ? (
              <div className="text-xs text-text-muted" style={{ padding: "10px 12px" }}>
                {t("chat.noRecentProjects")}
              </div>
            ) : (
              recentProjects.map((p) => (
                <button
                  key={p}
                  role="option"
                  aria-selected={p === activeProject}
                  onClick={() => {
                    onSelect(p);
                    setOpen(false);
                  }}
                  className="flex items-center gap-2 w-full text-left transition-colors duration-150"
                  style={{ padding: "8px 12px", background: p === activeProject ? "var(--surface-active)" : "transparent", border: "none", cursor: "pointer" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = p === activeProject ? "var(--surface-active)" : "transparent")
                  }
                >
                  <FolderOpen size={13} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
                  <span className="text-sm text-text-secondary truncate">{p.split("/").pop() || p}</span>
                </button>
              ))
            )}
            <div style={{ borderTop: "1px solid var(--border)" }} />
            <button
              onClick={() => {
                setOpen(false);
                onBrowse();
              }}
              className="flex items-center gap-2 w-full text-left transition-colors duration-150"
              style={{ padding: "9px 12px", background: "transparent", border: "none", cursor: "pointer", color: "var(--accent)" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <FolderPlus size={13} />
              <span className="text-sm">{t("chat.browseForProject")}</span>
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/** Auto / Plan composer mode toggle, styled as a pair of pills. */
function ModeToggle({ mode, onChange }: { mode: ChatMode; onChange: (m: ChatMode) => void }) {
  const { t } = useI18n();
  const pill = (m: ChatMode, label: string, icon: React.ReactNode, title: string) => {
    const active = mode === m;
    return (
      <button
        onClick={() => onChange(m)}
        title={title}
        className="inline-flex items-center gap-1 rounded-md text-xs font-medium transition-colors duration-150"
        style={{
          padding: "4px 8px",
          background: active ? "var(--accent-subtle)" : "transparent",
          color: active ? "var(--accent)" : "var(--text-muted)",
          border: "none",
          cursor: "pointer",
        }}
      >
        {icon}
        {label}
      </button>
    );
  };
  return (
    <div className="inline-flex items-center rounded-md" style={{ background: "var(--surface-active)", padding: "2px" }}>
      {pill("auto", t("chat.modeAuto"), <Sparkles size={13} />, t("chat.modeAutoTip"))}
      {pill("plan", t("chat.modePlan"), <ListChecks size={13} />, t("chat.modePlanTip"))}
    </div>
  );
}

function ToolbarIconButton({
  icon,
  title,
  onClick,
  disabled,
}: {
  icon: React.ReactNode;
  title: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <IconButton size={30} onClick={onClick} title={title} aria-label={title} disabled={disabled}>
      {icon}
    </IconButton>
  );
}

function AgentDropdown({
  agents,
  value,
  onSelect,
}: {
  agents: CallableAgent[];
  value: string;
  onSelect: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const { triggerRef, menuRef, onMenuKey, onTriggerKey } = useListboxNav(open, () => setOpen(false));
  const { t } = useI18n();
  const active = agents.find((a) => a.id === value);
  return (
    <div className="relative">
      <button
        ref={triggerRef}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => onTriggerKey(e, () => setOpen(true))}
        aria-haspopup="listbox"
        aria-expanded={open}
        title={t("chat.activeAgent")}
        className="inline-flex items-center gap-1 rounded-md transition-all duration-150"
        style={{
          padding: "5px 8px",
          fontSize: "13px",
          fontWeight: 500,
          background: "transparent",
          color: "var(--text-secondary)",
          border: "none",
          cursor: "pointer",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <Bot size={14} style={{ color: "var(--accent)" }} />
        <span>{active?.name ?? value}</span>
        <ChevronDown size={14} style={{ opacity: 0.7 }} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0" style={{ zIndex: 40 }} onClick={() => setOpen(false)} />
          <div
            ref={menuRef}
            role="listbox"
            onKeyDown={onMenuKey}
            className="absolute bottom-full mb-1 min-w-[180px] rounded-lg overflow-hidden"
            style={{
              left: 0,
              background: "var(--surface-primary)",
              border: "1px solid var(--border)",
              boxShadow: "0 8px 24px rgba(0,0,0,0.3)",
              zIndex: 50,
            }}
          >
            {agents.map((a) => (
              <button
                key={a.id}
                role="option"
                aria-selected={a.id === value}
                onClick={() => {
                  onSelect(a.id);
                  setOpen(false);
                }}
                className="flex items-center w-full text-left transition-colors duration-150"
                style={{
                  padding: "8px 12px",
                  fontSize: "13px",
                  background: a.id === value ? "var(--surface-active)" : "transparent",
                  color: a.id === value ? "var(--text-primary)" : "var(--text-secondary)",
                  border: "none",
                  cursor: "pointer",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = a.id === value ? "var(--surface-active)" : "transparent")
                }
              >
                {a.name}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

interface DropdownOption {
  value: string;
  label: string;
  title?: string;
}

function Dropdown({
  value,
  options,
  onSelect,
  leftIcon,
  subtle,
}: {
  value: string;
  options: DropdownOption[];
  onSelect: (value: string) => void;
  leftIcon?: React.ReactNode;
  subtle?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // On open, move focus to the selected option so the menu is keyboard-drivable.
  useEffect(() => {
    if (!open || !menuRef.current) return;
    const items = menuRef.current.querySelectorAll<HTMLButtonElement>('[role="option"]');
    items[Math.max(0, options.findIndex((opt) => opt.value === value))]?.focus();
  }, [open, value, options]);

  function close(returnFocus = true) {
    setOpen(false);
    if (returnFocus) triggerRef.current?.focus();
  }

  function onMenuKey(e: React.KeyboardEvent<HTMLDivElement>) {
    const items = Array.from(menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? []);
    const idx = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") { e.preventDefault(); close(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); items[Math.min(items.length - 1, idx + 1)]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[Math.max(0, idx - 1)]?.focus(); }
    else if (e.key === "Home") { e.preventDefault(); items[0]?.focus(); }
    else if (e.key === "End") { e.preventDefault(); items[items.length - 1]?.focus(); }
  }

  return (
    <div className="relative">
      <button
        ref={triggerRef}
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        onKeyDown={(e) => {
          if (!open && (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ")) {
            e.preventDefault();
            setOpen(true);
          }
        }}
        className="inline-flex items-center gap-1 rounded-md transition-all duration-150"
        style={{
          padding: "5px 8px",
          fontSize: "13px",
          fontWeight: 500,
          background: "transparent",
          color: subtle ? "var(--text-muted)" : "var(--text-secondary)",
          border: "none",
          cursor: "pointer",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        {leftIcon}
        <span>{options.find((opt) => opt.value === value)?.label ?? value}</span>
        <ChevronDown size={14} style={{ opacity: 0.7 }} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0" style={{ zIndex: 40 }} onClick={() => close(false)} />
          <div
            ref={menuRef}
            role="listbox"
            onKeyDown={onMenuKey}
            className="absolute bottom-full mb-1 min-w-[140px] rounded-lg overflow-hidden"
            style={{
              left: 0,
              background: "var(--surface-primary)",
              border: "1px solid var(--border)",
              boxShadow: "0 8px 24px rgba(0,0,0,0.3)",
              zIndex: 50,
            }}
          >
            {options.map((opt) => (
              <button
                key={opt.value}
                role="option"
                aria-selected={opt.value === value}
                title={opt.title}
                onClick={() => {
                  onSelect(opt.value);
                  close();
                }}
                className="flex items-center w-full text-left transition-colors duration-150"
                style={{
                  padding: "8px 12px",
                  fontSize: "13px",
                  background: opt.value === value ? "var(--surface-active)" : "transparent",
                  color: opt.value === value ? "var(--text-primary)" : "var(--text-secondary)",
                  border: "none",
                  cursor: "pointer",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = opt.value === value ? "var(--surface-active)" : "transparent")
                }
              >
                {opt.label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
