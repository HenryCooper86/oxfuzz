import { useState, useRef, useEffect, useCallback } from "react";
import { Send, Loader2, Crosshair, FolderPlus, FolderOpen, ChevronDown, X, Bot, RotateCcw, History, GitBranch, Maximize2, Minimize2, Sparkles, ListChecks } from "lucide-react";
import { getTransport, pickFolder } from "../lib";
import { Button } from "../components/ui";
import { useProject } from "../providers/ProjectContext";
import { usePrefs } from "../providers/PrefsContext";
import { useI18n } from "../i18n";
import { useRunOutput } from "../providers/RunOutputContext";
import { applyMode, normalizeChatRole, type ChatMode } from "./chatHelpers";

interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
}

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
const CHAT_MODE_KEY = "hf_chat_mode";

// A pending guardrail approval request (mirrors the backend payload).
interface PermissionRequest {
  id: string;
  action: string;
  reason: string;
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
  const { sendOnEnter } = usePrefs();
  const { t } = useI18n();
  // In-flight fuzz runs surface as the composer's task count.
  const { running } = useRunOutput();
  const taskCount = running ? 1 : 0;
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [attached, setAttached] = useState<string>(activeProject);
  const [models, setModels] = useState<string[]>([]);
  const [model, setModel] = useState<string>("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [permission, setPermission] = useState<PermissionRequest | null>(null);
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

  useEffect(() => {
    localStorage.setItem(CHAT_MODE_KEY, mode);
  }, [mode]);

  // Listen for guardrail approval requests from the agent (high-risk actions
  // like running a fuzzer) and surface an approve/deny prompt.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    getTransport()
      .listen<PermissionRequest>("chat:permission_request", (ev) => setPermission(ev.payload))
      .then((u) => {
        unlisten = u;
      });
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  async function answerPermission(approved: boolean) {
    const req = permission;
    if (!req) return;
    setPermission(null);
    await getTransport().invoke("chat_answer_permission", { id: req.id, approved });
  }

  // Create a persistent conversation session once (server-side memory). Falls
  // back to frontend-replayed history when no database is configured.
  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<string | null>("create_session")
      .then((id) => {
        if (!cancelled) setSessionId(id);
      })
      .catch(() => {
        /* no DB configured; chat still works via replayed history */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Populate the model selector from the actually-configured provider pool
  // (config/providers.toml). The chat uses that config, so the dropdown must
  // reflect it -- a stale setup-wizard choice is only honored if it's still a
  // configured model; otherwise we show the configured provider's model.
  useEffect(() => {
    let cancelled = false;
    const chosen = (localStorage.getItem("hf_provider_model") ?? "").trim();
    getTransport()
      .invoke<ModelInfo[]>("list_models")
      .then((list) => {
        if (cancelled) return;
        const configured = Array.from(new Set(list.map((m) => m.model).filter(Boolean)));
        const names = configured.length ? configured : chosen ? [chosen] : [];
        setModels(names);
        setModel(configured.includes(chosen) ? chosen : names[0] ?? "");
      })
      .catch(() => {
        if (cancelled) return;
        if (chosen) {
          setModels([chosen]);
          setModel(chosen);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
    const minPx = expanded ? 200 : 24;
    const maxPx = expanded ? window.innerHeight * 0.5 : 160;
    ta.style.height = "auto";
    const next = Math.min(Math.max(ta.scrollHeight, minPx), maxPx);
    ta.style.height = `${next}px`;
    ta.style.overflowY = ta.scrollHeight > maxPx ? "auto" : "hidden";
  }, [input, expanded]);

  async function attachProjectFolder() {
    const path = await pickFolder();
    if (path) {
      setAttached(path);
      setActiveProject(path);
    }
  }

  // Undo the most recent turn: truncate the persisted transcript (when a
  // session is active) and drop the last exchange from the visible thread.
  async function rollbackLast() {
    if (busy || messages.length < 2) return;
    if (sessionId) {
      try {
        await getTransport().invoke("chat_rollback", { sessionId });
      } catch {
        /* best-effort; still undo locally */
      }
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
      } catch {
        /* best-effort; still truncate locally */
      }
    }
    setMessages((m) => m.slice(0, cp.message_count_before));
  }

  // Fork the current conversation into a new branch and switch to it. The
  // visible thread stays (the branch starts as a copy); future turns diverge.
  async function branchFromHere() {
    if (!sessionId || busy) return;
    try {
      const id = await getTransport().invoke<string | null>("chat_branch", {
        sessionId,
        forkCount: messages.length,
        title: null,
      });
      if (id) setSessionId(id);
    } catch {
      /* no-op; branching unavailable */
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
      const hist = await getTransport().invoke<{ role: string; content: string }[]>("chat_history", {
        sessionId: b.id,
      });
      setSessionId(b.id);
      setMessages(
        hist.map((t) => ({
          role: normalizeChatRole(t.role),
          content: t.content,
          timestamp: new Date().toISOString(),
        })),
      );
    } catch {
      /* no-op */
    }
  }

  async function send() {
    const text = input.trim();
    if (!text || busy) return;

    const now = () => new Date().toLocaleTimeString();
    const msg: ChatMessage = { role: "user", content: text, timestamp: now() };
    // Snapshot prior turns as agent history before appending the new message.
    const history = messages
      .filter((m) => m.role === "user" || m.role === "assistant")
      .map((m) => ({ role: m.role, content: m.content }));
    setMessages((m) => [...m, msg]);
    setInput("");
    setBusy(true);

    const transport = getTransport();
    let unlisten: (() => void) | undefined;
    try {
      // Stream live tool activity from the autonomous agent as system lines.
      unlisten = await transport.listen<AgentEvent>("chat:event", (ev) => {
        const e = ev.payload;
        if (e.type === "tool_call") {
          setMessages((m) => [
            ...m,
            { role: "system", content: `Calling tool: ${e.name}(${JSON.stringify(e.args)})`, timestamp: now() },
          ]);
        } else if (e.type === "tool_result") {
          setMessages((m) => [
            ...m,
            { role: "system", content: `${e.name} -> ${e.summary}`, timestamp: now() },
          ]);
        }
        // "thinking" events are the model's internal reasoning -- not shown as
        // chat messages.
      });

      const responseText = await transport.invoke<string>("chat_agent", {
        message: applyMode(text, mode),
        project: activeProject || null,
        history,
        sessionId,
        agentId,
      });
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content:
            responseText ||
            "I couldn't generate a response. Make sure a provider is configured in Settings.",
          timestamp: now(),
        },
      ]);
    } catch (err) {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: `I hit an error: ${err instanceof Error ? err.message : String(err)}. Configure a provider in Settings, and pick a project folder so I can run tools.`,
          timestamp: now(),
        },
      ]);
    } finally {
      if (unlisten) unlisten();
      setBusy(false);
    }
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key !== "Enter") return;
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
        {messages.length === 0 && (
          <div
            className="flex flex-col items-center justify-center h-full text-center"
            style={{ padding: "var(--space-xl) var(--space-md)" }}
          >
            <img
              src="/logo-256x256.png"
              alt="hobot_fuzz"
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
                    <p
                      className="text-sm text-text-primary whitespace-pre-wrap"
                      style={{ lineHeight: 1.5, overflowWrap: "anywhere" }}
                    >
                      {m.content}
                    </p>
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
            <span>Thinking...</span>
          </div>
        )}
      </div>

      {/* Guardrail approval prompt (HITL) */}
      {permission && (
        <div
          className="flex items-center justify-between gap-3 mx-4 mb-2 px-3 py-2 rounded-md border"
          style={{ borderColor: "var(--accent)", background: "var(--surface-secondary)" }}
        >
          <div className="text-sm">
            <span style={{ color: "var(--accent)" }}>Approval required:</span> {permission.action}
            <span className="text-text-secondary"> — {permission.reason}</span>
          </div>
          <div className="flex gap-2 shrink-0">
            <button
              onClick={() => answerPermission(false)}
              className="text-xs px-3 py-1.5 rounded-md border border-border text-text-secondary hover:bg-surface-hover"
            >
              Deny
            </button>
            <button
              onClick={() => answerPermission(true)}
              className="text-xs px-3 py-1.5 rounded-md"
              style={{ background: "var(--accent)", color: "var(--accent-contrast)" }}
            >
              Approve
            </button>
          </div>
        </div>
      )}

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
          {attached && (
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
                title={attached}
              >
                <FolderPlus size={12} style={{ color: "var(--accent)" }} />
                {attached.split("/").pop() || attached}
                <button
                  onClick={() => setAttached("")}
                  className="inline-flex items-center"
                  style={{
                    background: "none",
                    border: "none",
                    color: "var(--text-muted)",
                    cursor: "pointer",
                    padding: 0,
                  }}
                  title="Remove attachment"
                  aria-label="Remove attachment"
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
            rows={1}
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
                title="Attach project folder"
                onClick={attachProjectFolder}
              />
              {agents.length > 0 && (
                <AgentDropdown agents={agents} value={agentId} onSelect={setAgentId} />
              )}
              {messages.length >= 2 && !busy && (
                <ToolbarIconButton
                  icon={<RotateCcw size={16} />}
                  title="Undo last turn (rollback)"
                  onClick={rollbackLast}
                />
              )}
              {sessionId && messages.length >= 2 && !busy && (
                <div className="relative">
                  <ToolbarIconButton
                    icon={<History size={16} />}
                    title="Roll back to an earlier turn"
                    onClick={() => (pickerOpen ? setPickerOpen(false) : void openPicker())}
                  />
                  {pickerOpen && (
                    <div
                      className="absolute bottom-full mb-2 left-0 z-20 rounded-md border border-border shadow-lg overflow-hidden"
                      style={{ background: "var(--surface-secondary)", width: "300px", maxHeight: "260px" }}
                    >
                      <div className="text-xs text-text-muted px-3 py-2 border-b border-border" style={{ fontWeight: 600, letterSpacing: "0.04em" }}>
                        ROLL BACK TO BEFORE…
                      </div>
                      <div className="overflow-y-auto" style={{ maxHeight: "220px" }}>
                        {checkpoints.length === 0 && (
                          <div className="text-xs text-text-muted px-3 py-3">No earlier turns.</div>
                        )}
                        {checkpoints.map((cp) => (
                          <button
                            key={cp.checkpoint_id}
                            onClick={() => void rollbackTo(cp)}
                            className="flex items-start gap-2 w-full text-left px-3 py-2 hover:bg-surface-hover border-b border-border last:border-0"
                          >
                            <span className="text-xs font-mono shrink-0" style={{ color: "var(--accent)", minWidth: "44px" }}>
                              turn {cp.turn_number}
                            </span>
                            <span className="text-xs text-text-secondary truncate">{cp.preview || "(no preview)"}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {sessionId && messages.length >= 2 && !busy && (
                <div className="relative">
                  <ToolbarIconButton
                    icon={<GitBranch size={16} />}
                    title="Branches (fork / switch)"
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
                        <GitBranch size={13} /> Branch from here
                      </button>
                      <div className="text-xs text-text-muted px-3 py-1.5 border-b border-border" style={{ fontWeight: 600, letterSpacing: "0.04em" }}>
                        CONVERSATION TREE
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
                              {b.active ? " · current" : ""}
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
              <span className="text-xs text-text-muted" title="In-flight fuzz runs" style={{ whiteSpace: "nowrap" }}>
                {taskCount} task{taskCount === 1 ? "" : "s"}
              </span>
              <ToolbarIconButton
                icon={expanded ? <Minimize2 size={15} /> : <Maximize2 size={15} />}
                title={expanded ? "Collapse input" : "Expand input"}
                onClick={() => setExpanded((e) => !e)}
              />
              {models.length > 0 ? (
                <Dropdown value={model} options={models} onSelect={setModel} subtle />
              ) : (
                <span
                  className="text-xs text-text-muted"
                  style={{ padding: "5px 8px" }}
                  title="Configure a provider in Settings"
                >
                  No provider
                </span>
              )}
              <button
                onClick={send}
                disabled={busy || !hasText}
                title="Send"
                aria-label="Send"
                className="inline-flex items-center justify-center rounded-full transition-all duration-150 outline-none disabled:opacity-55"
                style={{
                  width: "30px",
                  height: "30px",
                  background: hasText ? "var(--accent)" : "transparent",
                  color: hasText ? "var(--accent-contrast)" : "var(--text-secondary)",
                  border: "none",
                  cursor: busy || !hasText ? "default" : "pointer",
                }}
              >
                {busy ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
              </button>
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
  const { t } = useI18n();
  const name = activeProject ? activeProject.split("/").pop() || activeProject : t("common.noProject");
  return (
    <div className="relative inline-block">
      <button
        onClick={() => setOpen((o) => !o)}
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
                No recent projects
              </div>
            ) : (
              recentProjects.map((p) => (
                <button
                  key={p}
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
              <span className="text-sm">Browse for project…</span>
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/** Auto / Plan composer mode toggle, styled as a pair of pills. */
function ModeToggle({ mode, onChange }: { mode: ChatMode; onChange: (m: ChatMode) => void }) {
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
      {pill("auto", "Auto", <Sparkles size={13} />, "Auto: send the message as-is")}
      {pill("plan", "Plan", <ListChecks size={13} />, "Plan: the agent outlines a plan before acting")}
    </div>
  );
}

function ToolbarIconButton({
  icon,
  title,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={title}
      className="inline-flex items-center justify-center rounded-md transition-all duration-150"
      style={{
        width: "30px",
        height: "30px",
        background: "transparent",
        color: "var(--text-secondary)",
        border: "none",
        cursor: "pointer",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
    >
      {icon}
    </button>
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
  const active = agents.find((a) => a.id === value);
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        title="Active agent"
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

function Dropdown({
  value,
  options,
  onSelect,
  leftIcon,
  subtle,
}: {
  value: string;
  options: string[];
  onSelect: (value: string) => void;
  leftIcon?: React.ReactNode;
  subtle?: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
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
        <span>{value}</span>
        <ChevronDown size={14} style={{ opacity: 0.7 }} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0" style={{ zIndex: 40 }} onClick={() => setOpen(false)} />
          <div
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
                key={opt}
                onClick={() => {
                  onSelect(opt);
                  setOpen(false);
                }}
                className="flex items-center w-full text-left transition-colors duration-150"
                style={{
                  padding: "8px 12px",
                  fontSize: "13px",
                  background: opt === value ? "var(--surface-active)" : "transparent",
                  color: opt === value ? "var(--text-primary)" : "var(--text-secondary)",
                  border: "none",
                  cursor: "pointer",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = opt === value ? "var(--surface-active)" : "transparent")
                }
              >
                {opt}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
