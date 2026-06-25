import { useState, useRef, useEffect, useCallback } from "react";
import { Send, Loader2, Bug, Crosshair, Play, Database, FolderPlus, FolderOpen, ChevronDown, Mic, X } from "lucide-react";
import { getTransport, pickFolder } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePrefs } from "../providers/PrefsContext";

interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  actions?: { label: string; icon: string }[];
}

interface ModelInfo {
  id: string;
  provider_type: string;
  model: string;
}

// A pending guardrail approval request (mirrors the backend payload).
interface PermissionRequest {
  id: string;
  action: string;
  reason: string;
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
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [attached, setAttached] = useState<string>(activeProject);
  const [models, setModels] = useState<string[]>([]);
  const [model, setModel] = useState<string>("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [permission, setPermission] = useState<PermissionRequest | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

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

  async function attachProjectFolder() {
    const path = await pickFolder();
    if (path) {
      setAttached(path);
      setActiveProject(path);
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
        message: text,
        project: activeProject || null,
        history,
        sessionId,
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

  const actionIcons: Record<string, React.ReactNode> = {
    crosshair: <Crosshair size={12} />,
    play: <Play size={12} />,
    bug: <Bug size={12} />,
    database: <Database size={12} />,
  };

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
              Welcome to hobot_fuzz
            </h2>
            <p className="text-sm text-text-secondary max-w-md" style={{ lineHeight: 1.6 }}>
              An AI fuzzing agent that discovers targets, writes harnesses, and drives fuzzing engines.
              <br />
              Pick a project to get started, or ask the assistant below.
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
              {["Discover targets", "Generate harness", "Run a fuzzer", "Triage crashes", "Manage corpus"].map((s) => (
                <button
                  key={s}
                  onClick={() => setInput(s)}
                  className="text-xs px-3 py-1.5 rounded-md border border-border bg-surface-primary text-text-secondary transition-all duration-150 hover:bg-surface-hover hover:text-text-primary"
                >
                  {s}
                </button>
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
                  <p className="text-sm text-text-primary whitespace-pre-wrap">{m.content}</p>
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
                <div className="flex flex-col gap-1 max-w-[80%]">
                  <div
                    className="rounded-lg"
                    style={{
                      background: "var(--surface-secondary)",
                      border: "1px solid var(--border)",
                      padding: "var(--space-sm) var(--space-md)",
                    }}
                  >
                    <p className="text-sm text-text-primary whitespace-pre-wrap" style={{ lineHeight: 1.5 }}>
                      {m.content}
                    </p>
                  </div>
                  {m.actions && (
                    <div className="flex gap-1 flex-wrap mt-1">
                      {m.actions.map((a, j) => (
                        <button
                          key={j}
                          className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded-md border border-border bg-surface-primary text-text-secondary transition-all duration-150 hover:bg-surface-hover hover:text-text-primary"
                        >
                          {actionIcons[a.icon]}
                          {a.label}
                        </button>
                      ))}
                    </div>
                  )}
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
              className="text-xs px-3 py-1.5 rounded-md text-black"
              style={{ background: "var(--accent)" }}
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
                >
                  <X size={12} />
                </button>
              </span>
            </div>
          )}

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Write a message…"
            rows={1}
            className="w-full text-sm bg-transparent border-none outline-none text-text-primary resize-none"
            style={{
              fontFamily: "var(--font-sans)",
              lineHeight: 1.5,
              minHeight: "24px",
              maxHeight: "160px",
              padding: "4px 2px",
            }}
          />

          {/* Toolbar */}
          <div className="flex items-center justify-between mt-1">
            <div className="flex items-center gap-1">
              <ToolbarIconButton
                icon={<FolderPlus size={17} />}
                title="Attach project folder"
                onClick={attachProjectFolder}
              />
            </div>
            <div className="flex items-center gap-2">
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
                onClick={hasText ? send : undefined}
                disabled={busy}
                title={hasText ? "Send" : "Voice input"}
                className="inline-flex items-center justify-center rounded-full transition-all duration-150 outline-none disabled:opacity-55"
                style={{
                  width: "30px",
                  height: "30px",
                  background: hasText ? "var(--accent)" : "transparent",
                  color: hasText ? "var(--accent-contrast)" : "var(--text-secondary)",
                  border: "none",
                  cursor: busy ? "default" : "pointer",
                }}
              >
                {busy ? (
                  <Loader2 size={15} className="animate-spin" />
                ) : hasText ? (
                  <Send size={15} />
                ) : (
                  <Mic size={17} />
                )}
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
  const name = activeProject ? activeProject.split("/").pop() || activeProject : "No project";
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
