import { useState, useRef, useEffect, useCallback } from "react";
import { Send, Loader2, Bug, Crosshair, Play, Database } from "lucide-react";

interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  actions?: { label: string; icon: string }[];
}

export function ChatView() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

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

  async function send() {
    const text = input.trim();
    if (!text || busy) return;

    const msg: ChatMessage = {
      role: "user",
      content: text,
      timestamp: new Date().toLocaleTimeString(),
    };
    setMessages((m) => [...m, msg]);
    setInput("");
    setBusy(true);

    // Simulate assistant response based on keywords.
    const lower = text.toLowerCase();
    let response: ChatMessage;

    if (lower.includes("discover") || lower.includes("scan") || lower.includes("find target")) {
      response = {
        role: "assistant",
        content: "I can scan your project for fuzzing targets. Use the Discover panel to select a project folder, or tell me the path and I'll scan it for C/C++ functions worth fuzzing.",
        timestamp: new Date().toLocaleTimeString(),
        actions: [{ label: "Go to Discover", icon: "crosshair" }],
      };
    } else if (lower.includes("run") || lower.includes("fuzz")) {
      response = {
        role: "assistant",
        content: "Ready to run a fuzz campaign. I'll compile a harness in the sandbox and drive the engine. Head to the Run panel, or tell me the target symbol and engine.",
        timestamp: new Date().toLocaleTimeString(),
        actions: [{ label: "Go to Run", icon: "play" }],
      };
    } else if (lower.includes("crash") || lower.includes("triage")) {
      response = {
        role: "assistant",
        content: "I can triage crash artifacts from your fuzz runs. Go to the Triage panel to scan the output directory and classify crashes by stack signature.",
        timestamp: new Date().toLocaleTimeString(),
        actions: [{ label: "Go to Triage", icon: "bug" }],
      };
    } else if (lower.includes("corpus")) {
      response = {
        role: "assistant",
        content: "The corpus panel lets you seed, grow, prune, and inspect your fuzzing corpus. You can also merge corpora across engines.",
        timestamp: new Date().toLocaleTimeString(),
        actions: [{ label: "Go to Corpus", icon: "database" }],
      };
    } else if (lower.includes("help") || lower.includes("what can you")) {
      response = {
        role: "assistant",
        content: "I'm the hobot_fuzz AI assistant. I can help you:\n\n- Discover fuzzing targets in a C/C++ project\n- Generate and compile fuzz harnesses\n- Run AFL++, honggfuzz, or libFuzzer in a sandbox\n- Triage crashes and draft bug reports\n- Manage your fuzzing corpus\n\nAsk me about any of these, or use the sidebar to navigate directly.",
        timestamp: new Date().toLocaleTimeString(),
      };
    } else {
      response = {
        role: "assistant",
        content: `I understood: "${text}". I'm a fuzzing assistant -- try asking me to "discover targets", "run a fuzzer", "triage crashes", or "manage corpus". You can also use the sidebar panels for direct access.`,
        timestamp: new Date().toLocaleTimeString(),
      };
    }

    setTimeout(() => {
      setMessages((m) => [...m, response]);
      setBusy(false);
    }, 400 + Math.random() * 600);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
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

  return (
    <div className="flex flex-col h-full" style={{ animation: "fadeIn 0.2s ease" }}>
      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-1" style={{ paddingBottom: "var(--space-md)" }}>
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center" style={{ padding: "var(--space-xl) var(--space-md)" }}>
            <div
              className="flex items-center justify-center mb-4 rounded-full"
              style={{
                width: "56px",
                height: "56px",
                background: "var(--accent-subtle)",
                border: "1px solid var(--border)",
              }}
            >
              <Crosshair size={28} style={{ color: "var(--accent)" }} />
            </div>
            <h2 className="text-base font-semibold mb-1">hobot_fuzz AI Assistant</h2>
            <p className="text-sm text-text-secondary max-w-md">
              Ask me to discover fuzzing targets, generate harnesses, run fuzzers, triage crashes, or manage your corpus.
            </p>
            <div className="flex flex-wrap gap-2 mt-4 justify-center max-w-lg">
              {["Discover targets", "Run a fuzzer", "Triage crashes", "Manage corpus"].map((s) => (
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
          <div className="flex gap-2 items-center text-text-muted text-sm" style={{ padding: "var(--space-sm) var(--space-md)" }}>
            <Loader2 size={14} className="animate-spin" />
            <span>Thinking...</span>
          </div>
        )}
      </div>

      {/* Input area */}
      <div
        className="flex items-end gap-2"
        style={{
          padding: "var(--space-sm) var(--space-md)",
          borderTop: "1px solid var(--border)",
          background: "var(--surface-primary)",
        }}
      >
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Ask about discovering targets, running fuzzers, triaging crashes..."
          rows={1}
          className="flex-1 text-sm bg-surface-secondary border border-solid border-border rounded-md text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150 resize-none"
          style={{
            padding: "var(--space-sm) var(--space-md)",
            fontFamily: "var(--font-sans)",
            lineHeight: 1.5,
            minHeight: "36px",
            maxHeight: "120px",
          }}
        />
        <button
          onClick={send}
          disabled={!input.trim() || busy}
          className="inline-flex items-center justify-center rounded-md transition-all duration-150 outline-none disabled:opacity-55 disabled:cursor-not-allowed"
          style={{
            width: "36px",
            height: "36px",
            background: "var(--accent)",
            color: "var(--accent-contrast)",
            border: "none",
            flexShrink: 0,
          }}
          onMouseEnter={(e) => !busy && (e.currentTarget.style.opacity = "0.85")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
        >
          {busy ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
        </button>
      </div>
    </div>
  );
}