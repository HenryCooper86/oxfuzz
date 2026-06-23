import { useState } from "react";
import { Check, Copy } from "lucide-react";

interface CodeBlockProps {
  code: string;
  maxHeight?: string;
  showCopy?: boolean;
}

export function CodeBlock({ code, maxHeight = "16rem", showCopy = true }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <div className="relative rounded-md overflow-hidden" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
      {showCopy && (
        <button
          onClick={copy}
          className="absolute top-2 right-2 p-1 rounded-sm transition-colors duration-150"
          style={{ background: "var(--surface-active)", color: "var(--text-muted)", border: "none", cursor: "pointer" }}
          title="Copy"
        >
          {copied ? <Check size={12} style={{ color: "var(--success)" }} /> : <Copy size={12} />}
        </button>
      )}
      <pre className="text-xs p-3 overflow-auto" style={{ fontFamily: "var(--font-mono)", lineHeight: 1.5, color: "var(--text-secondary)", maxHeight }}>
        <code>{code}</code>
      </pre>
    </div>
  );
}