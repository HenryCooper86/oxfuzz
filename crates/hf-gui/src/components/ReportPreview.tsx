import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { X, Download, Copy, Check } from "lucide-react";
import { Button } from "./ui";
import { Mermaid } from "./Mermaid";

/**
 * Extract the language + text from a react-markdown `code` node so fenced
 * ```mermaid blocks can be rendered as diagrams and everything else as code.
 */
export function codeInfo(className: unknown, children: unknown): { lang: string; text: string } {
  const lang = typeof className === "string" ? (/language-(\w+)/.exec(className)?.[1] ?? "") : "";
  const text = String(children ?? "").replace(/\n$/, "");
  return { lang, text };
}

/**
 * A modal that renders a Markdown report (GFM tables + Mermaid graphs) with
 * Download and Copy actions. The rendered Markdown mirrors what the user gets
 * in any external Markdown tool, so the preview is faithful.
 */
export function ReportPreview({
  markdown,
  onClose,
  onDownload,
}: {
  markdown: string;
  onClose: () => void;
  onDownload: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  };

  return (
    <div
      className="fixed inset-0 z-9999 flex items-center justify-center"
      style={{ background: "rgba(0,0,0,0.55)", backdropFilter: "blur(3px)", WebkitBackdropFilter: "blur(3px)" }}
      onClick={onClose}
    >
      <div
        className="surface-card flex flex-col"
        style={{
          width: "min(900px, 92vw)",
          height: "min(88vh, 900px)",
          padding: 0,
          boxShadow: "var(--shadow-lg)",
          animation: "dialogContentIn 0.16s ease",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between border-b border-solid border-border"
          style={{ padding: "var(--space-md)" }}
        >
          <span className="text-sm font-semibold">Fuzzing Report</span>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={copy} title="Copy Markdown">
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? "Copied" : "Copy"}
            </Button>
            <Button variant="outline" size="sm" onClick={onDownload} title="Download .md">
              <Download size={14} />
              Download
            </Button>
            <button onClick={onClose} className="hf-action-btn" title="Close">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Rendered Markdown */}
        <div className="markdown-body flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              code({ className, children, ...props }) {
                const { lang, text } = codeInfo(className, children);
                if (lang === "mermaid") return <Mermaid code={text} />;
                return (
                  <code className={typeof className === "string" ? className : undefined} {...props}>
                    {children}
                  </code>
                );
              },
            }}
          >
            {markdown}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  );
}
