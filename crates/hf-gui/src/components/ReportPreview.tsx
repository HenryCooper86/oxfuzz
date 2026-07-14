import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { X, Download, Copy, Check, ChevronDown } from "lucide-react";
import { Button } from "./ui";
import { Mermaid } from "./Mermaid";
import { useListboxNav } from "../hooks/useListboxNav";
import { useI18n } from "../i18n";

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
const FORMAT_LABELS: Record<string, string> = {
  md: "Markdown (.md)",
  html: "HTML (.html)",
  pdf: "PDF (.pdf)",
  docx: "Word (.docx)",
};

export function ReportPreview({
  markdown,
  onClose,
  onExport,
  formats,
}: {
  markdown: string;
  onClose: () => void;
  onExport: (format: string) => void;
  formats: string[];
}) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const { triggerRef, menuRef, onMenuKey, onTriggerKey } = useListboxNav(exportOpen, () => setExportOpen(false));

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
          <span className="text-sm font-semibold">{t("reportPreview.title")}</span>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={copy} title={t("reportPreview.copyMarkdown")}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? t("common.copied") : t("common.copy")}
            </Button>
            <div className="relative">
              <Button
                ref={triggerRef}
                variant="outline"
                size="sm"
                onClick={() => setExportOpen((o) => !o)}
                onKeyDown={(e) => onTriggerKey(e, () => setExportOpen(true))}
                aria-haspopup="listbox"
                aria-expanded={exportOpen}
                title={t("reportPreview.exportTitle")}
              >
                <Download size={14} />
                {t("common.export")}
                <ChevronDown size={13} style={{ opacity: 0.7 }} />
              </Button>
              {exportOpen && (
                <>
                  <div className="fixed inset-0" style={{ zIndex: 40 }} onClick={() => setExportOpen(false)} />
                  <div
                    ref={menuRef}
                    role="listbox"
                    onKeyDown={onMenuKey}
                    className="absolute right-0 mt-1 min-w-[170px] rounded-lg overflow-hidden"
                    style={{ background: "var(--surface-primary)", border: "1px solid var(--border)", boxShadow: "0 8px 24px rgba(0,0,0,0.3)", zIndex: 50 }}
                  >
                    {formats.map((f) => (
                      <button
                        key={f}
                        role="option"
                        aria-selected={false}
                        onClick={() => {
                          setExportOpen(false);
                          onExport(f);
                        }}
                        className="flex items-center w-full text-left transition-colors duration-150"
                        style={{ padding: "8px 12px", fontSize: "13px", background: "transparent", color: "var(--text-secondary)", border: "none", cursor: "pointer" }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
                        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                      >
                        {FORMAT_LABELS[f] ?? f.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
            <button onClick={onClose} className="hf-action-btn" title={t("common.close")} aria-label={t("common.close")}>
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
