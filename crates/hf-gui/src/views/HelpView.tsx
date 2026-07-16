import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { BookOpen, Gitlab, LifeBuoy, Search } from "lucide-react";
import { Button, ViewHeader } from "../components/ui";
import { Mermaid } from "../components/Mermaid";
import { codeInfo } from "../lib/reportPreviewCode";
import {
  GETTING_STARTED_GUIDE_URL,
  PROJECT_REPOSITORY_URL,
} from "../lib/projectLinks";
import { openExternal } from "../lib";
import { useI18n } from "../i18nContext";
import { HELP_GROUPS, HELP_SECTIONS, type HelpSection } from "./help/helpContent";
import { HELP_GROUPS_ZH, HELP_SECTIONS_ZH } from "./help/helpContent.zh";

/** Case-insensitive match of a query against a section's title, keywords, body. */
function matches(section: HelpSection, query: string): boolean {
  if (!query) return true;
  const haystack = `${section.title} ${section.keywords ?? ""} ${section.body}`.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((term) => haystack.includes(term));
}

/**
 * In-app usage documentation. Fully self-contained: the content lives in
 * `help/helpContent.ts` and renders with the same Markdown pipeline as the
 * report preview, so it needs no backend and works in both desktop and web modes.
 */
export function HelpView() {
  const { locale } = useI18n();
  const zh = locale === "zh";
  const L = (en: string, cn: string) => (zh ? cn : en);
  const sections = zh ? HELP_SECTIONS_ZH : HELP_SECTIONS;
  const groupDefs = zh ? HELP_GROUPS_ZH : HELP_GROUPS;
  const [query, setQuery] = useState("");
  const [activeId, setActiveId] = useState<string>(sections[0].id);

  const visible = useMemo(
    () => sections.filter((s) => matches(s, query)),
    [sections, query],
  );

  // Keep a valid selection: if the search hides the active section, fall back to
  // the first visible one so the content pane never goes blank mid-search.
  const active =
    visible.find((s) => s.id === activeId) ?? visible[0] ?? null;

  const groups = groupDefs.map((g) => ({
    ...g,
    sections: visible.filter((s) => s.group === g.id),
  })).filter((g) => g.sections.length > 0);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <ViewHeader
          title={L("Help & Documentation", "帮助与文档")}
          description={L(
            "How to use the hobot_fuzz desktop app, screen by screen. Everything here works offline.",
            "如何逐屏使用 hobot_fuzz 桌面应用。此处内容均可离线查看。",
          )}
        />
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void openExternal(GETTING_STARTED_GUIDE_URL)} title={L("Open the getting-started guide", "打开入门指南")}>
            <LifeBuoy size={14} /> {L("Getting Started", "入门")}
          </Button>
          <Button variant="outline" size="sm" onClick={() => void openExternal(PROJECT_REPOSITORY_URL)} title={L("Open the GitLab repository", "打开 GitLab 仓库")}>
            <Gitlab size={14} /> GitLab
          </Button>
        </div>
      </div>

      <div className="flex gap-4 min-w-0" style={{ alignItems: "flex-start" }}>
        {/* Left rail: search + grouped table of contents */}
        <nav
          className="surface-card flex flex-col gap-2 shrink-0"
          style={{ width: 260, padding: "var(--space-md)", position: "sticky", top: 0, maxHeight: "calc(100vh - 160px)", overflow: "auto" }}
          aria-label={L("Documentation sections", "文档章节")}
        >
          <div className="flex items-center gap-2 rounded-md" style={{ padding: "6px 8px", background: "var(--surface-secondary)", border: "1px solid var(--border)" }}>
            <Search size={14} className="text-text-muted shrink-0" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={L("Search the docs...", "搜索文档…")}
              className="flex-1 bg-transparent outline-none text-sm text-text-primary min-w-0"
              style={{ border: "none" }}
              aria-label={L("Search documentation", "搜索文档")}
            />
          </div>

          {groups.length === 0 ? (
            <p className="text-xs text-text-muted" style={{ padding: "8px 4px" }}>{L(`No topics match "${query}".`, `没有匹配“${query}”的主题。`)}</p>
          ) : (
            groups.map((group) => (
              <div key={group.id} className="flex flex-col gap-0.5">
                <span
                  className="text-xs font-semibold uppercase"
                  style={{ color: "var(--text-muted)", letterSpacing: "0.08em", padding: "8px 6px 2px" }}
                >
                  {group.title}
                </span>
                {group.sections.map((section) => {
                  const isActive = active?.id === section.id;
                  return (
                    <button
                      key={section.id}
                      onClick={() => setActiveId(section.id)}
                      className={`text-left rounded-md transition-colors ${
                        isActive
                          ? "bg-surface-active text-text-primary"
                          : "bg-transparent text-text-secondary hover:bg-surface-hover hover:text-text-primary"
                      }`}
                      style={{ padding: "6px 8px", fontSize: 13, border: "none", cursor: "pointer" }}
                      aria-current={isActive ? "page" : undefined}
                    >
                      {section.title}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </nav>

        {/* Right pane: rendered Markdown for the active section */}
        <section className="surface-card markdown-body flex-1 min-w-0" style={{ padding: "var(--space-lg)", minHeight: 400 }}>
          {active ? (
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
              {active.body}
            </ReactMarkdown>
          ) : (
            <p className="text-sm text-text-muted">{L("Select a topic to read it here.", "选择一个主题以在此阅读。")}</p>
          )}
          <div className="flex items-center gap-3 mt-6 pt-4" style={{ borderTop: "1px solid var(--border)" }}>
            <BookOpen size={14} className="text-text-muted" />
            <span className="text-xs text-text-muted">
              {L("Looking for the deep-dive design docs? See the ", "想查看深入的设计文档？请访问")}
              <button
                onClick={() => void openExternal(PROJECT_REPOSITORY_URL)}
                style={{ background: "none", border: "none", padding: 0, color: "var(--accent)", cursor: "pointer" }}
              >
                {L("project repository", "项目仓库")}
              </button>
              {L(".", "。")}
            </span>
          </div>
        </section>
      </div>
    </div>
  );
}
