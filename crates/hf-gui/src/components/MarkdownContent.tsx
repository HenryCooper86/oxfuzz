import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

// Model output is untrusted. Raw HTML is dropped (skipHtml, no rehype-raw), and
// the app has no safe external-open path, so links render as text with their
// destination visible, and images render as their alt text (no remote loads).
const components: Components = {
  a: ({ href, children }) => (
    <span style={{ color: "var(--accent)" }}>
      {children}
      {href ? <span className="text-text-muted"> ({href})</span> : null}
    </span>
  ),
  img: ({ alt }) => <span className="text-text-muted">{alt}</span>,
  p: ({ children }) => <p style={{ margin: "0 0 0.5em" }}>{children}</p>,
  ul: ({ children }) => <ul style={{ margin: "0 0 0.5em", paddingLeft: "1.4em", listStyle: "disc" }}>{children}</ul>,
  ol: ({ children }) => <ol style={{ margin: "0 0 0.5em", paddingLeft: "1.4em", listStyle: "decimal" }}>{children}</ol>,
  h1: ({ children }) => <h3 style={{ fontSize: "1.1em", fontWeight: 600, margin: "0.6em 0 0.3em" }}>{children}</h3>,
  h2: ({ children }) => <h3 style={{ fontSize: "1.05em", fontWeight: 600, margin: "0.6em 0 0.3em" }}>{children}</h3>,
  h3: ({ children }) => <h4 style={{ fontWeight: 600, margin: "0.5em 0 0.3em" }}>{children}</h4>,
  blockquote: ({ children }) => (
    <blockquote style={{ margin: "0 0 0.5em", paddingLeft: "0.8em", borderLeft: "3px solid var(--border)", color: "var(--text-secondary)" }}>
      {children}
    </blockquote>
  ),
  pre: ({ children }) => (
    <pre
      style={{
        margin: "0 0 0.5em",
        padding: "8px 10px",
        overflowX: "auto",
        background: "var(--surface-active)",
        border: "1px solid var(--border)",
        borderRadius: "6px",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        lineHeight: 1.45,
      }}
    >
      {children}
    </pre>
  ),
  code: ({ children, className }) => (
    <code
      className={className}
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "0.92em",
        // Block code sits in <pre> (language class or newline); inline gets a chip.
        ...(className || String(children).includes("\n")
          ? {}
          : { background: "var(--surface-active)", borderRadius: "4px", padding: "1px 4px" }),
      }}
    >
      {children}
    </code>
  ),
  // Cells wrap only between words: the container's overflow-wrap:anywhere
  // would let a table column shrink to one character. A table wider than the
  // message scrolls sideways in its wrapper instead.
  table: ({ children }) => (
    <div style={{ overflowX: "auto", margin: "0 0 0.5em" }}>
      <table style={{ borderCollapse: "collapse", fontSize: "0.95em" }}>{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th
      style={{
        border: "1px solid var(--border)",
        padding: "4px 8px",
        textAlign: "left",
        background: "var(--surface-active)",
        fontWeight: 600,
        overflowWrap: "normal",
      }}
    >
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td style={{ border: "1px solid var(--border)", padding: "4px 8px", overflowWrap: "normal" }}>{children}</td>
  ),
};

/** Safe Markdown (GFM) rendering for assistant messages. */
export function MarkdownContent({ text }: { text: string }) {
  return (
    <div className="text-sm text-text-primary" style={{ lineHeight: 1.5, overflowWrap: "anywhere" }}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={components}>
        {text}
      </ReactMarkdown>
    </div>
  );
}
