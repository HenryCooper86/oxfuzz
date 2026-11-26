import { lineDiff } from "../lib/diff";

// A line-level diff of two text blobs, added/removed lines highlighted.
export function DiffView({ oldText, newText }: { oldText: string; newText: string }) {
  const diff = lineDiff(oldText, newText);
  return (
    <pre
      className="text-xs p-3 rounded-md overflow-auto"
      style={{ background: "var(--surface-code)", border: "1px solid var(--border)", fontFamily: "var(--font-mono)", lineHeight: 1.5, maxHeight: "60vh", margin: 0 }}
    >
      {diff.map((d, i) => (
        <div
          key={i}
          style={{
            background: d.type === "add" ? "var(--success-subtle)" : d.type === "del" ? "var(--error-subtle)" : "transparent",
            color: d.type === "add" ? "var(--success)" : d.type === "del" ? "var(--error)" : "var(--text-secondary)",
            whiteSpace: "pre-wrap",
          }}
        >
          {d.type === "add" ? "+ " : d.type === "del" ? "- " : "  "}
          {d.text}
        </div>
      ))}
    </pre>
  );
}
