import { useEffect, useRef, useState } from "react";

type MermaidApi = (typeof import("mermaid"))["default"];

let mermaidPromise: Promise<MermaidApi> | null = null;

function loadMermaid(): Promise<MermaidApi> {
  if (!mermaidPromise) {
    mermaidPromise = import("mermaid").then(({ default: mermaid }) => {
      // Render explicitly per block and keep generated SVG isolated from
      // executable page content.
      mermaid.initialize({ startOnLoad: false, theme: "dark", securityLevel: "strict" });
      return mermaid;
    });
  }
  return mermaidPromise;
}

let seq = 0;

/**
 * Render a single Mermaid diagram from its source. Falls back to showing the
 * raw source in a code block if the diagram fails to parse, so a malformed
 * graph never blanks the report.
 */
export function Mermaid({ code }: { code: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let alive = true;
    const id = `mmd-${(seq += 1)}`;
    void loadMermaid()
      .then((mermaid) => mermaid.render(id, code))
      .then(({ svg }) => {
        if (alive && ref.current) {
          ref.current.innerHTML = svg;
          setError(false);
        }
      })
      .catch(() => {
        if (alive) setError(true);
      });
    return () => {
      alive = false;
    };
  }, [code]);

  if (error) {
    return (
      <pre className="text-xs overflow-auto surface-card" style={{ padding: "var(--space-md)" }}>
        <code>{code}</code>
      </pre>
    );
  }
  return <div ref={ref} className="flex justify-center my-3" style={{ overflowX: "auto" }} />;
}
