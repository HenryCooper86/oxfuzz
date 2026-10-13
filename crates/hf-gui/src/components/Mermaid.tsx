import { useEffect, useState } from "react";

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
  const [result, setResult] = useState<{ code: string; svg: string | null } | null>(null);

  useEffect(() => {
    let alive = true;
    const id = `mmd-${(seq += 1)}`;
    void loadMermaid()
      .then(async (mermaid) => {
        if (!alive) return;
        const { svg } = await mermaid.render(id, code);
        if (alive) setResult({ code, svg });
      })
      .catch(() => {
        if (alive) setResult({ code, svg: null });
      });
    return () => {
      alive = false;
    };
  }, [code]);

  const current = result?.code === code ? result : null;
  if (current?.svg === null) {
    return (
      <pre className="text-xs overflow-auto surface-card" style={{ padding: "var(--space-md)" }}>
        <code>{code}</code>
      </pre>
    );
  }
  return <div className="flex justify-center my-3" style={{ overflowX: "auto" }} dangerouslySetInnerHTML={{ __html: current?.svg ?? "" }} />;
}
