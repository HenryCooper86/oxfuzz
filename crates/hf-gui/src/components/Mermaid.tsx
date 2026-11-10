import { useEffect, useState } from "react";
import { usePrefs } from "../providers/prefs";

type MermaidApi = (typeof import("mermaid"))["default"];

let mermaidPromise: Promise<MermaidApi> | null = null;

function loadMermaid(): Promise<MermaidApi> {
  if (!mermaidPromise) {
    mermaidPromise = import("mermaid").then(({ default: mermaid }) => mermaid);
  }
  return mermaidPromise;
}

// Mermaid configuration is global; configure and render each diagram together.
let renderQueue = Promise.resolve();
let seq = 0;

/**
 * Render a single Mermaid diagram from its source. Falls back to showing the
 * raw source in a code block if the diagram fails to parse, so a malformed
 * graph never blanks the report.
 */
export function Mermaid({ code }: { code: string }) {
  const { resolvedTheme } = usePrefs();
  const [result, setResult] = useState<{ code: string; theme: string; svg: string | null } | null>(null);

  useEffect(() => {
    let alive = true;
    const id = `mmd-${(seq += 1)}`;
    renderQueue = renderQueue.then(async () => {
      const mermaid = await loadMermaid();
      if (!alive) return;
      mermaid.initialize({ startOnLoad: false, theme: resolvedTheme === "dark" ? "dark" : "default", securityLevel: "strict" });
      const { svg } = await mermaid.render(id, code);
      if (alive) setResult({ code, theme: resolvedTheme, svg });
    }).catch(() => {
      // Invalid diagrams retain their source instead of breaking the report.
      if (alive) setResult({ code, theme: resolvedTheme, svg: null });
    });
    return () => {
      alive = false;
    };
  }, [code, resolvedTheme]);

  const current = result?.code === code && result.theme === resolvedTheme ? result : null;
  if (current?.svg === null) {
    return (
      <pre className="text-xs overflow-auto surface-card" style={{ padding: "var(--space-md)" }}>
        <code>{code}</code>
      </pre>
    );
  }
  return <div className="flex justify-center my-3" style={{ overflowX: "auto" }} dangerouslySetInnerHTML={{ __html: current?.svg ?? "" }} />;
}
