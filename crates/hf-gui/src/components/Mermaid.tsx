import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";

let initialized = false;
function ensureInit() {
  if (initialized) return;
  initialized = true;
  // The app is dark-themed; render diagrams to match. startOnLoad is off
  // because we render explicitly per block.
  mermaid.initialize({ startOnLoad: false, theme: "dark", securityLevel: "strict" });
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
    ensureInit();
    let alive = true;
    const id = `mmd-${(seq += 1)}`;
    mermaid
      .render(id, code)
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
