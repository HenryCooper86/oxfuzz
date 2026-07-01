import { useState } from "react";
import { getTransport } from "../lib";
import type { Crash, CorpusEntry } from "../types";
import { Button, ViewHeader } from "../components/ui";
import { Bug, Database, RefreshCw, FileWarning } from "lucide-react";

export function ArtifactsView() {
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [corpus, setCorpus] = useState<CorpusEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanned, setScanned] = useState(false);

  async function scan() {
    setLoading(true);
    const t = getTransport();
    try {
      // Browse-all view: read persisted artifacts from the store across every
      // target/run. Re-triaging with an empty target scans the wrong per-target
      // workspace dir and always comes back empty, so crashes never showed up
      // here even after a run produced them.
      const [c, k] = await Promise.all([
        t.invoke<Crash[]>("all_crashes").catch(() => [] as Crash[]),
        t.invoke<CorpusEntry[]>("all_corpus").catch(() => [] as CorpusEntry[]),
      ]);
      setCrashes(c);
      setCorpus(k);
    } finally {
      setScanned(true);
      setLoading(false);
    }
  }

  const empty = scanned && crashes.length === 0 && corpus.length === 0;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <ViewHeader title="Artifacts" description="Crash reproducers and corpus inputs from your fuzz runs." />
        <Button variant="primary" onClick={scan} loading={loading}>
          {!loading && <RefreshCw size={14} />}
          {loading ? "Scanning..." : "Scan"}
        </Button>
      </div>

      {!scanned && !loading && (
        <div
          className="surface-card flex flex-col items-center justify-center"
          style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}
        >
          <FileWarning size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} />
          <p className="text-sm text-text-muted">Scan to collect crash and corpus artifacts.</p>
        </div>
      )}

      {empty && (
        <div
          className="surface-card flex flex-col items-center justify-center"
          style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}
        >
          <FileWarning size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} />
          <p className="text-sm text-text-muted">No artifacts found.</p>
          <p className="text-xs text-text-muted mt-1">Run a fuzz campaign first, then scan.</p>
        </div>
      )}

      {crashes.length > 0 && (
        <Section icon={<Bug size={15} style={{ color: "var(--error)" }} />} title="Crashes" count={crashes.length}>
          {crashes.map((c) => (
            <div
              key={c.id}
              className="surface-card flex items-center gap-3"
              style={{ padding: "var(--space-sm) var(--space-md)" }}
            >
              <Bug size={14} style={{ color: "var(--error)", flexShrink: 0 }} />
              <span
                className="text-xs px-2 py-0.5 rounded-sm font-medium"
                style={{ background: "var(--error-subtle)", color: "var(--error)" }}
              >
                {c.kind || "crash"}
              </span>
              <span className="text-xs font-mono text-text-secondary truncate flex-1">
                {c.input_path.split("/").pop()}
              </span>
              {c.minimized && <span className="text-xs text-text-muted">minimized</span>}
            </div>
          ))}
        </Section>
      )}

      {corpus.length > 0 && (
        <Section icon={<Database size={15} style={{ color: "var(--accent)" }} />} title="Corpus" count={corpus.length}>
          {corpus.map((e) => (
            <div
              key={e.sha256}
              className="surface-card flex items-center gap-3"
              style={{ padding: "var(--space-sm) var(--space-md)" }}
            >
              <Database size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
              <span className="text-xs font-mono text-text-secondary truncate flex-1">
                {e.path.split("/").pop()}
              </span>
              <span className="text-xs text-text-muted">{e.size} B</span>
              <span className="text-xs text-text-muted">{e.source}</span>
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({
  icon,
  title,
  count,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2">
        {icon}
        <h2 className="text-sm font-semibold">{title}</h2>
        <span className="text-xs text-text-muted">{count}</span>
      </div>
      {children}
    </div>
  );
}
