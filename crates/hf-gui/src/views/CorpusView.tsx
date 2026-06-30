import { useCallback, useEffect, useState } from "react";
import { getTransport } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useTarget } from "../providers/TargetContext";
import type { CorpusEntry } from "../types";
import { Button } from "../components/ui";
import { Database, Plus, Scissors, Eye } from "lucide-react";

export function CorpusView({ embedded = false }: { embedded?: boolean }) {
  const { activeProject } = useProject();
  // The corpus belongs to a specific target's workspace -- the one seeded during
  // Harness and grown during Run -- so it must scan that target, not "".
  const { target } = useTarget();
  const [entries, setEntries] = useState<CorpusEntry[]>([]);
  const [loading, setLoading] = useState<string | null>(null);

  const action = useCallback(
    async (op: string) => {
      setLoading(op);
      try {
        const project = activeProject || ".";
        if (op !== "corpus_list") {
          await getTransport().invoke(op, { project, target });
        }
        const result = await getTransport().invoke<CorpusEntry[]>("corpus_list", {
          project,
          target,
        });
        setEntries(result);
      } catch {
        setEntries([]);
      } finally {
        setLoading(null);
      }
    },
    [activeProject, target],
  );

  // Auto-load the corpus for the current target so it reflects what the flow
  // actually used (seeds + fuzzer-grown inputs), without a manual List click.
  // Direct async load (no synchronous setState in the effect body).
  useEffect(() => {
    if (!activeProject || !target) return;
    let cancelled = false;
    (async () => {
      try {
        const result = await getTransport().invoke<CorpusEntry[]>("corpus_list", {
          project: activeProject,
          target,
        });
        if (!cancelled) setEntries(result);
      } catch {
        if (!cancelled) setEntries([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeProject, target]);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        {embedded ? (
          <span />
        ) : (
          <div>
            <h1 className="text-xl font-semibold">Corpus Management</h1>
            <p className="text-sm text-text-secondary mt-0.5">
              Seed, grow, prune, and inspect the fuzzing corpus.
            </p>
          </div>
        )}
        <div className="flex gap-2">
          <ActionButton icon={<Plus size={14} />} label="Seed" loading={loading === "corpus_seed"} onClick={() => action("corpus_seed")} />
          <ActionButton icon={<Eye size={14} />} label="Grow" loading={loading === "corpus_grow"} onClick={() => action("corpus_grow")} />
          <ActionButton icon={<Scissors size={14} />} label="Prune" loading={loading === "corpus_prune"} onClick={() => action("corpus_prune")} />
          <ActionButton icon={<Database size={14} />} label="List" loading={loading === "corpus_list"} onClick={() => action("corpus_list")} />
        </div>
      </div>

      {entries.length === 0 && !loading && (
        <div
          className="surface-card flex flex-col items-center justify-center"
          style={{ padding: "var(--space-xl) var(--space-md)", textAlign: "center" }}
        >
          <Database size={32} className="text-text-muted mb-3" style={{ opacity: 0.4 }} />
          {target ? (
            <>
              <p className="text-sm text-text-muted">
                Corpus for <span style={{ fontFamily: "var(--font-mono)" }}>{target}</span> is empty.
              </p>
              <p className="text-xs text-text-muted mt-1">
                Click "Seed" for default inputs, or run the fuzzer — it grows the corpus as it finds new coverage.
              </p>
            </>
          ) : (
            <>
              <p className="text-sm text-text-muted">No target selected.</p>
              <p className="text-xs text-text-muted mt-1">
                Pick a target in Harness (or run the flow) to view and manage its corpus.
              </p>
            </>
          )}
        </div>
      )}

      {entries.length > 0 && (
        <div className="surface-card overflow-hidden" style={{ animation: "slideInUp 0.2s ease" }}>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left text-xs text-text-muted uppercase px-3 py-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
                  File
                </th>
                <th className="text-left text-xs text-text-muted uppercase px-3 py-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
                  SHA256
                </th>
                <th className="text-left text-xs text-text-muted uppercase px-3 py-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
                  Source
                </th>
                <th className="text-right text-xs text-text-muted uppercase px-3 py-2" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
                  Size
                </th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i} className="border-b border-border transition-colors duration-100 hover:bg-surface-hover">
                  <td className="px-3 py-2 font-mono text-xs text-text-primary">{e.path.split("/").pop()}</td>
                  <td className="px-3 py-2 font-mono text-xs text-text-muted">{e.sha256.slice(0, 16)}...</td>
                  <td className="px-3 py-2 text-xs text-text-secondary">{e.source}</td>
                  <td className="px-3 py-2 text-right text-xs text-text-secondary">{e.size}b</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ActionButton({ icon, label, loading, onClick }: { icon: React.ReactNode; label: string; loading: boolean; onClick: () => void }) {
  return (
    <Button variant="outline" size="sm" onClick={onClick} loading={loading}>
      {!loading && icon}
      {label}
    </Button>
  );
}