import { useState } from "react";
import { getTransport } from "../lib";
import type { CorpusEntry } from "../types";
import { Database, Loader2, Plus, Scissors, Eye } from "lucide-react";

export function CorpusView() {
  const [entries, setEntries] = useState<CorpusEntry[]>([]);
  const [loading, setLoading] = useState<string | null>(null);

  async function action(op: string) {
    setLoading(op);
    try {
      if (op === "list") {
        const result = await getTransport().invoke<CorpusEntry[]>("corpus_list", {
          project: ".",
          target: "",
        });
        setEntries(result);
      } else {
        await getTransport().invoke(op, { project: ".", target: "" });
        const result = await getTransport().invoke<CorpusEntry[]>("corpus_list", {
          project: ".",
          target: "",
        });
        setEntries(result);
      }
    } catch {
      setEntries([]);
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Corpus Management</h1>
          <p className="text-sm text-text-secondary mt-0.5">
            Seed, grow, prune, and inspect the fuzzing corpus.
          </p>
        </div>
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
          <p className="text-sm text-text-muted">Corpus is empty.</p>
          <p className="text-xs text-text-muted mt-1">Click "Seed" to add default seed inputs.</p>
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
    <button
      onClick={onClick}
      disabled={loading}
      className="inline-flex items-center justify-center gap-1 px-3 py-1.5 text-xs font-medium rounded-md border border-solid border-border bg-surface-primary text-text-secondary transition-all duration-150 outline-none hover:bg-surface-hover hover:text-text-primary disabled:opacity-55"
    >
      {loading ? <Loader2 size={14} className="animate-spin" /> : icon}
      {label}
    </button>
  );
}