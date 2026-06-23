import { useState } from "react";
import { getTransport } from "../lib";
import type { CorpusEntry } from "../types";

export function CorpusView() {
  const [entries, setEntries] = useState<CorpusEntry[]>([]);
  const [loading, setLoading] = useState(false);

  async function loadCorpus() {
    setLoading(true);
    try {
      const result = await getTransport().invoke<CorpusEntry[]>("corpus_list", {
        project: ".",
        target: "",
      });
      setEntries(result);
    } catch {
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Corpus</h1>
        <button
          onClick={loadCorpus}
          disabled={loading}
          className="px-4 py-2 bg-accent text-surface-tertiary rounded-DEFAULT hover:bg-accent-hover disabled:opacity-50"
        >
          {loading ? "Loading..." : "List"}
        </button>
      </div>
      {entries.length === 0 ? (
        <p className="text-text-muted">Corpus is empty. Seed it first.</p>
      ) : (
        <table className="surface-card w-full text-sm">
          <thead>
            <tr className="border-b border-border text-text-muted">
              <th className="text-left p-2">File</th>
              <th className="text-left p-2">SHA256</th>
              <th className="text-right p-2">Size</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i} className="border-b border-border">
                <td className="p-2 font-mono">{e.path.split("/").pop()}</td>
                <td className="p-2 font-mono text-text-muted">{e.sha256.slice(0, 16)}...</td>
                <td className="p-2 text-right">{e.size}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}