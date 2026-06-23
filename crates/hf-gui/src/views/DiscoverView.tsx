import { useState } from "react";
import { getTransport } from "../lib";
import type { TargetInventory } from "../types";
import { Crosshair } from "lucide-react";

export function DiscoverView() {
  const [project, setProject] = useState("");
  const [inventory, setInventory] = useState<TargetInventory | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function discover() {
    if (!project) return;
    setLoading(true);
    setError(null);
    try {
      const inv = await getTransport().invoke<TargetInventory>("discover", {
        project,
        lang: "c",
      });
      setInventory(inv);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-bold">Target Discovery</h1>
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="/path/to/project"
          value={project}
          onChange={(e) => setProject(e.target.value)}
          className="flex-1 px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        />
        <button
          onClick={discover}
          disabled={loading}
          className="px-4 py-2 bg-accent text-surface-tertiary rounded-DEFAULT hover:bg-accent-hover disabled:opacity-50"
        >
          {loading ? "Scanning..." : "Discover"}
        </button>
      </div>
      {error && <p className="text-error">{error}</p>}
      {inventory && (
        <div className="flex flex-col gap-2">
          <p className="text-text-secondary">{inventory.candidates.length} candidates found</p>
          <div className="flex flex-col gap-1">
            {inventory.candidates
              .sort((a, b) => b.fit_score - a.fit_score)
              .map((c) => (
                <div
                  key={c.id}
                  className="surface-card p-3 flex items-center gap-3"
                >
                  <Crosshair size={16} className="text-accent shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm">{c.symbol}</span>
                      <span className="text-xs text-text-muted">{c.kind}</span>
                    </div>
                    <div className="text-xs text-text-muted truncate">
                      {c.location.file}:{c.location.line}
                    </div>
                    {c.rationale && (
                      <div className="text-xs text-text-secondary mt-1">{c.rationale}</div>
                    )}
                  </div>
                  <span className="text-sm font-mono text-accent">
                    {c.fit_score.toFixed(3)}
                  </span>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}