import { useCallback, useEffect, useState } from "react";
import { getTransport, onDataChanged } from "../lib";
import { useConfirm } from "../providers/ConfirmContext";
import { PathActions } from "../components/PathActions";
import { useProject } from "../providers/ProjectContext";
import { useTarget } from "../providers/TargetContext";
import type { CorpusEntry } from "../types";
import { Button, ViewHeader } from "../components/ui";
import { Database, Plus, Scissors, Sprout, Sparkles } from "lucide-react";

export function CorpusView({ embedded = false }: { embedded?: boolean }) {
  const { activeProject } = useProject();
  const confirm = useConfirm();
  // The corpus belongs to a specific target's workspace -- the one seeded during
  // Harness and grown during Run -- so it must scan that target, not "".
  const { target, lang } = useTarget();
  const [entries, setEntries] = useState<CorpusEntry[]>([]);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refreshList = useCallback(
    async (project: string) => {
      const result = await getTransport().invoke<CorpusEntry[]>("corpus_list", {
        project,
        target,
      });
      setEntries(result);
    },
    [target],
  );

  const action = useCallback(
    async (op: string) => {
      if (op === "corpus_prune") {
        if (!(await confirm({ title: "Prune corpus", message: "Prune removes redundant-coverage entries from the corpus. Continue?", confirmLabel: "Prune" }))) {
          return;
        }
      }
      setLoading(op);
      setError(null);
      setNotice(null);
      try {
        const project = activeProject || ".";
        if (op !== "corpus_list") {
          await getTransport().invoke(op, { project, target });
        }
        await refreshList(project);
      } catch (e) {
        // Surface the failure instead of blanking the table (which reads as
        // "empty corpus" and hides the real error).
        setError(String(e));
      } finally {
        setLoading(null);
      }
    },
    [activeProject, target, refreshList, confirm],
  );

  // AI seed generation: the LLM (or heuristic fallback) synthesizes valid inputs
  // for the target, persisted as tracked corpus entries.
  const generateAi = useCallback(async () => {
    setLoading("generate_seeds_llm");
    setError(null);
    setNotice(null);
    try {
      const project = activeProject || ".";
      const res = await getTransport().invoke<{ seeds: { name: string }[] }>(
        "generate_seeds_llm",
        { project, target, lang: lang || "c", count: 12 },
      );
      const n = res?.seeds?.length ?? 0;
      setNotice(`Generated ${n} AI seed${n === 1 ? "" : "s"}.`);
      await refreshList(project);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(null);
    }
  }, [activeProject, target, lang, refreshList]);

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
        if (!cancelled) {
          setEntries(result);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeProject, target]);

  // Refetch when the workspace is cleared elsewhere so the table doesn't show
  // corpus rows whose files were just deleted.
  useEffect(() => {
    if (!activeProject || !target) return undefined;
    return onDataChanged(() => {
      void refreshList(activeProject).catch(() => setEntries([]));
    });
  }, [activeProject, target, refreshList]);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        {embedded ? (
          <span />
        ) : (
          <ViewHeader
            title="Corpus Management"
            description="Seed, grow, prune, and inspect the fuzzing corpus."
          />
        )}
        <div className="flex gap-2">
          <ActionButton icon={<Sparkles size={14} />} label="Generate with AI" loading={loading === "generate_seeds_llm"} disabled={!target} onClick={generateAi} />
          <ActionButton icon={<Plus size={14} />} label="Seed" loading={loading === "corpus_seed"} disabled={!target} onClick={() => action("corpus_seed")} />
          <ActionButton icon={<Sprout size={14} />} label="Grow" loading={loading === "corpus_grow"} disabled={!target} onClick={() => action("corpus_grow")} />
          <ActionButton icon={<Scissors size={14} />} label="Prune" loading={loading === "corpus_prune"} disabled={!target} onClick={() => action("corpus_prune")} />
          <ActionButton icon={<Database size={14} />} label="List" loading={loading === "corpus_list"} disabled={!target} onClick={() => action("corpus_list")} />
        </div>
      </div>

      {error && (
        <div
          className="surface-card text-xs"
          style={{ padding: "var(--space-sm) var(--space-md)", color: "var(--danger, #e5484d)", borderColor: "var(--danger, #e5484d)" }}
        >
          {error}
        </div>
      )}
      {notice && !error && (
        <div className="text-xs text-text-muted" style={{ paddingLeft: "2px" }}>
          {notice}
        </div>
      )}

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
        <div className="surface-card overflow-x-auto" style={{ animation: "slideInUp 0.2s ease" }}>
          <table className="w-full text-sm" style={{ minWidth: 480 }}>
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
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i} className="border-b border-border transition-colors duration-100 hover:bg-surface-hover">
                  <td className="px-3 py-2 font-mono text-xs text-text-primary">{e.path.split("/").pop()}</td>
                  <td className="px-3 py-2 font-mono text-xs text-text-muted">{e.sha256.slice(0, 16)}...</td>
                  <td className="px-3 py-2 text-xs text-text-secondary">{e.source}</td>
                  <td className="px-3 py-2 text-right text-xs text-text-secondary">{e.size}b</td>
                  <td className="px-3 py-2 text-right"><PathActions path={e.path} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ActionButton({ icon, label, loading, disabled, onClick }: { icon: React.ReactNode; label: string; loading: boolean; disabled?: boolean; onClick: () => void }) {
  return (
    <Button variant="outline" size="sm" onClick={onClick} loading={loading} disabled={disabled}>
      {!loading && icon}
      {label}
    </Button>
  );
}