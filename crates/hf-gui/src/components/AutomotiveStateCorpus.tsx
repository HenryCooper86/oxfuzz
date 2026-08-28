import { useCallback, useEffect, useRef, useState } from "react";
import { Boxes, Database } from "lucide-react";
import { useI18n } from "../i18nContext";
import {
  listAutomotiveStateCorpus,
  promoteAutomotiveStateArtifact,
  type AutomotiveOperationSummary,
  type AutomotiveStateArtifactSource,
  type AutomotiveStateCorpusEntry,
} from "../lib/automotive";
import { useToast } from "./ui/toastContext";
import { Badge, Button, EmptyState, LoadingState, Select } from "./ui";

interface AutomotiveStateCorpusProps {
  projectRoot: string;
  operations: AutomotiveOperationSummary[];
}

/**
 * One operation a promotion could draw on: completed, and carrying both a
 * validated state signature and an artifact the service can resolve. The
 * service revalidates all three, so this only avoids offering a control whose
 * every use would be rejected.
 */
function promotable(operations: AutomotiveOperationSummary[]): AutomotiveOperationSummary[] {
  return operations.filter(
    (operation) =>
      operation.status === "done" &&
      operation.state_signatures.length > 0 &&
      operation.promotable_artifacts.length > 0,
  );
}

function artifactKey(artifact: AutomotiveStateArtifactSource): string {
  return `${artifact.location}:${artifact.artifact_id}`;
}

/**
 * Promote validated evidence from a retained operation into the protocol-state
 * corpus, and list what has been promoted.
 *
 * The campaign report and the lab coverage view read this corpus as feedback,
 * so without a writer here they report zero promoted state on every project.
 */
export function AutomotiveStateCorpus({ projectRoot, operations }: AutomotiveStateCorpusProps) {
  const { t } = useI18n();
  const { toast } = useToast();
  const candidates = promotable(operations);
  const [entries, setEntries] = useState<AutomotiveStateCorpusEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [operationId, setOperationId] = useState("");
  const [digest, setDigest] = useState("");
  const [artifact, setArtifact] = useState("");

  const selected = candidates.find((operation) => operation.id === operationId) ?? candidates[0];
  const signature =
    selected?.state_signatures.find((entry) => entry.digest === digest) ??
    selected?.state_signatures[0];
  const source =
    selected?.promotable_artifacts.find((entry) => artifactKey(entry) === artifact) ??
    selected?.promotable_artifacts[0];

  // A project switch invalidates whatever list is still in flight, so each read
  // carries a request id and only the newest one is allowed to land.
  const requestRef = useRef(0);
  const refresh = useCallback(async () => {
    const requestId = ++requestRef.current;
    if (!projectRoot) {
      setEntries([]);
      return;
    }
    setLoading(true);
    try {
      const next = await listAutomotiveStateCorpus(projectRoot, 50);
      if (requestRef.current === requestId) setEntries(next);
    } catch (reason) {
      if (requestRef.current === requestId) {
        toast({
          title: t("automotive.stateCorpus.listFailed"),
          description: String(reason),
          variant: "error",
        });
      }
    } finally {
      if (requestRef.current === requestId) setLoading(false);
    }
  }, [projectRoot, t, toast]);

  useEffect(() => {
    queueMicrotask(() => void refresh());
    return () => {
      requestRef.current += 1;
    };
  }, [refresh]);

  async function promote() {
    if (!selected || !signature || !source || busy) return;
    setBusy(true);
    try {
      // The signature and the selector go back exactly as the summary reported
      // them; reshaping either here would name evidence the service cannot
      // match against its own retained copy.
      await promoteAutomotiveStateArtifact({
        projectRoot,
        sourceOperationId: selected.id,
        stateSignature: signature,
        artifact: source,
      });
      toast({ title: t("automotive.stateCorpus.promoted"), variant: "success" });
      await refresh();
    } catch (reason) {
      toast({
        title: t("automotive.stateCorpus.promoteFailed"),
        description: String(reason),
        variant: "error",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center gap-2">
        <Database size={17} className="text-accent" />
        <h2 className="text-sm font-semibold">{t("automotive.stateCorpus.title")}</h2>
        <span className="text-12px text-text-muted">{entries.length}</span>
      </div>
      <p className="text-12px text-text-secondary">{t("automotive.stateCorpus.description")}</p>

      {candidates.length === 0 ? (
        <p className="text-11px text-text-muted">{t("automotive.stateCorpus.noCandidates")}</p>
      ) : (
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-11px text-text-muted">
            {t("automotive.stateCorpus.operation")}
            <Select
              value={selected?.id ?? ""}
              onChange={(value) => {
                setOperationId(value);
                setDigest("");
                setArtifact("");
              }}
              options={candidates.map((operation) => ({
                value: operation.id,
                label: `${operation.operation} - ${operation.id.slice(0, 8)}`,
              }))}
              className="min-w-56"
            />
          </label>
          <label className="flex flex-col gap-1 text-11px text-text-muted">
            {t("automotive.stateCorpus.state")}
            <Select
              value={signature?.digest ?? ""}
              onChange={setDigest}
              options={(selected?.state_signatures ?? []).map((entry) => ({
                value: entry.digest,
                label: `${entry.protocol}:${entry.digest.slice(0, 12)}`,
              }))}
              className="min-w-48"
            />
          </label>
          <label className="flex flex-col gap-1 text-11px text-text-muted">
            {t("automotive.stateCorpus.artifact")}
            <Select
              value={source ? artifactKey(source) : ""}
              onChange={setArtifact}
              options={(selected?.promotable_artifacts ?? []).map((entry) => ({
                value: artifactKey(entry),
                label: `${entry.location} - ${entry.artifact_id}`,
              }))}
              className="min-w-48"
            />
          </label>
          <Button
            variant="primary"
            loading={busy}
            disabled={busy || !selected || !signature || !source}
            onClick={() => void promote()}
          >
            {t("automotive.stateCorpus.promote")}
          </Button>
        </div>
      )}

      {loading && entries.length === 0 ? (
        <LoadingState label={t("automotive.stateCorpus.loading")} />
      ) : entries.length === 0 ? (
        <EmptyState
          icon={<Boxes size={22} />}
          title={t("automotive.stateCorpus.empty")}
          hint={t("automotive.stateCorpus.emptyHint")}
        />
      ) : (
        <div className="flex flex-col gap-1">
          {entries.map((entry) => (
            <div
              key={`${entry.state_digest}-${entry.artifact_sha256}`}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-surface-primary px-3 py-1.5 text-11px"
            >
              <Badge variant="accent">{entry.protocol}</Badge>
              <span className="font-mono text-text-muted">{entry.state_digest.slice(0, 16)}</span>
              <span className="font-mono text-text-secondary">{entry.artifact_path}</span>
              <span className="ml-auto text-text-muted">
                {new Date(entry.created_at).toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
