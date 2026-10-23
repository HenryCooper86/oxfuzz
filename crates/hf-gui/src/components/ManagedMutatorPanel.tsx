import { useEffect, useRef, useState } from "react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import { Button } from "./ui";

export interface MutatorArtifact {
  version: number;
  api: "afl_plus_plus" | "lib_fuzzer";
  source_sha256: string;
  artifact_name: string;
  artifact_sha256: string;
  sandbox_image_id: string;
  custom_trim: boolean;
  self_test: null | { exit_code: number; mutation_observed: boolean; trim_observed: boolean; log: string; log_truncated: boolean };
}
interface MutatorStatus { harness_id: string; source: string | null; mutator: MutatorArtifact | null }

export function ManagedMutatorEvidence({ artifact }: { artifact: MutatorArtifact }) {
  const { t } = useI18n();
  return <div className="flex flex-col gap-2 text-xs">
    <p role="status" style={{ color: (artifact.self_test?.exit_code === 0 && artifact.self_test.mutation_observed) ? "var(--success)" : "var(--text-secondary)" }}>
      {t((artifact.self_test?.exit_code === 0 && artifact.self_test.mutation_observed) ? "mutator.observed" : "mutator.unqualified")}
      {" · "}{t(artifact.custom_trim ? artifact.self_test?.trim_observed ? "mutator.trimObserved" : "mutator.trimUnknown" : "mutator.nativeTrim")}
    </p>
    <dl className="grid gap-2" style={{ overflowWrap: "anywhere" }}>
      {([["mutator.sourceHash", artifact.source_sha256], ["mutator.artifactHash", artifact.artifact_sha256], ["mutator.image", artifact.sandbox_image_id]] as const).map(([label, value]) =>
        <div key={label}><dt className="text-text-muted">{t(label)}</dt><dd style={{ fontFamily: "var(--font-mono)" }}>{value}</dd></div>)}
    </dl>
    {artifact.self_test && <details><summary>{t("mutator.log")}</summary><pre className="overflow-auto max-h-40" style={{ whiteSpace: "pre-wrap" }}>{artifact.self_test.log}</pre>
      {artifact.self_test.log_truncated && <p>{t("mutator.truncated")}</p>}
    </details>}
  </div>;
}

interface ManagedMutatorProps {
  project: string; target: string; engine: string; lang: string; harnessId: string; disabled: boolean; onImported: () => void;
}
export function ManagedMutatorPanel(props: ManagedMutatorProps) {
  return <ManagedMutatorForm key={JSON.stringify([props.project, props.target, props.engine, props.lang, props.harnessId])} {...props} />;
}
function ManagedMutatorForm({ project, target, engine, lang, harnessId, disabled, onImported }: ManagedMutatorProps) {
  const { t } = useI18n();
  const [status, setStatus] = useState<MutatorStatus | null>(null);
  const [source, setSource] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [imported, setImported] = useState(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const supported = ["afl++", "libfuzzer"].includes(engine) && ["c", "cpp"].includes(lang);
  useEffect(() => {
    if (!supported) return;
    let active = true;
    getTransport().invoke<MutatorStatus>("managed_mutator_status", { project, target, engine }).then((result) => {
      if (active) { setStatus(result); setSource(result.source ?? ""); setError(null); }
    }).catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [project, target, engine, harnessId, supported]);
  async function compile() {
    if (!status || busy) return;
    setBusy(true); setError(null); setImported(false);
    try {
      const result = await getTransport().invoke<MutatorStatus>("attach_managed_mutator", {
        project, target, engine, expectedHarnessId: status.harness_id, source,
      });
      if (mounted.current) { setStatus(result); setImported(true); onImported(); }
    } catch (reason) { if (mounted.current) setError(String(reason)); } finally { if (mounted.current) setBusy(false); }
  }
  async function importFile(file: File | undefined) {
    if (!file) return;
    if (file.size > 65536) { setError(t("mutator.size")); return; }
    try {
      const text = await file.text();
      if (mounted.current) { setSource(text); setError(null); }
    } catch (reason) { if (mounted.current) setError(String(reason)); }
  }
  return <section className="mt-3 pt-3 flex flex-col gap-3" style={{ borderTop: "1px solid var(--border)" }}>
    <h3 className="text-sm font-medium">{t("mutator.title")}</h3>
    <p className="text-xs text-text-secondary">{t(supported ? "mutator.help" : "mutator.support")}</p>
    {status?.mutator && <ManagedMutatorEvidence artifact={status.mutator} />}
    {supported && <details><summary className="text-xs">{t("mutator.source")}</summary>
      <label className="text-xs block mt-2">{t("mutator.file")}<input type="file" accept=".c,.cc,.cpp,.cxx" disabled={disabled || busy || !status} onChange={(event) => { void importFile(event.target.files?.[0]); }} /></label>
      <textarea aria-label={t("mutator.source")} value={source} disabled={disabled || busy || !status} onChange={(event) => setSource(event.target.value)} rows={10}
        className="w-full text-xs mt-2 p-2" style={{ background: "var(--surface-code)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", fontFamily: "var(--font-mono)" }} />
      <Button size="sm" disabled={disabled || busy || !status || source.trim().length === 0} onClick={() => { void compile(); }}>{t(busy ? "mutator.compiling" : "mutator.compile")}</Button>
    </details>}
    {imported && <p role="status" className="text-xs">{t("mutator.next")}</p>}
    {error && <p role="alert" className="text-xs" style={{ color: "var(--danger)" }}>{error}</p>}
  </section>;
}
