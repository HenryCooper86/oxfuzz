import { useEffect, useRef, useState } from "react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import { formatInvokeError } from "../lib/invokeError";
import { Button } from "./ui";

type Evidence = { status: "unavailable"; run_id: string; reason: string } | {
  status: "available"; run_id: string; binary_sha256: string; export_sha256: string;
  observed_functions: number; limitation: string;
  functions: { name: string; count: string; files: string[] }[];
};
function isEvidence(value: unknown, runId: string): value is Evidence {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  if (item.run_id !== runId) return false;
  if (item.status === "unavailable") return typeof item.reason === "string";
  return item.status === "available" && typeof item.binary_sha256 === "string"
    && typeof item.export_sha256 === "string" && typeof item.limitation === "string"
    && Number.isSafeInteger(item.observed_functions) && Number(item.observed_functions) >= 0
    && Array.isArray(item.functions) && item.functions.every((entry: unknown) => {
      if (!entry || typeof entry !== "object") return false;
      const fn = entry as Record<string, unknown>;
      return typeof fn.name === "string" && typeof fn.count === "string" && /^\d+$/.test(fn.count)
        && Array.isArray(fn.files) && fn.files.every((file: unknown) => typeof file === "string");
    });
}
export function RunFunctionCoverage({ runId }: { runId: string }) {
  return <EvidenceView key={runId} runId={runId} />;
}
function EvidenceView({ runId }: { runId: string }) {
  const { t } = useI18n();
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const active = useRef(true);
  const pending = useRef(false);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  async function load() {
    if (pending.current) return;
    pending.current = true; setBusy(true); setError(null);
    try {
      const result = await getTransport().invoke<unknown>("run_function_coverage", { runId });
      if (!isEvidence(result, runId)) throw new Error(t("functionCoverage.invalid"));
      if (active.current) setEvidence(result);
    } catch (failure) { if (active.current) setError(formatInvokeError(failure)); }
    finally { pending.current = false; if (active.current) setBusy(false); }
  }
  return <section className="space-y-2 mt-3">
    <Button disabled={busy} onClick={() => void load()}>{t("functionCoverage.load")}</Button>
    {error && <p role="alert">{error}</p>}
    {evidence?.status === "unavailable" && <p>{evidence.reason}</p>}
    {evidence?.status === "available" && <>
      <p>{evidence.limitation}</p>
      <p>{t("functionCoverage.observed")}: {evidence.observed_functions}</p>
      <p className="break-all">{t("functionCoverage.binary")}: {evidence.binary_sha256}</p>
      <p className="break-all">{t("functionCoverage.export")}: {evidence.export_sha256}</p>
      <p>{t("functionCoverage.limit")}</p>
      <ul>{evidence.functions.slice(0, 200).map((fn, index) => <li key={index}>
        <code>{fn.name}</code>: {fn.count} — {fn.files.join(", ")}
      </li>)}</ul>
    </>}
  </section>;
}
