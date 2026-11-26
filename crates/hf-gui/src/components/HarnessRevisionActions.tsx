import "../i18n.parityHarness";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18nContext";
import { Button, Input } from "./ui";
import { adoptHarnessRevision, refineHarness, UUID_PATTERN, type HarnessAiPolicy } from "../lib/parityHarness";

interface Props {
  project: string; target: string; engine: string; lang: string;
  ai: HarnessAiPolicy; repairs: number; disabled: boolean;
  onChanged: () => void;
}

/** Coverage-guided refine and adopting a stored revision (`--refine`, `--adopt`). */
export function HarnessRevisionActions({ project, target, engine, lang, ai, repairs, disabled, onChanged }: Props) {
  const { t } = useI18n();
  const [busy, setBusy] = useState<null | "refine" | "adopt">(null);
  const [revision, setRevision] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const scope = { project, target, engine, lang };
  const revisionValid = UUID_PATTERN.test(revision.trim());

  async function run(kind: "refine" | "adopt") {
    if (busy) return;
    setBusy(kind); setMessage(null); setError(null);
    try {
      if (kind === "refine") {
        const result = await refineHarness(scope, repairs, ai);
        if (!mounted.current) return;
        setMessage(t("parityHarness.refineDone", { status: result.status, id: result.harness_id }));
      } else {
        const result = await adoptHarnessRevision(scope, revision.trim());
        if (!mounted.current) return;
        setMessage(t("parityHarness.adoptDone", { status: result.status }));
      }
      onChanged();
    } catch (reason) {
      if (mounted.current) setError(String(reason));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }
  const locked = disabled || busy !== null;
  return <section className="surface-card flex flex-col gap-3 text-xs" style={{ padding: "var(--space-md)" }}>
    <h3 className="text-sm font-medium">{t("parityHarness.reviseTitle")}</h3>
    <p className="text-text-muted">{t("parityHarness.refineHelp")}</p>
    <Button size="sm" className="self-start" disabled={locked} onClick={() => { void run("refine"); }}>{t(busy === "refine" ? "parityHarness.refining" : "parityHarness.refine")}</Button>
    <p className="text-text-muted">{t("parityHarness.adoptHelp")}</p>
    <div className="flex gap-2 items-center flex-wrap">
      <Input mono className="w-96 max-w-full" aria-label={t("parityHarness.adoptId")} placeholder="00000000-0000-0000-0000-000000000000" value={revision} disabled={locked}
        onChange={(event) => setRevision(event.target.value)} />
      <Button size="sm" disabled={locked || !revisionValid} onClick={() => { void run("adopt"); }}>{t(busy === "adopt" ? "parityHarness.adopting" : "parityHarness.adopt")}</Button>
    </div>
    {revision.trim().length > 0 && !revisionValid && <p className="text-text-muted">{t("parityHarness.adoptInvalid")}</p>}
    {message && <p role="status">{message}</p>}
    {error && <p role="alert" style={{ color: "var(--error)" }}>{error}</p>}
  </section>;
}
