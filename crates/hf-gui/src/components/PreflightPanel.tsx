import "../i18n.parityRun";
import { useState } from "react";
import { useI18n } from "../i18nContext";
import { engineStatusKey, runApi, type PreflightResult } from "../lib/parityRun";
import { Button, Switch } from "./ui";
import { Stethoscope } from "lucide-react";

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Readiness check for one engine and duration (`oxfuzz doctor --engine`). */
export function PreflightPanel({ engine, durationSecs }: { engine: string; durationSecs: number | null }) {
  const { t } = useI18n();
  const [requireProvider, setRequireProvider] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PreflightResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function check() {
    setBusy(true);
    setError(null);
    try {
      setResult(await runApi.preflight({
        engine,
        ...(durationSecs !== null ? { durationSecs } : {}),
        requireProvider,
      }));
    } catch (e) {
      setResult(null);
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  const engineKey = result ? engineStatusKey(result.engine) : null;
  const checks: { label: string; ok: boolean | null }[] = result
    ? [
        { label: t("preflight.docker"), ok: result.status.docker ?? null },
        { label: t("preflight.image"), ok: result.status.sandbox_image ?? null },
        ...(engineKey ? [{ label: t("preflight.engineTools", { engine: result.engine }), ok: result.status[engineKey] ?? null }] : []),
        ...(result.provider_configured !== null ? [{ label: t("preflight.provider"), ok: result.provider_configured }] : []),
      ]
    : [];

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }} aria-label={t("preflight.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-semibold">{t("preflight.title")}</span>
        <span className="text-xs text-text-muted">{t("preflight.hint")}</span>
      </div>
      <Switch
        checked={requireProvider}
        onChange={setRequireProvider}
        ariaLabel={t("preflight.requireModel")}
        label={t("preflight.requireModel")}
      />
      <div>
        <Button variant="outline" size="sm" onClick={() => void check()} loading={busy} disabled={busy}>
          {!busy && <Stethoscope size={14} />}
          {t("preflight.check")}
        </Button>
      </div>
      {error && <p role="alert" className="text-xs text-error">{error}</p>}
      {result && (
        <div className="flex flex-col gap-2" role="status">
          <p className="text-sm font-semibold" style={{ color: result.ready ? "var(--success)" : "var(--error)" }}>
            {result.ready ? t("preflight.ready") : t("preflight.notReady")}
          </p>
          <ul className="flex flex-col gap-1 text-xs">
            {checks.map((check) => (
              <li key={check.label}>
                {check.label}: {check.ok === null ? t("run.unknown") : check.ok ? t("preflight.ok") : t("preflight.missing")}
              </li>
            ))}
          </ul>
          {result.problems.length > 0 && (
            <ul className="flex flex-col gap-1 text-xs text-error">
              {result.problems.map((problem) => <li key={problem}>{problem}</li>)}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
