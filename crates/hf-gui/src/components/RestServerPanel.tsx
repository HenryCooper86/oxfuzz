import "../i18n.parityDiscovery";
import { useEffect, useState } from "react";
import { useI18n } from "../i18nContext";
import { formatInvokeError } from "../lib/invokeError";
import { DEFAULT_REST_PORT, restServerApi, type RestServerInfo } from "../lib/parityDiscovery";
import { Button, Input } from "./ui";

/** Start and stop the REST API from the app (`oxfuzz serve`), loopback only. */
export function RestServerPanel({ project }: { project: string }) {
  const { t } = useI18n();
  const [port, setPort] = useState(String(DEFAULT_REST_PORT));
  const [info, setInfo] = useState<RestServerInfo | null>(null);
  // Held only while this panel is mounted: the token is shown once.
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    // Browser mode and a build without the server have no such command: the
    // panel then shows the stopped state and reports the error on Start.
    restServerApi.status().then((current) => { if (live) setInfo(current); }).catch(() => undefined);
    return () => { live = false; };
  }, []);

  async function act(run: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await run();
    } catch (cause) {
      setError(formatInvokeError(cause));
    } finally {
      setBusy(false);
    }
  }

  const start = () => act(async () => {
    const started = await restServerApi.start(Number(port), [project]);
    setInfo({ url: started.url, project_roots: started.project_roots });
    setToken(started.token);
  });
  const stop = () => act(async () => {
    await restServerApi.stop();
    setInfo(null);
    setToken(null);
  });

  const portValid = /^\d{1,5}$/.test(port) && Number(port) <= 65535;
  return (
    <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }} aria-label={t("parityDiscovery.rest.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-semibold">{t("parityDiscovery.rest.title")}</span>
        <span className="text-xs text-text-muted">{t("parityDiscovery.rest.help")}</span>
      </div>
      {info ? (
        <>
          <p className="text-xs" role="status">{t("parityDiscovery.rest.running", { url: info.url, roots: info.project_roots.join(", ") })}</p>
          {token && (
            <label className="flex flex-col gap-1 text-xs">
              {t("parityDiscovery.rest.token")}
              <Input readOnly value={token} aria-label={t("parityDiscovery.rest.token")} onFocus={(event) => event.target.select()} />
              <span className="text-text-muted">{t("parityDiscovery.rest.tokenHelp")}</span>
            </label>
          )}
          <div><Button variant="outline" size="sm" onClick={() => void stop()} loading={busy} disabled={busy}>{t("parityDiscovery.rest.stop")}</Button></div>
        </>
      ) : (
        <>
          <p className="text-xs text-text-muted">{project ? t("parityDiscovery.rest.stopped") : t("parityDiscovery.rest.needProject")}</p>
          <div className="flex gap-2 items-center">
            <Input className="w-24" inputMode="numeric" aria-label={t("parityDiscovery.rest.port")} value={port} onChange={(event) => setPort(event.target.value)} />
            <Button variant="outline" size="sm" onClick={() => void start()} loading={busy} disabled={busy || !project || !portValid}>{t("parityDiscovery.rest.start")}</Button>
          </div>
        </>
      )}
      {error && <p role="alert" className="text-xs" style={{ color: "var(--error)" }}>{t("parityDiscovery.rest.failed", { error })}</p>}
    </section>
  );
}
