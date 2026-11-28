import "../i18n.parityDiscovery";
import { useState } from "react";
import { useI18n } from "../i18nContext";
import { formatInvokeError } from "../lib/invokeError";
import { discoveryApi, type RemoteArmAction } from "../lib/parityDiscovery";
import { isTauriEnvironment } from "../lib/transport";
import { DesktopOnlyNotice } from "./RestServerPanel";
import { Button, Input } from "./ui";

/** Arm, disarm or query another running server (`oxfuzz arm --url`). */
export function RemoteArmPanel() {
  // The desktop app makes this request itself; a browser calls the other
  // server's API directly, and this server never relays to an arbitrary URL.
  return isTauriEnvironment() ? <DesktopRemoteArmPanel /> : <DesktopOnlyNotice title="parityDiscovery.remote.title" />;
}

function DesktopRemoteArmPanel() {
  const { t } = useI18n();
  const [url, setUrl] = useState("");
  // Held in memory for the request only: never persisted.
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState<RemoteArmAction | null>(null);
  const [armed, setArmed] = useState<boolean | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  async function send(action: RemoteArmAction) {
    setBusy(action);
    setError(null);
    try {
      setArmed(await discoveryApi.remoteArm(url.trim(), action, token));
    } catch (cause) {
      setArmed(undefined);
      setError(formatInvokeError(cause));
    } finally {
      setBusy(null);
    }
  }

  const idle = url.trim().length === 0 || busy !== null;
  const outcome = armed === undefined
    ? null
    : armed === null
      ? t("parityDiscovery.remote.unknown")
      : t(armed ? "parityDiscovery.remote.armed" : "parityDiscovery.remote.disarmed");
  return (
    <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }} aria-label={t("parityDiscovery.remote.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-semibold">{t("parityDiscovery.remote.title")}</span>
        <span className="text-xs text-text-muted">{t("parityDiscovery.remote.help")}</span>
      </div>
      <div className="flex gap-2 flex-wrap">
        <Input className="flex-1" aria-label={t("parityDiscovery.remote.url")} placeholder="http://127.0.0.1:8081" value={url} onChange={(event) => setUrl(event.target.value)} />
        <Input type="password" autoComplete="off" aria-label={t("parityDiscovery.remote.token")} placeholder={t("parityDiscovery.remote.token")} value={token} onChange={(event) => setToken(event.target.value)} />
      </div>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={() => void send("status")} loading={busy === "status"} disabled={idle}>{t("parityDiscovery.remote.status")}</Button>
        <Button variant="outline" size="sm" onClick={() => void send("arm")} loading={busy === "arm"} disabled={idle}>{t("parityDiscovery.remote.arm")}</Button>
        <Button variant="outline" size="sm" onClick={() => void send("disarm")} loading={busy === "disarm"} disabled={idle}>{t("parityDiscovery.remote.disarm")}</Button>
      </div>
      {outcome && <p className="text-xs" role="status">{outcome}</p>}
      {error && <p role="alert" className="text-xs" style={{ color: "var(--error)" }}>{t("parityDiscovery.remote.failed", { error })}</p>}
    </section>
  );
}
