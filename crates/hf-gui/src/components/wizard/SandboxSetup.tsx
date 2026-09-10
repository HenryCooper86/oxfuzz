import { useEffect, useRef, useState } from "react";
import { getTransport, isTauriEnvironment } from "../../lib";
import { useI18n } from "../../i18nContext";
import type { SystemStatus } from "../../types";
import { Button } from "../ui/Button";

interface Readiness { status: SystemStatus; runtime_ready: boolean }
export function SandboxSetup({ onContinue }: { onContinue: () => void }) {
  const { t } = useI18n();
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const active = useRef(true);
  const preparing = useRef(false);
  const generation = useRef(0);
  const desktop = isTauriEnvironment();
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  useEffect(() => {
    let current = true;
    const request = generation.current;
    void getTransport().invoke<Readiness>("setup_readiness").then(value => {
      if (typeof value?.runtime_ready !== "boolean" || !value.status) throw new Error(t("setup.invalidResponse"));
      if (current && request === generation.current) setReadiness(value);
    }).catch((error: unknown) => { if (current && request === generation.current) setError(String(error)); });
    return () => { current = false; };
  }, [attempt, t]);
  async function prepare() {
    if (!desktop || preparing.current) return;
    generation.current += 1;
    preparing.current = true; setBusy(true); setError(null); setReadiness(null);
    try {
      await getTransport().invoke("ensure_docker");
      if (active.current) setAttempt(value => value + 1);
    } catch (error) { if (active.current) setError(String(error)); }
    finally { preparing.current = false; if (active.current) setBusy(false); }
  }
  return <div className="flex flex-col gap-4">
    <p className="m-0 text-sm text-text-secondary">{t("setup.sandboxHint")}</p>
    {error ? <p role="alert" className="m-0 text-sm break-words">{t("setup.readinessFailed")}: {error}</p> : !readiness ? <p role="status">{t(busy ? "setup.preparing" : "setup.checking")}</p> : <div role="status" className="flex flex-col gap-2">
      <p className="m-0 font-medium">{t(readiness.runtime_ready ? "setup.runtimeReady" : "setup.runtimeNotReady")}</p>
      <p className="m-0 text-sm">{t("setup.docker")}: {t(readiness.status.docker ? "setup.available" : "setup.unavailable")}</p>
      <p className="m-0 text-sm">{t("setup.sandboxImage")}: {t(readiness.status.sandbox_image ? "setup.available" : "setup.unavailable")}</p>
      <details><summary className="cursor-pointer text-sm">{t("setup.engineDetails")}</summary><ul className="text-sm pl-5">{([['libfuzzer', 'libFuzzer'], ['aflplusplus', 'AFL++'], ['honggfuzz', 'honggfuzz'], ['syzkaller', 'syzkaller']] as const).map(([key, label]) => <li key={key}>{label}: {t(readiness.status[key] ? "setup.available" : "setup.unavailable")}</li>)}</ul></details>
    </div>}
    {!readiness?.runtime_ready && <p className="m-0 text-sm text-text-secondary">{t(desktop ? "setup.prepareHint" : "setup.serverHint")}</p>}
    <div className="flex flex-wrap gap-2">
      {desktop && !readiness?.runtime_ready && <Button variant="outline" disabled={busy} onClick={() => void prepare()}>{t("setup.prepareSandbox")}</Button>}
      <Button variant="outline" disabled={busy} onClick={() => { generation.current += 1; setReadiness(null); setError(null); setAttempt(value => value + 1); }}>{t("setup.checkAgain")}</Button>
      <Button variant="primary" disabled={busy || !!error || !readiness?.runtime_ready} onClick={onContinue}>{t("setup.continue")}</Button>
    </div>
  </div>;
}
