import "../i18n.parityDiscovery";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18nContext";
import { formatInvokeError } from "../lib/invokeError";
import {
  clangIsTerminal,
  clangSupportsLanguage,
  discoveryApi,
  type ClangOperation,
  type ClangResult,
} from "../lib/parityDiscovery";
import { Button } from "./ui";

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Clang call and type analysis of a C or C++ project (`oxfuzz discover --clang`). */
export function ClangAnalysisPanel({ project, lang, pollMs = 1500 }: { project: string; lang: string; pollMs?: number }) {
  const { t } = useI18n();
  const [available, setAvailable] = useState(false);
  const [operation, setOperation] = useState<ClangOperation | null>(null);
  const [result, setResult] = useState<ClangResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  // Bumped on unmount and on a new start (the owner remounts the panel for
  // another project or language), so a poll loop
  // that belongs to an earlier analysis stops writing state.
  const generation = useRef(0);

  useEffect(() => {
    let live = true;
    // A build without the feature, or browser mode, has no such command: the
    // panel then stays hidden.
    discoveryApi.clangAvailable().then((value) => { if (live) setAvailable(value === true); }).catch(() => undefined);
    return () => { live = false; };
  }, []);

  useEffect(() => {
    const current = generation;
    return () => { current.current += 1; };
  }, []);

  if (!available || !project || !clangSupportsLanguage(lang)) return null;

  async function follow(id: string, mine: number) {
    for (;;) {
      await wait(pollMs);
      if (generation.current !== mine) return;
      const status = await discoveryApi.clangStatus(id);
      if (generation.current !== mine || !status) return;
      setOperation(status);
      if (!clangIsTerminal(status.state)) continue;
      if (status.state === "done") {
        const published = await discoveryApi.clangResult(id);
        if (generation.current === mine) setResult(published);
      }
      return;
    }
  }

  async function start() {
    const mine = ++generation.current;
    setStarting(true);
    setError(null);
    setResult(null);
    try {
      const started = await discoveryApi.clangStart(project, lang);
      if (generation.current !== mine) return;
      setOperation(started);
      setStarting(false);
      await follow(started.id, mine);
    } catch (cause) {
      if (generation.current === mine) setError(formatInvokeError(cause));
    } finally {
      if (generation.current === mine) setStarting(false);
    }
  }

  async function stop() {
    if (!operation) return;
    try {
      const cancelled = await discoveryApi.clangCancel(operation.id);
      generation.current += 1;
      if (cancelled) setOperation(cancelled);
    } catch (cause) {
      setError(formatInvokeError(cause));
    }
  }

  const running = operation !== null && !clangIsTerminal(operation.state);
  return (
    <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }} aria-label={t("parityDiscovery.clang.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-semibold">{t("parityDiscovery.clang.title")}</span>
        <span className="text-xs text-text-muted">{t("parityDiscovery.clang.help")}</span>
      </div>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={() => void start()} loading={starting} disabled={starting || running}>{t("parityDiscovery.clang.run")}</Button>
        {running && <Button variant="outline" size="sm" onClick={() => void stop()}>{t("parityDiscovery.clang.stop")}</Button>}
      </div>
      {operation && <p className="text-xs" role="status">{t("parityDiscovery.clang.state", { state: operation.state })}{operation.failure ? ` · ${t("parityDiscovery.clang.failure", { reason: operation.failure })}` : ""}</p>}
      {result && <p className="text-xs">{t("parityDiscovery.clang.result", { version: result.index.clang_version, functions: result.index.functions.length, calls: result.index.calls.length, units: result.index.units.length })}</p>}
      {error && <p role="alert" className="text-xs" style={{ color: "var(--error)" }}>{t("parityDiscovery.clang.failed", { error })}</p>}
    </section>
  );
}
