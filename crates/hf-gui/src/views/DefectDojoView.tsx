// DefectDojo, embedded in-app.
//
// DefectDojo sends `X-Frame-Options: DENY`, so it cannot be shown in an iframe.
// Instead the Tauri backend renders it as a native child webview overlaid on the
// content region of this view. This component owns the layout: it measures the
// host element and reports its logical rectangle to `defectdojo_embed` so the
// native webview tracks it exactly (on mount, resize, and sidebar/panel toggles),
// and tears the webview down on unmount.
//
// The embed is gated on the server actually answering. A native webview pointed
// at a dead port renders as an empty grey rectangle with no way to tell a
// stopped server from a broken view, so until `defectdojo_status` reports
// `ready` this shows what is happening -- and, when the instance is one we
// manage, offers to start it.

import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, ExternalLink, Play, RotateCw, ShieldAlert } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../lib";
import type { DefectDojoStatus } from "../types";
import { Button, Spinner } from "../components/ui";
import { useToast } from "../components/ui/Toast";

/// How often to re-check while the server is booting (uwsgi takes ~30-60s).
const STARTING_POLL_MS = 3000;

export function DefectDojoView({ onBack }: { onBack: () => void }) {
  const { toast } = useToast();
  const hostRef = useRef<HTMLDivElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const [status, setStatus] = useState<DefectDojoStatus | null>(null);
  const [starting, setStarting] = useState(false);

  const ready = status?.state === "ready";
  const booting = starting || status?.state === "starting";

  const refresh = useCallback(
    () =>
      getTransport()
        .invoke<DefectDojoStatus>("defectdojo_status")
        .then(setStatus)
        .catch(() => {}),
    [],
  );

  // Status on mount, plus the launch-time `defectdojo:status` narration, so a
  // view opened while the stack is still booting keeps up with it.
  useEffect(() => {
    void refresh();
    let unlisten: (() => void) | undefined;
    getTransport()
      .listen<DefectDojoStatus>("defectdojo:status", (e) => setStatus(e.payload))
      .then((u) => {
        unlisten = u;
      })
      .catch(() => {});
    return () => unlisten?.();
  }, [refresh]);

  // While it boots, keep asking: the transition to `ready` is what mounts the
  // webview, and nothing else will tell us it happened.
  useEffect(() => {
    if (!booting) return undefined;
    const id = setInterval(() => void refresh(), STARTING_POLL_MS);
    return () => clearInterval(id);
  }, [booting, refresh]);

  const sync = useCallback(() => {
    const el = hostRef.current;
    if (!el || !isTauriEnvironment()) return;
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return;
    getTransport()
      .invoke("defectdojo_embed", { x: r.left, y: r.top, width: r.width, height: r.height })
      .catch((e) =>
        toast({ title: "Could not embed DefectDojo", description: String(e), variant: "error" }),
      );
  }, [toast]);

  // Coalesce bursts of layout changes into one reposition per frame.
  const scheduleSync = useCallback(() => {
    if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      sync();
    });
  }, [sync]);

  useEffect(() => {
    if (!isTauriEnvironment() || !ready) return undefined;
    const host = hostRef.current;
    scheduleSync();
    const onResize = () => scheduleSync();
    window.addEventListener("resize", onResize);
    const ro = new ResizeObserver(() => scheduleSync());
    if (host) ro.observe(host);
    return () => {
      window.removeEventListener("resize", onResize);
      ro.disconnect();
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
      getTransport()
        .invoke("defectdojo_embed_close")
        .catch(() => {});
    };
  }, [ready, scheduleSync]);

  async function start() {
    setStarting(true);
    try {
      setStatus(await getTransport().invoke<DefectDojoStatus>("defectdojo_start"));
    } catch (e) {
      toast({ title: "Could not start DefectDojo", description: String(e), variant: "error" });
      await refresh();
    } finally {
      setStarting(false);
    }
  }

  function reload() {
    getTransport()
      .invoke("defectdojo_embed_reload")
      .catch(() => {});
  }

  function openBrowser() {
    getTransport()
      .invoke("open_defectdojo", { inBrowser: true })
      .catch((e) =>
        toast({ title: "Could not open DefectDojo", description: String(e), variant: "error" }),
      );
  }

  return (
    <div className="flex flex-col flex-1 min-h-0" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center gap-2 border-b border-border" style={{ padding: "8px 12px" }}>
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeft size={14} />
          Back
        </Button>
        <div className="flex-1" />
        {isTauriEnvironment() && ready && (
          <Button variant="ghost" size="sm" onClick={reload} title="Reload DefectDojo">
            <RotateCw size={14} />
            Reload
          </Button>
        )}
        <Button
          variant="outline"
          size="sm"
          onClick={openBrowser}
          disabled={!ready}
          title={ready ? "Open in your default browser" : "DefectDojo is not running"}
        >
          <ExternalLink size={14} />
          Open in browser
        </Button>
      </div>
      {/* The native DefectDojo webview is overlaid on this host by the backend. */}
      <div ref={hostRef} className="flex-1 min-h-0" style={{ background: "var(--surface-secondary)" }}>
        {!isTauriEnvironment() ? (
          <div className="flex items-center justify-center h-full text-text-muted" style={{ fontSize: "13px" }}>
            DefectDojo opens in your browser in web mode -- use &ldquo;Open in browser&rdquo; above.
          </div>
        ) : (
          !ready && (
            <div className="flex flex-col items-center justify-center gap-3 h-full" style={{ padding: "var(--space-lg)" }}>
              {booting ? <Spinner size={20} /> : <ShieldAlert size={22} className="text-text-muted" />}
              <div className="text-sm text-text-secondary text-center" style={{ maxWidth: "460px" }}>
                {booting
                  ? "Starting DefectDojo -- the server takes a minute to come up."
                  : (status?.message ?? "Checking DefectDojo...")}
              </div>
              {status?.url && (
                <div className="text-xs font-mono text-text-muted">{status.url}</div>
              )}
              {status?.managed && !booting && (
                <Button variant="primary" size="sm" onClick={() => void start()}>
                  <Play size={13} />
                  Start DefectDojo
                </Button>
              )}
            </div>
          )
        )}
      </div>
    </div>
  );
}
