// DefectDojo, embedded in-app.
//
// DefectDojo sends `X-Frame-Options: DENY`, so it cannot be shown in an iframe.
// Instead the Tauri backend renders it as a native child webview overlaid on the
// content region of this view. This component owns the layout: it measures the
// host element and reports its logical rectangle to `defectdojo_embed` so the
// native webview tracks it exactly (on mount, resize, and sidebar/panel toggles),
// and tears the webview down on unmount.

import { useCallback, useEffect, useRef } from "react";
import { ArrowLeft, ExternalLink, RotateCw } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../lib";
import { Button } from "../components/ui";
import { useToast } from "../components/ui/Toast";

export function DefectDojoView({ onBack }: { onBack: () => void }) {
  const { toast } = useToast();
  const hostRef = useRef<HTMLDivElement | null>(null);
  const rafRef = useRef<number | null>(null);

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
    if (!isTauriEnvironment()) return undefined;
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
  }, [scheduleSync]);

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
        {isTauriEnvironment() && (
          <Button variant="ghost" size="sm" onClick={reload} title="Reload DefectDojo">
            <RotateCw size={14} />
            Reload
          </Button>
        )}
        <Button variant="outline" size="sm" onClick={openBrowser} title="Open in your default browser">
          <ExternalLink size={14} />
          Open in browser
        </Button>
      </div>
      {/* The native DefectDojo webview is overlaid on this host by the backend. */}
      <div ref={hostRef} className="flex-1 min-h-0" style={{ background: "var(--surface-secondary)" }}>
        {!isTauriEnvironment() && (
          <div className="flex items-center justify-center h-full text-text-muted" style={{ fontSize: "13px" }}>
            DefectDojo opens in your browser in web mode -- use &ldquo;Open in browser&rdquo; above.
          </div>
        )}
      </div>
    </div>
  );
}
