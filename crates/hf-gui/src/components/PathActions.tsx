import { useState } from "react";
import { Copy, Check, FolderSearch, ExternalLink } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../lib";
import { useToast } from "./ui/Toast";

// A compact row of actions for a filesystem path: copy, reveal in the OS file
// manager, and open with the default app. Reveal/open are desktop-only (they
// need OS integration); copy always works. Core triage ergonomics.
export function PathActions({ path, size = 13 }: { path: string; size?: number }) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);
  const tauri = isTauriEnvironment();

  async function copy() {
    try {
      await navigator.clipboard.writeText(path);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  }

  async function invokePath(cmd: "reveal_path" | "open_path", failLabel: string) {
    try {
      await getTransport().invoke(cmd, { path });
    } catch (e) {
      toast({ title: failLabel, description: String(e), variant: "error" });
    }
  }

  const btn = "inline-flex items-center justify-center rounded p-1 text-text-muted transition-colors hover:text-text-primary hover:bg-surface-hover";

  return (
    <span className="inline-flex items-center gap-0.5 shrink-0" onClick={(e) => e.stopPropagation()}>
      <button className={btn} onClick={() => void copy()} title="Copy path" aria-label="Copy path">
        {copied ? <Check size={size} /> : <Copy size={size} />}
      </button>
      {tauri && (
        <>
          <button className={btn} onClick={() => void invokePath("reveal_path", "Could not reveal path")} title="Reveal in Finder" aria-label="Reveal in file manager">
            <FolderSearch size={size} />
          </button>
          <button className={btn} onClick={() => void invokePath("open_path", "Could not open path")} title="Open with default app" aria-label="Open path">
            <ExternalLink size={size} />
          </button>
        </>
      )}
    </span>
  );
}
