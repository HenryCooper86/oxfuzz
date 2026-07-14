import { useState } from "react";
import { Copy, Check, FolderSearch, ExternalLink } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../lib";
import { useToast } from "./ui/Toast";
import { IconButton } from "./ui/IconButton";
import { useI18n } from "../i18n";

// A compact row of actions for a filesystem path: copy, reveal in the OS file
// manager, and open with the default app. Reveal/open are desktop-only (they
// need OS integration); copy always works. Core triage ergonomics.
export function PathActions({ path, size = 13 }: { path: string; size?: number }) {
  const { toast } = useToast();
  const { t } = useI18n();
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

  return (
    <span className="inline-flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
      <IconButton size={26} onClick={() => void copy()} title={t("pathActions.copyPath")} aria-label={t("pathActions.copyPath")}>
        {copied ? <Check size={size} /> : <Copy size={size} />}
      </IconButton>
      {tauri && (
        <>
          <IconButton
            size={26}
            onClick={() => void invokePath("reveal_path", t("pathActions.revealFailed"))}
            title={t("pathActions.revealTitle")}
            aria-label={t("pathActions.revealAria")}
          >
            <FolderSearch size={size} />
          </IconButton>
          <IconButton
            size={26}
            onClick={() => void invokePath("open_path", t("pathActions.openFailed"))}
            title={t("pathActions.openTitle")}
            aria-label={t("pathActions.openAria")}
          >
            <ExternalLink size={size} />
          </IconButton>
        </>
      )}
    </span>
  );
}
