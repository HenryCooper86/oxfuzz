import { useState } from "react";
import { Copy, Check, FolderSearch } from "lucide-react";
import { getTransport, isTauriEnvironment } from "../lib";
import { useToast } from "./ui/toastContext";
import { IconButton } from "./ui/IconButton";
import { useI18n } from "../i18nContext";

// A compact row of actions for a filesystem path: copy, and reveal in the OS
// file manager (desktop only). There is deliberately no "open with default app":
// these paths are crash reproducers and corpus inputs, which are untrusted fuzz
// output and must not be handed to a host application outside the sandbox.
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

  async function reveal() {
    try {
      await getTransport().invoke("reveal_path", { path });
    } catch (e) {
      toast({ title: t("pathActions.revealFailed"), description: String(e), variant: "error" });
    }
  }

  return (
    <span className="inline-flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
      <IconButton size={26} onClick={() => void copy()} title={t("pathActions.copyPath")} aria-label={t("pathActions.copyPath")}>
        {copied ? <Check size={size} /> : <Copy size={size} />}
      </IconButton>
      {tauri && (
        <IconButton
          size={26}
          onClick={() => void reveal()}
          title={t("pathActions.revealTitle")}
          aria-label={t("pathActions.revealAria")}
        >
          <FolderSearch size={size} />
        </IconButton>
      )}
    </span>
  );
}
