import { useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import { Button, Input } from "./ui";

export type PathKind = "folder" | "file";


export function ServerPathDialog({ kind, title, onFinish }: { kind: PathKind; title?: string; onFinish: (value: string | null) => void }) {
  const { t } = useI18n();
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const settled = useRef(false);
  const pending = useRef(false);
  function finish(value: string | null) { if (!settled.current) { settled.current = true; onFinish(value); } }
  async function submit() {
    if (!path.trim() || pending.current) return;
    pending.current = true; setBusy(true); setError(null);
    try {
      const selected = kind === "folder"
        ? (await getTransport().invoke<{ project: string }>("select_project", { project: path.trim() })).project
        : path.trim();
      finish(selected);
    } catch (cause) { if (!settled.current) setError(String(cause)); }
    finally { pending.current = false; if (!settled.current) setBusy(false); }
  }
  return <Dialog.Root open onOpenChange={open => { if (!open) finish(null); }}>
    <Dialog.Portal>
      <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
      <Dialog.Content className="surface-card fixed z-50 p-6 flex flex-col gap-4" style={{ width: "min(520px, calc(100vw - 32px))", left: "50%", top: "50%", transform: "translate(-50%, -50%)" }}>
        <Dialog.Title className="m-0 text-lg">{title ?? t("gui.serverPathTitle")}</Dialog.Title>
        <Dialog.Description className="m-0 text-sm text-text-secondary">{t("gui.serverPathHint")}</Dialog.Description>
        <form className="flex flex-col gap-3" onSubmit={event => { event.preventDefault(); void submit(); }}>
          <label htmlFor="server-path" className="text-sm">{t(`gui.${kind}Path`)}</label>
          <Input id="server-path" aria-label={t(`gui.${kind}Path`)} value={path} disabled={busy} onChange={event => setPath(event.target.value)} autoComplete="off" />
          {error && <p role="alert" className="text-sm break-words">{t("gui.pathFailed")} {error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => finish(null)}>{t("common.cancel")}</Button>
            <Button type="submit" variant="primary" disabled={busy || !path.trim()}>{t(busy ? "gui.validatingPath" : "gui.usePath")}</Button>
          </div>
        </form>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
