import "../i18n.parityRun";
import { useCallback, useEffect, useRef, useState } from "react";
import { useI18n } from "../i18nContext";
import { runApi, straightQuotes } from "../lib/parityRun";
import { Button, Textarea } from "./ui";
import { FolderOpen } from "lucide-react";

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Stored fuzzing dictionary of one target: show, load, save, clear. */
export function DictionaryPanel({ project, target }: { project: string; target: string }) {
  const { t } = useI18n();
  const [stored, setStored] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const ready = project !== "" && target !== "";

  const reload = useCallback(async () => {
    if (!ready) return;
    try {
      setStored((await runApi.dictionary(project, target)) ?? null);
    } catch (e) {
      setStored(null);
      setError(messageOf(e));
    }
  }, [project, target, ready]);

  useEffect(() => {
    let cancelled = false;
    if (!ready) return;
    runApi.dictionary(project, target)
      .then((dictionary) => { if (!cancelled) setStored(dictionary ?? null); })
      .catch(() => { if (!cancelled) setStored(null); });
    return () => { cancelled = true; };
  }, [project, target, ready]);

  async function save() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const count = await runApi.setDictionary(project, target, text);
      setMessage(t("dict.saved", { count }));
      setText("");
      await reload();
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await runApi.clearDictionary(project, target);
      setMessage(t("dict.cleared"));
      await reload();
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  async function loadFile(file: File | undefined) {
    if (!file) return;
    try {
      setText(await file.text());
      setError(null);
    } catch (e) {
      setError(messageOf(e));
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }} aria-label={t("dict.title")}>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-semibold">{t("dict.title")}</span>
        <span className="text-xs text-text-muted">{t("dict.hint")}</span>
      </div>
      {!ready ? (
        <p className="text-xs text-text-muted">{t("dict.noTarget")}</p>
      ) : (
        <>
          {stored === null ? (
            <p className="text-xs text-text-muted">{t("dict.empty")}</p>
          ) : (
            <pre className="text-xs max-h-40 overflow-auto" style={{ fontFamily: "var(--font-mono)", whiteSpace: "pre-wrap" }}>{stored}</pre>
          )}
          <Textarea
            mono
            rows={5}
            aria-label={t("dict.textLabel")}
            placeholder={t("dict.placeholder")}
            value={text}
            onChange={(e) => setText(straightQuotes(e.target.value))}
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
          />
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              hidden
              aria-label={t("dict.fileInput")}
              onChange={(e) => { void loadFile(e.target.files?.[0]); e.target.value = ""; }}
            />
            <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={busy}>
              <FolderOpen size={14} /> {t("dict.loadFile")}
            </Button>
            <Button variant="primary" size="sm" onClick={() => void save()} disabled={busy || text.trim() === ""}>
              {t("dict.save")}
            </Button>
            <Button variant="outline" size="sm" onClick={() => void clear()} disabled={busy || stored === null}>
              {t("dict.clear")}
            </Button>
          </div>
        </>
      )}
      {message && <p role="status" className="text-xs text-text-muted">{message}</p>}
      {error && <p role="alert" className="text-xs text-error">{error}</p>}
    </section>
  );
}
