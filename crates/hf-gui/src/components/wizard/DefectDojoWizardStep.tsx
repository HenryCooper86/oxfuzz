// DefectDojo step for the setup wizard: a live, skippable integration setup that
// mirrors the DefectDojo view/Integrations patterns. Shows lifecycle status, can
// start a managed local instance, and can point oxfuzz at a remote server.

import { useCallback, useEffect, useState } from "react";
import { Database } from "lucide-react";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Badge } from "../ui/Badge";
import { Separator } from "../ui/Separator";
import { useToast } from "../ui/toastContext";
import { getTransport } from "../../lib";
import { useI18n } from "../../i18nContext";
import type { DefectDojoStatus } from "../../types";
import {
  defectDojoDraftFromPublic,
  type DefectDojoDraft,
  type DefectDojoPublicConfig,
} from "../../lib/integrationSettings";
import { DD_STATE_VARIANT, defectDojoRemotePatch } from "./defectdojoWizard";

export function DefectDojoWizardStep({ active }: { active: boolean }) {
  const { t } = useI18n();
  const { toast } = useToast();
  const [status, setStatus] = useState<DefectDojoStatus | null>(null);
  const [draft, setDraft] = useState<DefectDojoDraft | null>(null);
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);

  const refreshStatus = useCallback(() => {
    getTransport()
      .invoke<DefectDojoStatus>("defectdojo_status")
      .then(setStatus)
      .catch(() => {
        // Status is best-effort; a failure just leaves the neutral placeholder.
      });
  }, []);

  useEffect(() => {
    if (!active) return;
    refreshStatus();
    getTransport()
      .invoke<DefectDojoPublicConfig>("get_defectdojo_config")
      .then((cfg) => {
        const d = defectDojoDraftFromPublic(cfg);
        setDraft(d);
        setUrl(d.url);
      })
      .catch(() => {
        // No config yet is fine -- the fields stay empty and the step is optional.
      });
  }, [active, refreshStatus]);

  async function startLocal() {
    if (busy) return;
    setBusy(true);
    try {
      setStatus(await getTransport().invoke<DefectDojoStatus>("defectdojo_start"));
    } catch (e) {
      toast({ title: t("wizard.ddStartFailed"), description: String(e), variant: "error" });
    } finally {
      setBusy(false);
    }
  }

  async function saveRemote() {
    if (busy || !draft) return;
    const trimmed = url.trim();
    if (!trimmed) {
      toast({ title: t("wizard.ddUrlRequired"), variant: "error" });
      return;
    }
    setBusy(true);
    try {
      const patch = defectDojoRemotePatch(draft, trimmed, token);
      await getTransport().invoke("patch_defectdojo_config", { patch });
      setToken("");
      toast({ title: t("wizard.ddSaved") });
      refreshStatus();
    } catch (e) {
      toast({ title: t("wizard.ddSaveFailed"), description: String(e), variant: "error" });
    } finally {
      setBusy(false);
    }
  }

  const state = status?.state ?? "not_configured";
  const managed = status?.managed ?? false;
  const canStart = managed && state !== "ready" && state !== "starting";

  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold">{t("wizard.ddTitle")}</h2>
      <p className="text-xs text-text-secondary">{t("wizard.ddDesc")}</p>

      <div className="flex items-center justify-between p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2">
          <Database size={14} style={{ color: "var(--accent)" }} />
          <span className="text-xs text-text-primary">{status?.message ?? t("wizard.ddChecking")}</span>
        </div>
        <Badge variant={DD_STATE_VARIANT[state]}>{state.replace(/_/g, " ")}</Badge>
      </div>

      {canStart && (
        <Button variant="outline" size="sm" onClick={startLocal} disabled={busy}>
          {busy ? t("wizard.ddStarting") : t("wizard.ddStartLocal")}
        </Button>
      )}

      <Separator />

      <div className="flex flex-col gap-2">
        <span className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("wizard.ddRemote")}</span>
        <div>
          <label className="text-xs text-text-muted mb-1 block">{t("wizard.ddUrl")}</label>
          <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://dojo.example.com" mono />
        </div>
        <div>
          <label className="text-xs text-text-muted mb-1 block">{t("wizard.ddToken")}</label>
          <Input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder={t("wizard.ddTokenHint")} />
        </div>
        <div>
          <Button variant="outline" size="sm" onClick={saveRemote} disabled={busy || !url.trim()}>
            {t("wizard.ddSave")}
          </Button>
        </div>
      </div>

      <span className="text-xs text-text-muted">{t("wizard.ddSkipHint")}</span>
    </div>
  );
}
