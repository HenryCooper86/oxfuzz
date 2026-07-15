// Storage tab -- service-resolved workspace location and cleanup.

import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { getTransport, emitDataChanged } from "../../lib";
import { useI18n } from "../../i18nContext";
import { useToast } from "../ui/toastContext";
import { Button, Input } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";

export function StorageTab() {
  const { t } = useI18n();
  const { toast } = useToast();

  // The fuzz workspace location is resolved by the service (persistent, under
  // the per-user data dir, overridable via HF_WORKSPACE_DIR), not a config
  // field -- so show the real resolved path rather than a dead editable input.
  const [workspacePath, setWorkspacePath] = useState("");
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    getTransport()
      .invoke<{ config_dir: string; data_dir: string; workspace_dir: string }>("app_paths")
      .then((p) => setWorkspacePath(p.workspace_dir))
      .catch(() => {
        /* leave blank if the backend can't resolve it */
      });
  }, []);

  async function clearWorkspace() {
    if (!confirmClear) {
      setConfirmClear(true);
      return;
    }
    setClearing(true);
    try {
      await getTransport().invoke("clear_workspace");
      // Corpus/artifact views read from these now-deleted files -- refresh them.
      emitDataChanged();
      toast({ title: t("settings.storage.workspaceCleared"), description: t("settings.storage.workspaceClearedDesc"), variant: "success" });
    } catch (e) {
      toast({ title: t("settings.storage.clearFailed"), description: String(e), variant: "error" });
    } finally {
      setClearing(false);
      setConfirmClear(false);
    }
  }

  return (
    <div>
      <SettingsGroup title={t("settings.storage.fuzzWorkspace")}>
        <SettingsItem title={t("settings.storage.location")}>
          <div style={{ width: 320 }}>
            <Input value={workspacePath} readOnly mono />
          </div>
        </SettingsItem>
        <div
          role="note"
          aria-label={t("common.warning")}
          className="settings-item flex items-start gap-3"
          style={{
            padding: "var(--space-md)",
            borderLeft: "3px solid var(--warning, #d9a441)",
            background: "var(--surface-secondary)",
          }}
        >
          <AlertTriangle
            size={18}
            style={{ color: "var(--warning, #d9a441)", flexShrink: 0, marginTop: 1 }}
          />
          <div className="flex flex-1 flex-col gap-1 min-w-0">
            <span className="text-sm font-semibold text-text-primary">{t("common.warning")}</span>
            <span className="text-xs text-text-secondary">
              {t("settings.storage.workspaceNotePre")} <code>HF_WORKSPACE_DIR</code>{" "}
              {t("settings.storage.workspaceNotePost")}
            </span>
          </div>
          <div className="shrink-0">
            <Button variant="danger" onClick={clearWorkspace} disabled={clearing}>
              {clearing
                ? t("settings.storage.clearing")
                : confirmClear
                  ? t("settings.storage.clickAgain")
                  : t("settings.storage.clearWorkspace")}
            </Button>
          </div>
        </div>
      </SettingsGroup>
    </div>
  );
}
