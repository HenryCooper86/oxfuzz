// Storage tab -- service-resolved workspace location and cleanup.

import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { getTransport, emitDataChanged } from "../../lib";
import { isTauriEnvironment } from "../../lib/transport";
import { useI18n } from "../../i18nContext";
import { useToast } from "../ui/toastContext";
import { useConfirm } from "../../providers/confirm";
import { Button, Input } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";

export function StorageTab() {
  const { t } = useI18n();
  if (isTauriEnvironment()) return <DesktopStorageTab />;
  return (
    <SettingsGroup title={t("settings.storage.fuzzWorkspace")}>
      <p role="note" className="settings-item text-sm text-text-secondary">
        {t("settings.storage.desktopOnly")}
      </p>
    </SettingsGroup>
  );
}

function DesktopStorageTab() {
  const { t } = useI18n();
  const { toast } = useToast();

  // The fuzz workspace location is resolved by the service (persistent, under
  // the per-user data dir, overridable via HF_WORKSPACE_DIR), not a config
  // field -- so show the real resolved path rather than a dead editable input.
  const confirm = useConfirm();
  const [workspacePath, setWorkspacePath] = useState("");
  const [clearing, setClearing] = useState(false);
  const [deletingRecords, setDeletingRecords] = useState(false);

  useEffect(() => {
    getTransport()
      .invoke<{ config_dir: string; data_dir: string; workspace_dir: string }>("app_paths")
      .then((p) => setWorkspacePath(p.workspace_dir))
      .catch(() => {
        /* leave blank if the backend can't resolve it */
      });
  }, []);

  async function clearWorkspace() {
    const ok = await confirm({
      title: t("settings.storage.clearWorkspace"),
      message: t("settings.storage.clearWorkspaceConfirm"),
      danger: true,
      confirmLabel: t("settings.storage.clearWorkspace"),
    });
    if (!ok) return;
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
    }
  }

  // Every project's persisted fuzzing records. Per-project deletion lives in
  // Projects; this is the single all-project wipe in the app.
  async function deleteAllRecords() {
    const ok = await confirm({
      title: t("settings.storage.deleteRecords"),
      message: t("settings.storage.deleteRecordsConfirm"),
      danger: true,
      confirmLabel: t("common.delete"),
    });
    if (!ok) return;
    setDeletingRecords(true);
    try {
      await getTransport().invoke("clear_knowledge");
      emitDataChanged();
      toast({ title: t("settings.storage.recordsDeleted"), variant: "success" });
    } catch (e) {
      toast({ title: t("settings.storage.deleteRecordsFailed"), description: String(e), variant: "error" });
    } finally {
      setDeletingRecords(false);
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
            <Button variant="danger" onClick={() => void clearWorkspace()} disabled={clearing}>
              {clearing ? t("settings.storage.clearing") : t("settings.storage.clearWorkspace")}
            </Button>
          </div>
        </div>
      </SettingsGroup>
      <SettingsGroup title={t("settings.storage.records")}>
        <SettingsItem title={t("settings.storage.deleteRecords")} description={t("settings.storage.deleteRecordsHint")}>
          <Button variant="danger" onClick={() => void deleteAllRecords()} disabled={deletingRecords}>
            {deletingRecords ? t("settings.storage.clearing") : t("settings.storage.deleteRecords")}
          </Button>
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}
