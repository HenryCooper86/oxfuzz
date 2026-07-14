// Storage tab -- SQLite database and transcript configuration.
// Controlled: reads/writes the parsed `storage` config object via props.

import { useEffect, useState } from "react";
import { Database, FolderOpen } from "lucide-react";
import { getTransport, pickFile, emitDataChanged } from "../../lib";
import { useI18n } from "../../i18n";
import { useToast } from "../ui/Toast";
import { Button, Input } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";

type Cfg = Record<string, unknown>;

export function StorageTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const { t } = useI18n();
  const { toast } = useToast();
  const dbPath = (value.db_path as string) ?? "";
  const transcriptDir = (value.transcript_dir as string) ?? "";

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

  function patch(next: Cfg) {
    onChange({ ...value, ...next });
  }

  async function browseDb() {
    const file = await pickFile(t("settings.storage.pickDbTitle"));
    if (file) patch({ db_path: file });
  }

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
      <SettingsGroup title={t("settings.storage.database")} description={t("settings.storage.databaseDesc")}>
        <SettingsItem title={t("settings.storage.sqlitePath")}>
          <div style={{ display: "flex", gap: 4, width: 220 }}>
            <Input value={dbPath} onChange={(e) => patch({ db_path: e.target.value })} mono />
            <button onClick={browseDb} aria-label={t("settings.storage.browseDb")} className="inline-flex items-center justify-center px-3 py-2 text-xs rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover" style={{ cursor: "pointer" }}>
              <FolderOpen size={14} />
            </button>
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.storage.transcripts")}>
        <SettingsItem title={t("settings.storage.transcriptDir")}>
          <div style={{ width: 220 }}>
            <Input value={transcriptDir} onChange={(e) => patch({ transcript_dir: e.target.value })} mono />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.storage.fuzzWorkspace")}>
        <SettingsItem title={t("settings.storage.location")}>
          <div style={{ width: 320 }}>
            <Input value={workspacePath} readOnly mono />
          </div>
        </SettingsItem>
        <SettingsItem title={t("common.reset")}>
          <Button variant={confirmClear ? "danger" : "outline"} onClick={clearWorkspace} disabled={clearing}>
            {clearing ? t("settings.storage.clearing") : confirmClear ? t("settings.storage.clickAgain") : t("settings.storage.clearWorkspace")}
          </Button>
        </SettingsItem>
        <div className="settings-item" style={{ padding: "10px 14px" }}>
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <Database size={12} />
            <span>
              {t("settings.storage.workspaceNotePre")} <code>HF_WORKSPACE_DIR</code> {t("settings.storage.workspaceNotePost")}
            </span>
          </div>
        </div>
      </SettingsGroup>
    </div>
  );
}
