// Storage tab -- SQLite database and transcript configuration.

import { useState } from "react";
import { Input } from "../ui/Input";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Database, FolderOpen } from "lucide-react";

export function StorageTab() {
  const [dbPath, setDbPath] = useState("data/hobot_fuzz.db");
  const [transcriptDir, setTranscriptDir] = useState("data/transcripts");
  const [workspace, setWorkspace] = useState("/tmp/hobot_fuzz_workspace");

  return (
    <div>
      <SettingsGroup title="Database" description="Configure where run data, transcripts, and fuzz artifacts are stored.">
        <SettingsItem title="SQLite Path">
          <div style={{ display: "flex", gap: 4, width: 220 }}>
            <Input value={dbPath} onChange={(e) => setDbPath(e.target.value)} mono />
            <button className="inline-flex items-center justify-center px-3 py-2 text-xs rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover" style={{ cursor: "pointer" }}>
              <FolderOpen size={14} />
            </button>
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Transcripts">
        <SettingsItem title="Transcript Directory">
          <div style={{ width: 220 }}>
            <Input value={transcriptDir} onChange={(e) => setTranscriptDir(e.target.value)} mono />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Fuzz Workspace">
        <SettingsItem title="Workspace Path">
          <div style={{ display: "flex", gap: 4, width: 220 }}>
            <Input value={workspace} onChange={(e) => setWorkspace(e.target.value)} mono />
            <button className="inline-flex items-center justify-center px-3 py-2 text-xs rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover" style={{ cursor: "pointer" }}>
              <FolderOpen size={14} />
            </button>
          </div>
        </SettingsItem>
        <div className="settings-item" style={{ padding: "10px 14px" }}>
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <Database size={12} />
            <span>Corpora, crashes, and compiled harnesses are stored in the workspace.</span>
          </div>
        </div>
      </SettingsGroup>
    </div>
  );
}