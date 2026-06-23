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
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold">Storage</h2>
        <p className="text-xs text-text-secondary mt-0.5">Configure where run data, transcripts, and fuzz artifacts are stored.</p>
      </div>

      <SettingsGroup title="Database">
        <SettingsItem label="SQLite Path">
          <div className="flex gap-1">
            <Input value={dbPath} onChange={(e) => setDbPath(e.target.value)} mono />
            <button className="inline-flex items-center justify-center px-3 py-2 text-xs rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover" style={{ cursor: "pointer" }}>
              <FolderOpen size={14} />
            </button>
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Transcripts">
        <SettingsItem label="Transcript Directory">
          <Input value={transcriptDir} onChange={(e) => setTranscriptDir(e.target.value)} mono />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Fuzz Workspace">
        <SettingsItem label="Workspace Path">
          <div className="flex gap-1">
            <Input value={workspace} onChange={(e) => setWorkspace(e.target.value)} mono />
            <button className="inline-flex items-center justify-center px-3 py-2 text-xs rounded-md border border-border bg-surface-primary text-text-secondary hover:bg-surface-hover" style={{ cursor: "pointer" }}>
              <FolderOpen size={14} />
            </button>
          </div>
        </SettingsItem>
        <div className="flex items-center gap-2 mt-2 text-xs text-text-muted">
          <Database size={12} />
          <span>Corpora, crashes, and compiled harnesses are stored in the workspace.</span>
        </div>
      </SettingsGroup>
    </div>
  );
}