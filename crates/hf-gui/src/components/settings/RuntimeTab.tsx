// Runtime tab -- Docker sandbox configuration.

import { useState } from "react";
import { Input } from "../ui/Input";
import { Switch } from "../ui/Switch";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Container } from "lucide-react";

export function RuntimeTab() {
  const [backend, setBackend] = useState<"docker" | "native">("docker");
  const [image, setImage] = useState("hobot/fuzz-sandbox:latest");
  const [maxMem, setMaxMem] = useState(4096);
  const [maxCpus, setMaxCpus] = useState(2);
  const [maxDuration, setMaxDuration] = useState(7200);
  const [networkBuild, setNetworkBuild] = useState(true);
  const [networkFuzz, setNetworkFuzz] = useState(false);

  return (
    <div>
      <SettingsGroup title="Backend" description="Configure the sandbox for harness compilation and fuzz execution. Safety-first: all builds and runs are isolated.">
        <div className="settings-item" style={{ padding: "10px 14px" }}>
        <div className="flex gap-2">
          <button
            onClick={() => setBackend("docker")}
            className="flex items-center gap-2 px-3 py-2 rounded-md transition-all duration-150"
            style={{
              background: backend === "docker" ? "var(--accent-subtle)" : "transparent",
              border: `1px solid ${backend === "docker" ? "var(--accent)" : "var(--border)"}`,
              color: backend === "docker" ? "var(--accent)" : "var(--text-muted)",
              cursor: "pointer",
            }}
          >
            <Container size={14} />
            <span className="text-xs font-medium">Docker (recommended)</span>
          </button>
          <button
            onClick={() => setBackend("native")}
            className="flex items-center gap-2 px-3 py-2 rounded-md transition-all duration-150"
            style={{
              background: backend === "native" ? "var(--accent-subtle)" : "transparent",
              border: `1px solid ${backend === "native" ? "var(--accent)" : "var(--border)"}`,
              color: backend === "native" ? "var(--accent)" : "var(--text-muted)",
              cursor: "pointer",
            }}
          >
            <span className="text-xs font-medium">Native (dev only)</span>
          </button>
        </div>
        </div>
        <SettingsItem title="Docker Image">
          <div style={{ width: 220 }}>
            <Input value={image} onChange={(e) => setImage(e.target.value)} mono />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Resource Limits">
        <SettingsItem title="Max Memory (MB)">
          <div style={{ width: 120 }}>
            <Input type="number" value={maxMem} onChange={(e) => setMaxMem(parseInt(e.target.value) || 4096)} />
          </div>
        </SettingsItem>
        <SettingsItem title="Max CPUs">
          <div style={{ width: 120 }}>
            <Input type="number" value={maxCpus} onChange={(e) => setMaxCpus(parseInt(e.target.value) || 2)} />
          </div>
        </SettingsItem>
        <SettingsItem title="Max Duration (seconds)">
          <div style={{ width: 120 }}>
            <Input type="number" value={maxDuration} onChange={(e) => setMaxDuration(parseInt(e.target.value) || 7200)} />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Network Access">
        <SettingsItem title="Build phase" description="Allow network access during harness compilation (needed for package downloads).">
          <Switch checked={networkBuild} onChange={setNetworkBuild} />
        </SettingsItem>
        <SettingsItem title="Fuzz phase" description="Allow network access during fuzzing. Not recommended -- untrusted code should not access the network.">
          <Switch checked={networkFuzz} onChange={setNetworkFuzz} />
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}