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
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold">Runtime / Sandbox</h2>
        <p className="text-xs text-text-secondary mt-0.5">Configure the sandbox for harness compilation and fuzz execution. Safety-first: all builds and runs are isolated.</p>
      </div>

      <SettingsGroup title="Backend">
        <div className="flex gap-2 mb-3">
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
        <SettingsItem label="Docker Image">
          <Input value={image} onChange={(e) => setImage(e.target.value)} mono />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Resource Limits">
        <SettingsItem label="Max Memory (MB)">
          <Input type="number" value={maxMem} onChange={(e) => setMaxMem(parseInt(e.target.value) || 4096)} />
        </SettingsItem>
        <SettingsItem label="Max CPUs">
          <Input type="number" value={maxCpus} onChange={(e) => setMaxCpus(parseInt(e.target.value) || 2)} />
        </SettingsItem>
        <SettingsItem label="Max Duration (seconds)">
          <Input type="number" value={maxDuration} onChange={(e) => setMaxDuration(parseInt(e.target.value) || 7200)} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Network Access">
        <div className="flex items-center justify-between py-2">
          <div>
            <span className="text-xs text-text-primary">Build phase</span>
            <p className="text-xs text-text-muted">Allow network access during harness compilation (needed for package downloads).</p>
          </div>
          <Switch checked={networkBuild} onChange={setNetworkBuild} />
        </div>
        <div className="flex items-center justify-between py-2">
          <div>
            <span className="text-xs text-text-primary">Fuzz phase</span>
            <p className="text-xs text-text-muted">Allow network access during fuzzing. Not recommended -- untrusted code should not access the network.</p>
          </div>
          <Switch checked={networkFuzz} onChange={setNetworkFuzz} />
        </div>
      </SettingsGroup>
    </div>
  );
}