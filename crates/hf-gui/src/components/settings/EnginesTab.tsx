// Engines tab -- configure AFL++, honggfuzz, libFuzzer, ClusterFuzzLite.

import { useState } from "react";
import { Input } from "../ui/Input";
import { Switch } from "../ui/Switch";
import { Badge } from "../ui/Badge";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Crosshair, Bug, Zap, Cloud } from "lucide-react";

interface EngineConfig {
  id: string;
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  enabled: boolean;
  binary: string;
  default_duration: number;
  default_mem: number;
  supports: string[];
}

export function EnginesTab() {
  const [engines, setEngines] = useState<EngineConfig[]>([
    { id: "libfuzzer", label: "libFuzzer", icon: Zap, enabled: true, binary: "clang -fsanitize=fuzzer", default_duration: 3600, default_mem: 2048, supports: ["C", "C++", "Rust"] },
    { id: "afl++", label: "AFL++", icon: Crosshair, enabled: true, binary: "afl-fuzz", default_duration: 3600, default_mem: 2048, supports: ["C", "C++"] },
    { id: "honggfuzz", label: "honggfuzz", icon: Bug, enabled: true, binary: "honggfuzz", default_duration: 3600, default_mem: 2048, supports: ["C", "C++"] },
    { id: "clusterfuzzlite", label: "ClusterFuzzLite", icon: Cloud, enabled: false, binary: "python3 infra/helper.py", default_duration: 3600, default_mem: 2048, supports: ["C", "C++", "Rust", "Go", "Python"] },
  ]);

  function toggle(id: string) {
    setEngines(engines.map((e) => e.id === id ? { ...e, enabled: !e.enabled } : e));
  }
  function update(id: string, field: keyof EngineConfig, value: string | number) {
    setEngines(engines.map((e) => e.id === id ? { ...e, [field]: value } : e));
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold">Fuzzing Engines</h2>
        <p className="text-xs text-text-secondary mt-0.5">Configure and enable fuzzing engines. Disabled engines won't appear in the Run panel.</p>
      </div>

      {engines.map((e) => (
        <SettingsGroup key={e.id} title={e.label}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <e.icon size={16} />
              <span className="text-sm font-medium text-text-primary">{e.label}</span>
              {e.enabled ? <Badge variant="success">enabled</Badge> : <Badge>disabled</Badge>}
            </div>
            <Switch checked={e.enabled} onChange={() => toggle(e.id)} />
          </div>
          <SettingsItem label="Binary / Command">
            <Input value={e.binary} onChange={(ev) => update(e.id, "binary", ev.target.value)} mono disabled={!e.enabled} />
          </SettingsItem>
          <SettingsItem label="Default Duration (s)">
            <Input type="number" value={e.default_duration} onChange={(ev) => update(e.id, "default_duration", parseInt(ev.target.value) || 3600)} disabled={!e.enabled} />
          </SettingsItem>
          <SettingsItem label="Default Memory (MB)">
            <Input type="number" value={e.default_mem} onChange={(ev) => update(e.id, "default_mem", parseInt(ev.target.value) || 2048)} disabled={!e.enabled} />
          </SettingsItem>
          <div className="flex gap-1 mt-2">
            {e.supports.map((lang) => <Badge key={lang} variant="accent">{lang}</Badge>)}
          </div>
        </SettingsGroup>
      ))}
    </div>
  );
}