// Runtime tab -- Docker sandbox configuration.
// Controlled: reads/writes the parsed `runtime` config object via props. The
// SettingsView orchestrator owns load + save + dirty tracking.

import { Input } from "../ui/Input";
import { Switch } from "../ui/Switch";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Container } from "lucide-react";
import { useI18n } from "../../i18n";

type Cfg = Record<string, unknown>;

export function RuntimeTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const { t } = useI18n();
  const backend = (value.backend as string) === "native" ? "native" : "docker";
  const image = (value.docker_image as string) ?? "";
  const limits = (value.limits as Cfg) ?? {};
  const network = (value.network as Cfg) ?? {};
  const maxMem = (limits.max_mem_mb as number) ?? 4096;
  const maxCpus = (limits.max_cpus as number) ?? 2;
  const maxDuration = (limits.max_duration_secs as number) ?? 7200;
  const networkBuild = network.build !== false;
  const networkFuzz = network.fuzz === true;

  function patch(next: Cfg) {
    onChange({ ...value, ...next });
  }
  function patchLimits(next: Cfg) {
    onChange({ ...value, limits: { ...limits, ...next } });
  }
  function patchNetwork(next: Cfg) {
    onChange({ ...value, network: { ...network, ...next } });
  }

  return (
    <div>
      <SettingsGroup title={t("settings.runtime.backend")} description={t("settings.runtime.backendDesc")}>
        <div className="settings-item" style={{ padding: "10px 14px" }}>
        <div className="flex gap-2">
          <button
            onClick={() => patch({ backend: "docker" })}
            className="flex items-center gap-2 px-3 py-2 rounded-md transition-all duration-150"
            style={{
              background: backend === "docker" ? "var(--accent-subtle)" : "transparent",
              border: `1px solid ${backend === "docker" ? "var(--accent)" : "var(--border)"}`,
              color: backend === "docker" ? "var(--accent)" : "var(--text-muted)",
              cursor: "pointer",
            }}
          >
            <Container size={14} />
            <span className="text-xs font-medium">{t("settings.runtime.docker")}</span>
          </button>
          <button
            onClick={() => patch({ backend: "native" })}
            className="flex items-center gap-2 px-3 py-2 rounded-md transition-all duration-150"
            style={{
              background: backend === "native" ? "var(--accent-subtle)" : "transparent",
              border: `1px solid ${backend === "native" ? "var(--accent)" : "var(--border)"}`,
              color: backend === "native" ? "var(--accent)" : "var(--text-muted)",
              cursor: "pointer",
            }}
          >
            <span className="text-xs font-medium">{t("settings.runtime.native")}</span>
          </button>
        </div>
        </div>
        <SettingsItem title={t("settings.runtime.dockerImage")}>
          <div style={{ width: 220 }}>
            <Input value={image} onChange={(e) => patch({ docker_image: e.target.value })} mono />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.runtime.resourceLimits")}>
        <SettingsItem title={t("settings.runtime.maxMemory")}>
          <div style={{ width: 120 }}>
            <Input type="number" value={maxMem} onChange={(e) => patchLimits({ max_mem_mb: parseInt(e.target.value) || 4096 })} />
          </div>
        </SettingsItem>
        <SettingsItem title={t("settings.runtime.maxCpus")}>
          <div style={{ width: 120 }}>
            <Input type="number" value={maxCpus} onChange={(e) => patchLimits({ max_cpus: parseInt(e.target.value) || 2 })} />
          </div>
        </SettingsItem>
        <SettingsItem title={t("settings.runtime.maxDuration")}>
          <div style={{ width: 120 }}>
            <Input type="number" value={maxDuration} onChange={(e) => patchLimits({ max_duration_secs: parseInt(e.target.value) || 7200 })} />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.runtime.networkAccess")}>
        <SettingsItem title={t("settings.runtime.buildPhase")} description={t("settings.runtime.buildPhaseDesc")}>
          <Switch checked={networkBuild} onChange={(v) => patchNetwork({ build: v })} />
        </SettingsItem>
        <SettingsItem title={t("settings.runtime.fuzzPhase")} description={t("settings.runtime.fuzzPhaseDesc")}>
          <Switch checked={networkFuzz} onChange={(v) => patchNetwork({ fuzz: v })} />
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}
