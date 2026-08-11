import { Badge, Input, Select, Switch } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { useI18n } from "../../i18nContext";
import {
  FUZZING_ENGINE_OPTIONS,
  normalizeFuzzingSettings,
  patchFuzzingSettings,
  type FuzzingEngineId,
  type FuzzingSettings,
} from "../../lib/fuzzingSettings";

type ConfigValue = Record<string, unknown>;

interface FuzzingTabProps {
  value: ConfigValue;
  onChange: (next: ConfigValue) => void;
}

export function FuzzingTab({ value, onChange }: FuzzingTabProps) {
  const { t } = useI18n();
  const normalized = normalizeFuzzingSettings(value);
  if (normalized.error !== null) {
    return (
      <div role="alert" className="text-text-secondary" style={{ fontSize: "13px" }}>
        {t("settings.fuzzing.retiredEngineConfig")}
      </div>
    );
  }
  const { settings } = normalized;
  const enabled = new Set(settings.enabled_engines);

  function update(next: FuzzingSettings) {
    onChange(patchFuzzingSettings(value, next));
  }

  function toggleEngine(engine: FuzzingEngineId, checked: boolean) {
    const nextEnabled = checked
      ? [...settings.enabled_engines, engine]
      : settings.enabled_engines.filter((candidate) => candidate !== engine);
    if (nextEnabled.length === 0) return;
    update({
      ...settings,
      enabled_engines: nextEnabled,
      default_engine: nextEnabled.includes(settings.default_engine)
        ? settings.default_engine
        : nextEnabled[0],
    });
  }

  function updateSandbox(patch: Partial<FuzzingSettings["sandbox"]>) {
    const sandbox = { ...settings.sandbox, ...patch };
    update({
      ...settings,
      default_duration_secs: Math.min(settings.default_duration_secs, sandbox.max_duration_secs),
      sandbox,
    });
  }

  return (
    <div style={{ animation: "fadeIn 0.2s ease" }}>
      <SettingsGroup
        title={t("settings.fuzzing.engines")}
        description={t("settings.fuzzing.enginesDesc")}
      >
        {FUZZING_ENGINE_OPTIONS.map((engine) => {
          const isEnabled = enabled.has(engine.value);
          return (
            <SettingsItem
              key={engine.value}
              title={engine.label}
              description={engine.value === "syzkaller"
                ? t("settings.fuzzing.syzkallerDesc")
                : t("settings.fuzzing.engineDesc")}
            >
              <div className="flex items-center gap-2">
                <Badge variant={isEnabled ? "success" : "default"}>
                  {isEnabled ? t("settings.fuzzing.enabled") : t("settings.fuzzing.disabled")}
                </Badge>
                <Switch
                  checked={isEnabled}
                  disabled={isEnabled && settings.enabled_engines.length === 1}
                  ariaLabel={engine.label}
                  onChange={(checked) => toggleEngine(engine.value, checked)}
                />
              </div>
            </SettingsItem>
          );
        })}
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.fuzzing.defaults")}
        description={t("settings.fuzzing.defaultsDesc")}
      >
        <SettingsItem title={t("settings.fuzzing.defaultEngine")}>
          <Select
            value={settings.default_engine}
            onChange={(value) => update({
              ...settings,
              default_engine: value as FuzzingEngineId,
            })}
            options={FUZZING_ENGINE_OPTIONS.filter((option) => enabled.has(option.value))}
            className="w-[190px]"
          />
        </SettingsItem>
        <SettingsItem title={t("settings.fuzzing.defaultDuration")}>
          <Input
            mono
            type="number"
            min={1}
            max={settings.sandbox.max_duration_secs}
            value={settings.default_duration_secs}
            onChange={(event) => update({
              ...settings,
              default_duration_secs: Math.max(1, Number(event.target.value) || 1),
            })}
            className="w-28"
          />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.fuzzing.resources")}
        description={t("settings.fuzzing.resourcesDesc")}
      >
        <SettingsItem title={t("settings.fuzzing.maxMemory")}>
          <Input
            mono
            type="number"
            min={1}
            max={65536}
            value={settings.sandbox.max_mem_mb}
            onChange={(event) => updateSandbox({
              max_mem_mb: Math.max(1, Number(event.target.value) || 1),
            })}
            className="w-28"
          />
        </SettingsItem>
        <SettingsItem title={t("settings.fuzzing.maxCpus")}>
          <Input
            mono
            type="number"
            min={1}
            max={64}
            value={settings.sandbox.max_cpus}
            onChange={(event) => updateSandbox({
              max_cpus: Math.max(1, Number(event.target.value) || 1),
            })}
            className="w-28"
          />
        </SettingsItem>
        <SettingsItem
          title={t("settings.fuzzing.maxDuration")}
          description={t("settings.fuzzing.maxDurationDesc")}
        >
          <Input
            mono
            type="number"
            min={1}
            max={604800}
            value={settings.sandbox.max_duration_secs}
            onChange={(event) => updateSandbox({
              max_duration_secs: Math.max(1, Number(event.target.value) || 1),
            })}
            className="w-28"
          />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.fuzzing.protections")}
        description={t("settings.fuzzing.protectionsDesc")}
      >
        <SettingsItem title={t("settings.fuzzing.sandboxRequired")}>
          <Badge variant="success">{t("settings.fuzzing.alwaysOn")}</Badge>
        </SettingsItem>
        <SettingsItem title={t("settings.fuzzing.approvalRequired")}>
          <Badge variant="success">{t("settings.fuzzing.required")}</Badge>
        </SettingsItem>
        <SettingsItem title={t("settings.fuzzing.networkBlocked")}>
          <Badge variant="success">{t("settings.fuzzing.blocked")}</Badge>
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}
