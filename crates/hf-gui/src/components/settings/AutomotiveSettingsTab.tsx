import { AlertTriangle, LockKeyhole } from "lucide-react";
import { Badge, Input, Switch } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { useI18n } from "../../i18nContext";
import type {
  AutomotiveLimitSettings,
  AutomotiveSettings,
} from "../../lib/automotive";
import {
  AUTOMOTIVE_MODE_OPTIONS,
  AUTOMOTIVE_PROTOCOL_OPTIONS,
  automotiveLimitMaximums,
  formatAutomotiveIdList,
  isValidAutomotiveInterfaceList,
  parseAutomotiveIdList,
  parseAutomotiveTextList,
  setPhysicalBenchEnabled,
  setAutomotiveModeEnabled,
  toggleAutomotiveSelection,
} from "../../lib/automotiveSettings";

interface AutomotiveSettingsTabProps {
  value: AutomotiveSettings;
  onChange: (next: AutomotiveSettings) => void;
}

const LIMIT_FIELDS: readonly {
  key: keyof AutomotiveLimitSettings;
  labelKey: string;
  maximum: number;
}[] = [
  { key: "max_packets", labelKey: "settings.automotive.maxPackets", maximum: 1_000_000 },
  { key: "max_input_bytes", labelKey: "settings.automotive.maxInputBytes", maximum: 1_073_741_824 },
  { key: "max_payload_bytes", labelKey: "settings.automotive.maxPayloadBytes", maximum: 1_048_576 },
  { key: "max_duration_secs", labelKey: "settings.automotive.maxDuration", maximum: 3_600 },
  { key: "max_rate_per_second", labelKey: "settings.automotive.maxRate", maximum: 10_000 },
  { key: "max_output_bytes", labelKey: "settings.automotive.maxOutputBytes", maximum: 536_870_912 },
  { key: "max_mem_mb", labelKey: "settings.automotive.maxMemory", maximum: 8_192 },
  { key: "max_cpus", labelKey: "settings.automotive.maxCpus", maximum: 8 },
];

function hasPinnedImageReference(image: string): boolean {
  const value = image.trim();
  return /@sha256:[0-9a-f]{64}$/i.test(value)
    || /:[^/:]+$/.test(value) && !/:latest$/i.test(value);
}

export function AutomotiveSettingsTab({ value, onChange }: AutomotiveSettingsTabProps) {
  const { t } = useI18n();
  const pinnedImage = hasPinnedImageReference(value.sidecar_image);
  const modeMaximums = automotiveLimitMaximums(value.allowed_modes);

  function updateLimits(key: keyof AutomotiveLimitSettings, next: number, maximum: number) {
    onChange({
      ...value,
      limits: {
        ...value.limits,
        [key]: Math.min(maximum, Math.max(1, next || 1)),
      },
    });
  }

  function updatePhysical(patch: Partial<AutomotiveSettings["physical_bench"]>) {
    onChange({
      ...value,
      physical_bench: {
        ...value.physical_bench,
        ...patch,
        require_approval: true,
      },
    });
  }

  return (
    <div style={{ animation: "fadeIn 0.2s ease" }}>
      <SettingsGroup
        title={t("settings.automotive.availability")}
        description={t("settings.automotive.availabilityDesc")}
      >
        <SettingsItem
          title={t("settings.automotive.enabled")}
          description={t("settings.automotive.enabledDesc")}
        >
          <Switch
            checked={value.enabled}
            ariaLabel={t("settings.automotive.enabled")}
            onChange={(enabled) => onChange({ ...value, enabled })}
          />
        </SettingsItem>
        <SettingsItem
          title={t("settings.automotive.sidecarImage")}
          description={t("settings.automotive.sidecarImageDesc")}
          stacked
        >
          <Input
            mono
            value={value.sidecar_image}
            aria-invalid={!pinnedImage}
            onChange={(event) => onChange({ ...value, sidecar_image: event.target.value })}
            placeholder="registry.example/hobot-scapy:2.7.0"
          />
          {!pinnedImage && (
            <div role="alert" className="mt-2 text-11px text-warning">
              {t("settings.automotive.sidecarImageInvalid")}
            </div>
          )}
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.automotive.protocols")}
        description={t("settings.automotive.protocolsDesc")}
      >
        <SettingsItem title={t("settings.automotive.allowedProtocols")} stacked>
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
            {AUTOMOTIVE_PROTOCOL_OPTIONS.map((option) => {
              const checked = value.allowed_protocols.includes(option.value);
              return (
                <label
                  key={option.value}
                  className="flex items-center gap-2 rounded-md border border-border bg-surface-primary px-3 py-2 text-12px text-text-primary"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={checked && value.allowed_protocols.length === 1}
                    onChange={(event) => onChange({
                      ...value,
                      allowed_protocols: toggleAutomotiveSelection(
                        value.allowed_protocols,
                        option.value,
                        event.target.checked,
                      ),
                    })}
                  />
                  {option.label}
                </label>
              );
            })}
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.automotive.modes")}
        description={t("settings.automotive.modesDesc")}
      >
        <SettingsItem title={t("settings.automotive.normalModes")} stacked>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {AUTOMOTIVE_MODE_OPTIONS.map((option) => {
              const checked = value.allowed_modes.includes(option.value);
              const normalModeCount = value.allowed_modes.filter(
                (mode) => mode !== "physical_bench",
              ).length;
              return (
                <label
                  key={option.value}
                  className="flex items-center gap-2 rounded-md border border-border bg-surface-primary px-3 py-2 text-12px text-text-primary"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={checked && normalModeCount === 1}
                    onChange={(event) => onChange(setAutomotiveModeEnabled(
                      value,
                      option.value,
                      event.target.checked,
                    ))}
                  />
                  {option.label}
                </label>
              );
            })}
          </div>
        </SettingsItem>
        <SettingsItem
          title={t("settings.automotive.virtualInterfaces")}
          description={t("settings.automotive.virtualInterfacesDesc")}
          stacked
        >
          <Input
            key={value.virtual_interfaces.join(",")}
            mono
            defaultValue={value.virtual_interfaces.join(", ")}
            placeholder="vcan0, vcan1"
            onBlur={(event) => {
              const interfaces = parseAutomotiveTextList(event.target.value);
              const valid = isValidAutomotiveInterfaceList(interfaces);
              event.target.setCustomValidity(
                valid ? "" : t("settings.automotive.invalidInterfaces"),
              );
              if (valid) onChange({ ...value, virtual_interfaces: interfaces });
              else event.target.reportValidity();
            }}
          />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.automotive.resources")}
        description={t("settings.automotive.resourcesDesc")}
      >
        {LIMIT_FIELDS.map((field) => {
          const maximum = field.key === "max_packets"
            || field.key === "max_duration_secs"
            || field.key === "max_rate_per_second"
            ? modeMaximums[field.key]
            : field.maximum;
          return (
          <SettingsItem key={field.key} title={t(field.labelKey)}>
            <Input
              mono
              type="number"
              min={1}
              max={maximum}
              value={value.limits[field.key]}
              onChange={(event) => updateLimits(
                field.key,
                Number(event.target.value),
                maximum,
              )}
              className="w-36"
            />
          </SettingsItem>
          );
        })}
      </SettingsGroup>

      <SettingsGroup
        title={t("settings.automotive.physicalBench")}
        description={t("settings.automotive.physicalBenchDesc")}
      >
        <div
          role="note"
          className="flex gap-3 border-b border-border bg-warning/5 px-4 py-3 text-12px text-text-secondary"
        >
          <AlertTriangle size={18} className="shrink-0 text-warning" aria-hidden="true" />
          <span>{t("settings.automotive.physicalWarning")}</span>
        </div>
        <SettingsItem
          title={t("settings.automotive.physicalEnabled")}
          description={t("settings.automotive.physicalEnabledDesc")}
        >
          <div className="flex items-center gap-2">
            <Badge variant={value.physical_bench.enabled ? "warning" : "default"}>
              {value.physical_bench.enabled
                ? t("settings.automotive.policyReady")
                : t("settings.automotive.disabledByDefault")}
            </Badge>
            <Switch
              checked={value.physical_bench.enabled}
              ariaLabel={t("settings.automotive.physicalEnabled")}
              onChange={(enabled) => onChange(setPhysicalBenchEnabled(value, enabled))}
            />
          </div>
        </SettingsItem>
        <SettingsItem
          title={t("settings.automotive.approval")}
          description={t("settings.automotive.approvalDesc")}
        >
          <Badge variant="success">
            <span className="inline-flex items-center gap-1">
              <LockKeyhole size={11} aria-hidden="true" />
              {t("settings.automotive.mandatory")}
            </span>
          </Badge>
        </SettingsItem>
        <SettingsItem
          title={t("settings.automotive.physicalInterfaces")}
          description={t("settings.automotive.physicalInterfacesDesc")}
          stacked
        >
          <Input
            key={value.physical_bench.interfaces.join(",")}
            mono
            disabled={!value.physical_bench.enabled}
            defaultValue={value.physical_bench.interfaces.join(", ")}
            placeholder="can0"
            onBlur={(event) => {
              const interfaces = parseAutomotiveTextList(event.target.value);
              const valid = isValidAutomotiveInterfaceList(interfaces);
              event.target.setCustomValidity(
                valid ? "" : t("settings.automotive.invalidInterfaces"),
              );
              if (valid) updatePhysical({ interfaces });
              else event.target.reportValidity();
            }}
          />
        </SettingsItem>
        <SettingsItem
          title={t("settings.automotive.arbitrationIds")}
          description={t("settings.automotive.arbitrationIdsDesc")}
          stacked
        >
          <Input
            key={value.physical_bench.arbitration_ids.join(",")}
            mono
            disabled={!value.physical_bench.enabled}
            defaultValue={formatAutomotiveIdList(value.physical_bench.arbitration_ids)}
            placeholder="0x7e0, 0x7e8"
            onBlur={(event) => {
              const ids = parseAutomotiveIdList(event.target.value, 0x1fff_ffff);
              event.target.setCustomValidity(ids ? "" : t("settings.automotive.invalidIdList"));
              if (ids) updatePhysical({ arbitration_ids: ids });
              else event.target.reportValidity();
            }}
          />
        </SettingsItem>
        <SettingsItem
          title={t("settings.automotive.udsServices")}
          description={t("settings.automotive.udsServicesDesc")}
          stacked
        >
          <Input
            key={value.physical_bench.uds_services.join(",")}
            mono
            disabled={!value.physical_bench.enabled}
            defaultValue={formatAutomotiveIdList(value.physical_bench.uds_services)}
            placeholder="0x10, 0x22"
            onBlur={(event) => {
              const services = parseAutomotiveIdList(event.target.value, 0xff);
              event.target.setCustomValidity(
                services ? "" : t("settings.automotive.invalidServiceList"),
              );
              if (services) updatePhysical({ uds_services: services });
              else event.target.reportValidity();
            }}
          />
        </SettingsItem>
        <SettingsItem
          title={t("settings.automotive.dangerousServices")}
          description={t("settings.automotive.dangerousServicesDesc")}
        >
          <Switch
            checked={value.physical_bench.allow_dangerous_services}
            disabled={!value.physical_bench.enabled}
            ariaLabel={t("settings.automotive.dangerousServices")}
            onChange={(allow_dangerous_services) => updatePhysical({
              allow_dangerous_services,
            })}
          />
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}
