import type {
  AutomotiveLimitSettings,
  AutomotiveMode,
  AutomotiveProtocol,
  AutomotiveSettings,
} from "./automotive";

type ModeBoundedLimit = "max_packets" | "max_duration_secs" | "max_rate_per_second";

const MODE_LIMITS: Record<AutomotiveMode, Record<ModeBoundedLimit, number>> = {
  offline_pcap: {
    max_packets: 100_000,
    max_duration_secs: 3_600,
    max_rate_per_second: 10_000,
  },
  virtual_can: {
    max_packets: 10_000,
    max_duration_secs: 3_600,
    max_rate_per_second: 1_000,
  },
  physical_bench: {
    max_packets: 1_000,
    max_duration_secs: 300,
    max_rate_per_second: 100,
  },
};

export function automotiveLimitMaximums(
  modes: readonly AutomotiveMode[],
): Record<ModeBoundedLimit, number> {
  const selected: readonly AutomotiveMode[] = modes.length > 0 ? modes : ["offline_pcap"];
  return selected.reduce(
    (limits, mode) => ({
      max_packets: Math.min(limits.max_packets, MODE_LIMITS[mode].max_packets),
      max_duration_secs: Math.min(
        limits.max_duration_secs,
        MODE_LIMITS[mode].max_duration_secs,
      ),
      max_rate_per_second: Math.min(
        limits.max_rate_per_second,
        MODE_LIMITS[mode].max_rate_per_second,
      ),
    }),
    {
      max_packets: Number.MAX_SAFE_INTEGER,
      max_duration_secs: Number.MAX_SAFE_INTEGER,
      max_rate_per_second: Number.MAX_SAFE_INTEGER,
    },
  );
}

function clampModeBoundedLimits(
  limits: AutomotiveLimitSettings,
  modes: readonly AutomotiveMode[],
): AutomotiveLimitSettings {
  const maximums = automotiveLimitMaximums(modes);
  return {
    ...limits,
    max_packets: Math.min(limits.max_packets, maximums.max_packets),
    max_duration_secs: Math.min(limits.max_duration_secs, maximums.max_duration_secs),
    max_rate_per_second: Math.min(
      limits.max_rate_per_second,
      maximums.max_rate_per_second,
    ),
  };
}

export const AUTOMOTIVE_PROTOCOL_OPTIONS: readonly {
  value: AutomotiveProtocol;
  label: string;
}[] = [
  { value: "can", label: "CAN" },
  { value: "can_fd", label: "CAN FD" },
  { value: "iso_tp", label: "ISO-TP" },
  { value: "uds", label: "UDS" },
  { value: "gmlan", label: "GMLAN" },
  { value: "some_ip", label: "SOME/IP" },
  { value: "some_ip_sd", label: "SOME/IP-SD" },
  { value: "do_ip", label: "DoIP" },
  { value: "obd", label: "OBD" },
  { value: "ccp", label: "CCP" },
  { value: "xcp", label: "XCP" },
  { value: "bmw_hsfz", label: "BMW HSFZ" },
  { value: "sec_oc", label: "SecOC" },
];

export const AUTOMOTIVE_MODE_OPTIONS: readonly {
  value: Exclude<AutomotiveMode, "physical_bench">;
  label: string;
}[] = [
  { value: "offline_pcap", label: "Offline PCAP" },
  { value: "virtual_can", label: "Virtual CAN" },
];

export function toggleAutomotiveSelection<T extends string>(
  values: readonly T[],
  value: T,
  enabled: boolean,
): T[] {
  const unique = [...new Set(values)];
  if (enabled) return unique.includes(value) ? unique : [...unique, value];
  if (!unique.includes(value) || unique.length === 1) return unique;
  return unique.filter((candidate) => candidate !== value);
}

export function setPhysicalBenchEnabled(
  settings: AutomotiveSettings,
  enabled: boolean,
): AutomotiveSettings {
  const normalModes = settings.allowed_modes.filter((mode) => mode !== "physical_bench");
  const allowedModes: AutomotiveMode[] = enabled
    ? [...normalModes, "physical_bench"]
    : normalModes;
  return {
    ...settings,
    allowed_modes: allowedModes,
    limits: clampModeBoundedLimits(settings.limits, allowedModes),
    physical_bench: {
      ...settings.physical_bench,
      enabled,
      require_approval: true,
      allow_dangerous_services: enabled
        ? settings.physical_bench.allow_dangerous_services
        : false,
    },
  };
}

export function setAutomotiveModeEnabled(
  settings: AutomotiveSettings,
  mode: Exclude<AutomotiveMode, "physical_bench">,
  enabled: boolean,
): AutomotiveSettings {
  const normalModes = settings.allowed_modes.filter(
    (candidate): candidate is Exclude<AutomotiveMode, "physical_bench"> =>
      candidate !== "physical_bench",
  );
  const nextNormalModes = toggleAutomotiveSelection(normalModes, mode, enabled);
  const allowedModes: AutomotiveMode[] = settings.physical_bench.enabled
    ? [...nextNormalModes, "physical_bench"]
    : nextNormalModes;
  return {
    ...settings,
    allowed_modes: allowedModes,
    limits: clampModeBoundedLimits(settings.limits, allowedModes),
  };
}

export function parseAutomotiveTextList(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\n,]/)
        .map((entry) => entry.trim())
        .filter(Boolean),
    ),
  ];
}

export function isValidAutomotiveInterfaceList(values: readonly string[]): boolean {
  return values.length > 0
    && values.every((value) => /^[A-Za-z0-9_.-]{1,15}$/.test(value));
}

export function parseAutomotiveIdList(value: string, maximum: number): number[] | null {
  const entries = value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
  const parsed: number[] = [];
  for (const entry of entries) {
    if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(entry)) return null;
    const number = Number.parseInt(entry, entry.toLowerCase().startsWith("0x") ? 16 : 10);
    if (!Number.isSafeInteger(number) || number < 0 || number > maximum) return null;
    if (!parsed.includes(number)) parsed.push(number);
  }
  return parsed;
}

export function formatAutomotiveIdList(values: readonly number[]): string {
  return values.map((value) => `0x${value.toString(16)}`).join(", ");
}
