import { describe, expect, it } from "vitest";
import {
  parseAutomotiveIdList,
  parseAutomotiveTextList,
  setAutomotiveModeEnabled,
  isValidAutomotiveInterfaceList,
  setPhysicalBenchEnabled,
  toggleAutomotiveSelection,
} from "../lib/automotiveSettings";
import type { AutomotiveSettings } from "../lib/automotive";

const base: AutomotiveSettings = {
  enabled: false,
  sidecar_image: "hobot/scapy-automotive:2.7.0",
  allowed_protocols: ["can"],
  allowed_modes: ["offline_pcap", "virtual_can"],
  virtual_interfaces: ["vcan0"],
  limits: {
    max_packets: 10_000,
    max_input_bytes: 67_108_864,
    max_payload_bytes: 1_048_576,
    max_duration_secs: 300,
    max_rate_per_second: 100,
    max_output_bytes: 67_108_864,
    max_mem_mb: 1024,
    max_cpus: 1,
  },
  physical_bench: {
    enabled: false,
    require_approval: true,
    interfaces: [],
    arbitration_ids: [],
    uds_services: [],
    allow_dangerous_services: false,
  },
};

describe("automotive settings helpers", () => {
  it("enables and disables the physical mode with its policy atomically", () => {
    const enabled = setPhysicalBenchEnabled(base, true);
    expect(enabled.physical_bench.enabled).toBe(true);
    expect(enabled.physical_bench.require_approval).toBe(true);
    expect(enabled.allowed_modes).toContain("physical_bench");
    expect(enabled.limits.max_packets).toBe(1_000);
    expect(enabled.limits.max_duration_secs).toBeLessThanOrEqual(300);
    expect(enabled.limits.max_rate_per_second).toBeLessThanOrEqual(100);

    const disabled = setPhysicalBenchEnabled(enabled, false);
    expect(disabled.physical_bench.enabled).toBe(false);
    expect(disabled.allowed_modes).not.toContain("physical_bench");
  });

  it("clamps shared limits to the strictest selected adapter profile", () => {
    const offlineOnly: AutomotiveSettings = {
      ...base,
      allowed_modes: ["offline_pcap"],
      limits: {
        ...base.limits,
        max_packets: 100_000,
        max_duration_secs: 3_600,
        max_rate_per_second: 10_000,
      },
    };

    const withVirtual = setAutomotiveModeEnabled(offlineOnly, "virtual_can", true);
    expect(withVirtual.limits.max_packets).toBe(10_000);
    expect(withVirtual.limits.max_duration_secs).toBe(3_600);
    expect(withVirtual.limits.max_rate_per_second).toBe(1_000);

    const cannotRemoveLast = setAutomotiveModeEnabled(
      { ...base, allowed_modes: ["virtual_can"] },
      "virtual_can",
      false,
    );
    expect(cannotRemoveLast.allowed_modes).toEqual(["virtual_can"]);
  });

  it("never removes the final selected protocol or normal mode", () => {
    expect(toggleAutomotiveSelection(["can"], "can", false)).toEqual(["can"]);
    expect(toggleAutomotiveSelection(["can"], "uds", true)).toEqual(["can", "uds"]);
    expect(toggleAutomotiveSelection(["can", "uds"], "can", false)).toEqual(["uds"]);
  });

  it("normalizes comma-separated interface and numeric allowlists", () => {
    expect(parseAutomotiveTextList(" vcan0, vcan1, vcan0 ")).toEqual(["vcan0", "vcan1"]);
    expect(parseAutomotiveIdList("0x7e0, 2017, 0x7e0", 0x1fff_ffff)).toEqual([
      2016,
      2017,
    ]);
    expect(parseAutomotiveIdList("0x20000000", 0x1fff_ffff)).toBeNull();
    expect(parseAutomotiveIdList("not-an-id", 0xff)).toBeNull();
  });

  it("rejects empty or unsafe interface allowlists before save", () => {
    expect(isValidAutomotiveInterfaceList(["vcan0", "bench-can.1"])).toBe(true);
    expect(isValidAutomotiveInterfaceList([])).toBe(false);
    expect(isValidAutomotiveInterfaceList(["can 0"])).toBe(false);
    expect(isValidAutomotiveInterfaceList(["interface-name-too-long"])).toBe(false);
  });
});
