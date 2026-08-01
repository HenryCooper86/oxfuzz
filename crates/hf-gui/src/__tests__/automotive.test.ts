import { describe, expect, it, vi } from "vitest";
import {
  analyzeAutomotiveCapture,
  buildAutomotiveReplayPlan,
  executeAutomotiveReplay,
  generateAutomotiveReport,
  generateAutomotiveMutations,
  getAutomotiveSettings,
  inspectAutomotiveCapabilities,
  listAutomotiveOperations,
  setAutomotiveSettings,
  type AutomotiveSettings,
} from "../lib/automotive";
import type { Transport } from "../lib/transport";

const settings: AutomotiveSettings = {
  enabled: false,
  sidecar_image: "oxfuzz/scapy-automotive:2.7.0",
  allowed_protocols: ["can", "uds"],
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

describe("automotive frontend transport", () => {
  it("uses the exact service command names and camelCase Tauri arguments", async () => {
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      void command;
      void args;
      return {};
    });
    const transport: Transport = {
      invoke: async <T>(command: string, args?: Record<string, unknown>) =>
        (args === undefined ? invoke(command) : invoke(command, args)) as Promise<T>,
      listen: async () => () => {},
    };

    await getAutomotiveSettings(transport);
    await setAutomotiveSettings(settings, transport);
    await inspectAutomotiveCapabilities("/tmp/project", transport);
    await analyzeAutomotiveCapture(
      {
        projectRoot: "/tmp/project",
        protocol: "uds",
        capturePath: "/tmp/capture.pcap",
      },
      transport,
    );
    await executeAutomotiveReplay(
      {
        projectRoot: "/tmp/project",
        mode: { mode: "virtual_can", interface: "vcan0" },
        plan: {
          protocol: "uds",
          mode: "virtual_can",
          deterministic_seed: 7,
          steps: [
            {
              sequence: 0,
              delay_micros: 0,
              action: "send",
              message: {
                protocol: "uds",
                payload_hex: "221234",
                fields: { arbitration_id: "0x7e0", service: "0x22" },
              },
            },
          ],
        },
      },
      transport,
    );
    await generateAutomotiveMutations(
      {
        projectRoot: "/tmp/project",
        protocol: "uds",
        sourcePath: "/tmp/transcript.json",
        deterministicSeed: 7,
        mutationCount: 16,
        mediaType: "application/vnd.oxfuzz.automotive-transcript+json",
      },
      transport,
    );
    await buildAutomotiveReplayPlan(
      {
        projectRoot: "/tmp/project",
        protocol: "uds",
        sourcePath: "/tmp/transcript.json",
        targetMode: "virtual_can",
        deterministicSeed: 7,
      },
      transport,
    );
    await listAutomotiveOperations("/tmp/project", 25, transport);
    await generateAutomotiveReport("/tmp/project", true, "zh", transport);

    expect(invoke.mock.calls).toEqual([
      ["get_automotive_settings"],
      ["set_automotive_settings", { settings }],
      ["automotive_capabilities", { projectRoot: "/tmp/project" }],
      [
        "automotive_analyze_capture",
        {
          projectRoot: "/tmp/project",
          protocol: "uds",
          capturePath: "/tmp/capture.pcap",
        },
      ],
      [
        "automotive_execute_replay",
        {
          projectRoot: "/tmp/project",
          mode: { mode: "virtual_can", interface: "vcan0" },
          plan: {
            protocol: "uds",
            mode: "virtual_can",
            deterministic_seed: 7,
            steps: [
              {
                sequence: 0,
                delay_micros: 0,
                action: "send",
                message: {
                  protocol: "uds",
                  payload_hex: "221234",
                  fields: { arbitration_id: "0x7e0", service: "0x22" },
                },
              },
            ],
          },
        },
      ],
      [
        "automotive_generate_mutations",
        {
          projectRoot: "/tmp/project",
          protocol: "uds",
          sourcePath: "/tmp/transcript.json",
          deterministicSeed: 7,
          mutationCount: 16,
          mediaType: "application/vnd.oxfuzz.automotive-transcript+json",
        },
      ],
      [
        "automotive_build_replay_plan",
        {
          projectRoot: "/tmp/project",
          protocol: "uds",
          sourcePath: "/tmp/transcript.json",
          targetMode: "virtual_can",
          deterministicSeed: 7,
        },
      ],
      ["list_automotive_operations", { projectRoot: "/tmp/project", limit: 25 }],
      [
        "generate_automotive_report",
        { projectRoot: "/tmp/project", includeAi: true, language: "zh" },
      ],
    ]);
  });
});
