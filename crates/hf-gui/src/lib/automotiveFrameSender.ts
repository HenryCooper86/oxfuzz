import type {
  AutomotiveLimitSettings,
  AutomotiveReplayPlan,
  AutomotiveReplayStep,
} from "./automotive";

const MAX_CLASSIC_CAN_ID = 0x1fffffff;
const MAX_CLASSIC_CAN_PAYLOAD_BYTES = 8;

export interface PeriodicCanReplayInput {
  arbitrationId: string;
  payload: string;
  intervalMs: number;
  count: number;
  limits: AutomotiveLimitSettings;
}

function normalizeHex(input: string): string | null {
  const cleaned = input.replace(/[\s_]/g, "").toLowerCase();
  if (cleaned.length === 0 || cleaned.length % 2 !== 0 || !/^[0-9a-f]+$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

function parseArbitrationId(input: string): number | null {
  const trimmed = input.trim();
  const radix = /^0x[0-9a-f]+$/i.test(trimmed) ? 16 : /^\d+$/.test(trimmed) ? 10 : null;
  if (radix === null) return null;
  const value = Number.parseInt(trimmed, radix);
  return Number.isSafeInteger(value) && value <= MAX_CLASSIC_CAN_ID ? value : null;
}

function validPositiveLimit(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

/**
 * Build a bounded periodic classic-CAN replay plan, or return null when the UI
 * input cannot satisfy the effective service limits. This is an allocation
 * guard and operator-facing preflight only; the Rust service and sidecar repeat
 * authoritative contract and policy validation before execution.
 */
export function buildPeriodicCanReplayPlan(
  input: PeriodicCanReplayInput,
): AutomotiveReplayPlan | null {
  const payloadHex = normalizeHex(input.payload);
  const arbitrationId = parseArbitrationId(input.arbitrationId);
  const payloadBytes = payloadHex === null ? 0 : payloadHex.length / 2;
  const { limits } = input;

  if (
    payloadHex === null ||
    arbitrationId === null ||
    payloadBytes > MAX_CLASSIC_CAN_PAYLOAD_BYTES ||
    !Number.isSafeInteger(input.count) ||
    input.count < 1 ||
    !Number.isSafeInteger(input.intervalMs) ||
    input.intervalMs < 0 ||
    !validPositiveLimit(limits.max_packets) ||
    !validPositiveLimit(limits.max_payload_bytes) ||
    !validPositiveLimit(limits.max_duration_secs) ||
    !validPositiveLimit(limits.max_rate_per_second) ||
    input.count > limits.max_packets
  ) {
    return null;
  }

  const aggregatePayloadBytes = payloadBytes * input.count;
  const durationMs = input.intervalMs * (input.count - 1);
  if (
    !Number.isSafeInteger(aggregatePayloadBytes) ||
    aggregatePayloadBytes > limits.max_payload_bytes ||
    !Number.isSafeInteger(durationMs) ||
    durationMs > limits.max_duration_secs * 1_000
  ) {
    return null;
  }

  const peakRate =
    input.intervalMs === 0
      ? input.count
      : Math.min(input.count, Math.ceil(1_000 / input.intervalMs));
  if (peakRate > limits.max_rate_per_second) return null;

  const steps = Array.from(
    { length: input.count },
    (_, index): AutomotiveReplayStep => ({
      sequence: index,
      delay_micros: index === 0 ? 0 : input.intervalMs * 1_000,
      action: "send",
      message: {
        protocol: "can",
        payload_hex: payloadHex,
        fields: { arbitration_id: String(arbitrationId) },
      },
    }),
  );
  return {
    protocol: "can",
    mode: "virtual_can",
    deterministic_seed: 0,
    steps,
  };
}
