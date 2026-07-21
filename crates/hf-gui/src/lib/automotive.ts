import { getTransport } from "./index";
import type { Transport } from "./transport";

export type AutomotiveProtocol =
  | "can"
  | "can_fd"
  | "iso_tp"
  | "uds"
  | "gmlan"
  | "some_ip"
  | "some_ip_sd"
  | "do_ip"
  | "obd"
  | "ccp"
  | "xcp"
  | "bmw_hsfz"
  | "sec_oc";

export type AutomotiveMode = "offline_pcap" | "virtual_can" | "physical_bench";

export type AutomotiveCapability =
  | "decode_capture"
  | "generate_mutations"
  | "build_replay_plan"
  | "execute_virtual"
  | "execute_physical"
  | "state_feedback";

export interface AutomotiveLimitSettings {
  max_packets: number;
  max_input_bytes: number;
  max_payload_bytes: number;
  max_duration_secs: number;
  max_rate_per_second: number;
  max_output_bytes: number;
  max_mem_mb: number;
  max_cpus: number;
}

export interface AutomotivePhysicalBenchSettings {
  enabled: boolean;
  require_approval: boolean;
  interfaces: string[];
  arbitration_ids: number[];
  uds_services: number[];
  allow_dangerous_services: boolean;
}

export interface AutomotiveSettings {
  enabled: boolean;
  sidecar_image: string;
  allowed_protocols: AutomotiveProtocol[];
  allowed_modes: AutomotiveMode[];
  virtual_interfaces: string[];
  limits: AutomotiveLimitSettings;
  physical_bench: AutomotivePhysicalBenchSettings;
}

export interface AutomotiveStateSignature {
  protocol: string;
  digest: string;
  observations: Record<string, string>;
}

export interface AutomotiveArtifactRef {
  artifact_id: string;
  sha256: string;
  media_type: string;
  size_bytes: number;
}

export interface AutomotiveCapabilityReport {
  adapter_name: string;
  adapter_version: string;
  schema_versions: number[];
  protocols: AutomotiveProtocol[];
  modes: AutomotiveMode[];
  capabilities: AutomotiveCapability[];
  limits: {
    max_events: number;
    max_payload_bytes: number;
    max_duration_ms: number;
    max_rate_per_second: number;
  };
}

export interface AutomotiveCaptureAnalysis {
  protocol: AutomotiveProtocol;
  event_count: number;
  transcript: AutomotiveArtifactRef;
  transcript_hash: string;
  state_signatures: AutomotiveStateSignature[];
}

export interface AutomotiveProtocolMessage {
  protocol: AutomotiveProtocol;
  payload_hex: string;
  fields: Record<string, string>;
}

export interface AutomotiveReplayStep {
  sequence: number;
  delay_micros: number;
  action: "send" | "expect_response";
  message: AutomotiveProtocolMessage;
}

export interface AutomotiveReplayPlan {
  protocol: AutomotiveProtocol;
  mode: "virtual_can" | "physical_bench";
  deterministic_seed: number;
  steps: AutomotiveReplayStep[];
}

export type AutomotiveModeConfig =
  | { mode: "virtual_can"; interface: string }
  | { mode: "physical_bench"; interface: string; approval_id: string };

export interface AutomotiveReplay {
  protocol: AutomotiveProtocol;
  mode: "virtual_can" | "physical_bench";
  planned_events: number;
  executed_events: number;
  transcript_hash: string;
  state_signatures: AutomotiveStateSignature[];
  completed: boolean;
}

export interface AutomotiveMutation {
  protocol: AutomotiveProtocol;
  generated: number;
  transcript_hash: string | null;
  artifacts: AutomotiveArtifactRef[];
}

export type AutomotiveCapabilitiesResult = {
  result: "capabilities";
  data: AutomotiveCapabilityReport;
};

export type AutomotiveCaptureAnalysisResult = {
  result: "capture_analysis";
  data: AutomotiveCaptureAnalysis;
};

export type AutomotiveReplayResult = {
  result: "replay";
  data: AutomotiveReplay;
};

export type AutomotiveMutationResult = {
  result: "mutations";
  data: AutomotiveMutation;
};

export type AutomotiveReplayPlanResult = {
  result: "replay_plan";
  data: AutomotiveReplayPlan;
};

export type AutomotiveFrontendResult =
  | AutomotiveCapabilitiesResult
  | AutomotiveCaptureAnalysisResult
  | AutomotiveMutationResult
  | AutomotiveReplayPlanResult
  | AutomotiveReplayResult;

export interface AutomotiveOperationOutcome<
  TResult extends AutomotiveFrontendResult = AutomotiveFrontendResult,
> {
  operation_id: string;
  result: TResult;
  transcript_sha256: string | null;
  artifact_dir: string;
}

export type AutomotiveOperationStatus =
  | "running"
  | "done"
  | "failed"
  | "cancelled";

export interface AutomotiveOperationSummary {
  id: string;
  project_root: string;
  operation: string;
  mode: string;
  protocol: string | null;
  status: AutomotiveOperationStatus;
  started_at: string;
  ended_at: string | null;
  transcript_sha256: string | null;
  artifact_dir: string;
  error: string | null;
  state_signatures: AutomotiveStateSignature[];
}

export type AutomotiveReportAiStatus =
  | "not_requested"
  | "not_configured"
  | "not_applicable"
  | "applied"
  | "fallback";

export interface AutomotiveCampaignReport {
  generated_at: string;
  project_name: string;
  ai_status: AutomotiveReportAiStatus;
  ai_model: string | null;
  operation_count: number;
  failed_operation_count: number;
  unique_state_count: number;
  promoted_state_count: number;
  markdown: string;
}

export interface AnalyzeAutomotiveCaptureInput {
  projectRoot: string;
  protocol: AutomotiveProtocol;
  capturePath: string;
}

export interface ExecuteAutomotiveReplayInput {
  projectRoot: string;
  mode: AutomotiveModeConfig;
  plan: AutomotiveReplayPlan;
}

export interface GenerateAutomotiveMutationsInput {
  projectRoot: string;
  protocol: AutomotiveProtocol;
  sourcePath: string;
  deterministicSeed: number;
  mutationCount: number;
  mediaType: string;
}

export interface BuildAutomotiveReplayPlanInput {
  projectRoot: string;
  protocol: AutomotiveProtocol;
  sourcePath: string;
  targetMode: "virtual_can" | "physical_bench";
  deterministicSeed: number;
}

export function getAutomotiveSettings(
  transport: Transport = getTransport(),
): Promise<AutomotiveSettings> {
  return transport.invoke<AutomotiveSettings>("get_automotive_settings");
}

export function setAutomotiveSettings(
  settings: AutomotiveSettings,
  transport: Transport = getTransport(),
): Promise<AutomotiveSettings> {
  return transport.invoke<AutomotiveSettings>("set_automotive_settings", { settings });
}

export function inspectAutomotiveCapabilities(
  projectRoot: string,
  transport: Transport = getTransport(),
): Promise<AutomotiveOperationOutcome<AutomotiveCapabilitiesResult>> {
  return transport.invoke<AutomotiveOperationOutcome<AutomotiveCapabilitiesResult>>(
    "automotive_capabilities",
    { projectRoot },
  );
}

export function analyzeAutomotiveCapture(
  input: AnalyzeAutomotiveCaptureInput,
  transport: Transport = getTransport(),
): Promise<AutomotiveOperationOutcome<AutomotiveCaptureAnalysisResult>> {
  return transport.invoke<AutomotiveOperationOutcome<AutomotiveCaptureAnalysisResult>>(
    "automotive_analyze_capture",
    { ...input },
  );
}

export function executeAutomotiveReplay(
  input: ExecuteAutomotiveReplayInput,
  transport: Transport = getTransport(),
): Promise<AutomotiveOperationOutcome<AutomotiveReplayResult>> {
  return transport.invoke<AutomotiveOperationOutcome<AutomotiveReplayResult>>(
    "automotive_execute_replay",
    { ...input },
  );
}

export function generateAutomotiveMutations(
  input: GenerateAutomotiveMutationsInput,
  transport: Transport = getTransport(),
): Promise<AutomotiveOperationOutcome<AutomotiveMutationResult>> {
  return transport.invoke<AutomotiveOperationOutcome<AutomotiveMutationResult>>(
    "automotive_generate_mutations",
    { ...input },
  );
}

export function buildAutomotiveReplayPlan(
  input: BuildAutomotiveReplayPlanInput,
  transport: Transport = getTransport(),
): Promise<AutomotiveOperationOutcome<AutomotiveReplayPlanResult>> {
  return transport.invoke<AutomotiveOperationOutcome<AutomotiveReplayPlanResult>>(
    "automotive_build_replay_plan",
    { ...input },
  );
}

export function listAutomotiveOperations(
  projectRoot: string,
  limit: number,
  transport: Transport = getTransport(),
): Promise<AutomotiveOperationSummary[]> {
  return transport.invoke<AutomotiveOperationSummary[]>("list_automotive_operations", {
    projectRoot,
    limit,
  });
}

export function generateAutomotiveReport(
  projectRoot: string,
  includeAi: boolean,
  transport: Transport = getTransport(),
): Promise<AutomotiveCampaignReport> {
  return transport.invoke<AutomotiveCampaignReport>("generate_automotive_report", {
    projectRoot,
    includeAi,
  });
}

// --- Offline analysis (SavvyCAN-inspired: import, DBC decode, sniffer, diff) ---

export type OfflineCaptureFormat = "candump" | "vector_asc" | "crtd" | "gvret_csv";

export interface DecodedSignalView {
  name: string;
  value: number;
  unit: string;
  label: string | null;
}

export interface OfflineFrameView {
  timestamp_micros: number;
  channel: string;
  id: number;
  extended: boolean;
  fd: boolean;
  kind: string;
  data_hex: string;
  direction: string | null;
  message: string | null;
  signals: DecodedSignalView[];
}

export interface OfflineIdStat {
  id: number;
  extended: boolean;
  count: number;
  avg_period_micros: number | null;
}

export interface OfflineChangeMap {
  id: number;
  extended: boolean;
  observations: number;
  byte_changed: boolean[];
  distinct_values: number[];
}

export interface CaptureImport {
  format: string;
  frame_count: number;
  truncated: boolean;
  dbc_message_count: number;
  unique_ids: number;
  duration_micros: number;
  frames_per_second: number;
  frames: OfflineFrameView[];
  per_id: OfflineIdStat[];
  change_maps: OfflineChangeMap[];
}

export interface CaptureDiffView {
  only_in_first: number[];
  only_in_second: number[];
  changed: number[];
}

export interface ImportAutomotiveCaptureInput {
  capturePath: string;
  format: OfflineCaptureFormat;
  dbcPath?: string | null;
}

export function importAutomotiveCapture(
  input: ImportAutomotiveCaptureInput,
  transport: Transport = getTransport(),
): Promise<CaptureImport> {
  return transport.invoke<CaptureImport>("automotive_import_capture", {
    capturePath: input.capturePath,
    format: input.format,
    dbcPath: input.dbcPath ?? null,
  });
}

export interface DiffAutomotiveCapturesInput {
  firstPath: string;
  secondPath: string;
  format: OfflineCaptureFormat;
}

export function diffAutomotiveCaptures(
  input: DiffAutomotiveCapturesInput,
  transport: Transport = getTransport(),
): Promise<CaptureDiffView> {
  return transport.invoke<CaptureDiffView>("automotive_diff_captures", {
    firstPath: input.firstPath,
    secondPath: input.secondPath,
    format: input.format,
  });
}

export const OFFLINE_CAPTURE_FORMAT_OPTIONS: { value: OfflineCaptureFormat; label: string }[] = [
  { value: "candump", label: "candump (SocketCAN)" },
  { value: "vector_asc", label: "Vector ASC" },
  { value: "crtd", label: "CRTD (OVMS)" },
  { value: "gvret_csv", label: "GVRET CSV" },
];

export interface LiveMonitorInput {
  projectRoot: string;
  /** Allowlisted virtual CAN interface, e.g. vcan0. */
  interface: string;
  protocol?: AutomotiveProtocol;
}

/**
 * Run a bounded, read-only live capture on a virtual CAN interface. Returns the
 * retained capture-analysis operation outcome (transcript + state signatures).
 */
export function liveMonitorAutomotive(
  input: LiveMonitorInput,
  transport: Transport = getTransport(),
): Promise<AutomotiveOperationOutcome<AutomotiveCaptureAnalysisResult>> {
  return transport.invoke<AutomotiveOperationOutcome<AutomotiveCaptureAnalysisResult>>(
    "automotive_live_monitor",
    {
      projectRoot: input.projectRoot,
      interface: input.interface,
      protocol: input.protocol ?? "can",
    },
  );
}
