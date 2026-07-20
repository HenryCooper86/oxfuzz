import { useState } from "react";
import { FileJson, Play, Shuffle, Waypoints } from "lucide-react";
import { useI18n } from "../i18nContext";
import { isTauriEnvironment, pickFile } from "../lib";
import {
  buildAutomotiveReplayPlan,
  executeAutomotiveReplay,
  generateAutomotiveMutations,
  type AutomotiveMutationResult,
  type AutomotiveOperationOutcome,
  type AutomotiveProtocol,
  type AutomotiveReplayPlanResult,
  type AutomotiveReplayResult,
  type AutomotiveSettings,
} from "../lib/automotive";
import { useConfirm } from "../providers/confirm";
import { useToast } from "./ui/toastContext";
import { Badge, Button, Input, Select } from "./ui";

interface AutomotiveReplayWorkspaceProps {
  projectRoot: string;
  protocol: AutomotiveProtocol;
  settings: AutomotiveSettings;
  onOperation: () => Promise<void>;
}

function displayPathName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

function boundedInteger(value: string, fallback: number, maximum: number): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0
    ? Math.min(parsed, maximum)
    : fallback;
}

export function AutomotiveReplayWorkspace({
  projectRoot,
  protocol,
  settings,
  onOperation,
}: AutomotiveReplayWorkspaceProps) {
  const { t } = useI18n();
  const confirm = useConfirm();
  const { toast } = useToast();
  const desktop = isTauriEnvironment();
  const [sourcePath, setSourcePath] = useState("");
  const [seed, setSeed] = useState("0");
  const [mutationCount, setMutationCount] = useState("64");
  const [requestedInterface, setRequestedInterface] = useState(
    settings.virtual_interfaces[0] ?? "",
  );
  const [mutationOutcome, setMutationOutcome] = useState<
    AutomotiveOperationOutcome<AutomotiveMutationResult> | null
  >(null);
  const [planOutcome, setPlanOutcome] = useState<
    AutomotiveOperationOutcome<AutomotiveReplayPlanResult> | null
  >(null);
  const [replayOutcome, setReplayOutcome] = useState<
    AutomotiveOperationOutcome<AutomotiveReplayResult> | null
  >(null);
  const [busy, setBusy] = useState<"mutations" | "plan" | "replay" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedInterface = settings.virtual_interfaces.includes(requestedInterface)
    ? requestedInterface
    : (settings.virtual_interfaces[0] ?? "");
  const virtualReady =
    settings.enabled
    && settings.allowed_modes.includes("virtual_can")
    && selectedInterface.length > 0;
  const parsedSeed = boundedInteger(seed, 0, Number.MAX_SAFE_INTEGER);
  const parsedMutationCount = boundedInteger(
    mutationCount,
    64,
    settings.limits.max_packets,
  );

  async function selectTranscript() {
    if (!desktop) return;
    const selected = await pickFile(t("automotive.replay.selectTranscriptTitle"));
    if (selected) {
      setSourcePath(selected);
      setMutationOutcome(null);
      setPlanOutcome(null);
      setReplayOutcome(null);
      setError(null);
    }
  }

  async function generateMutations() {
    if (!sourcePath || busy) return;
    setBusy("mutations");
    setError(null);
    try {
      const outcome = await generateAutomotiveMutations({
        projectRoot,
        protocol,
        sourcePath,
        deterministicSeed: parsedSeed,
        mutationCount: Math.max(1, parsedMutationCount),
        mediaType: "application/vnd.oxfuzz.automotive-transcript+json",
      });
      setMutationOutcome(outcome);
      toast({
        title: t("automotive.replay.mutationsComplete"),
        description: t("automotive.evidenceRetained", { path: outcome.artifact_dir }),
        variant: "success",
      });
      await onOperation();
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({ title: t("automotive.replay.mutationsFailed"), description: message, variant: "error" });
    } finally {
      setBusy(null);
    }
  }

  async function buildPlan() {
    if (!sourcePath || !virtualReady || busy) return;
    setBusy("plan");
    setError(null);
    setReplayOutcome(null);
    try {
      const outcome = await buildAutomotiveReplayPlan({
        projectRoot,
        protocol,
        sourcePath,
        targetMode: "virtual_can",
        deterministicSeed: parsedSeed,
      });
      setPlanOutcome(outcome);
      toast({
        title: t("automotive.replay.planComplete"),
        description: t("automotive.evidenceRetained", { path: outcome.artifact_dir }),
        variant: "success",
      });
      await onOperation();
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({ title: t("automotive.replay.planFailed"), description: message, variant: "error" });
    } finally {
      setBusy(null);
    }
  }

  async function executeVirtualReplay() {
    const plan = planOutcome?.result.data;
    if (!plan || !virtualReady || busy) return;
    const approved = await confirm({
      title: t("automotive.replay.confirmTitle"),
      message: t("automotive.replay.confirmMessage", {
        count: plan.steps.length,
        interface: selectedInterface,
      }),
      confirmLabel: t("automotive.replay.execute"),
      danger: true,
    });
    if (!approved) return;
    setBusy("replay");
    setError(null);
    try {
      const outcome = await executeAutomotiveReplay({
        projectRoot,
        mode: { mode: "virtual_can", interface: selectedInterface },
        plan,
      });
      setReplayOutcome(outcome);
      toast({
        title: t("automotive.replay.complete"),
        description: t("automotive.evidenceRetained", { path: outcome.artifact_dir }),
        variant: "success",
      });
      await onOperation();
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({ title: t("automotive.replay.failed"), description: message, variant: "error" });
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex flex-wrap items-center gap-2">
        <Waypoints size={17} className="text-accent" />
        <h2 className="text-sm font-semibold">{t("automotive.replay.title")}</h2>
        <Badge variant="warning">{t("automotive.replay.virtualOnly")}</Badge>
      </div>
      <p className="text-12px text-text-secondary">{t("automotive.replay.description")}</p>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_10rem_8rem]">
        <div className="flex flex-col gap-1">
          <span className="text-11px font-semibold text-text-muted">
            {t("automotive.replay.transcriptSource")}
          </span>
          <Button
            variant="outline"
            onClick={() => void selectTranscript()}
            disabled={!desktop || !settings.enabled || busy !== null}
          >
            <FileJson size={14} />
            {sourcePath
              ? t("automotive.replay.replaceTranscript")
              : t("automotive.replay.selectTranscript")}
          </Button>
        </div>
        <label className="flex flex-col gap-1 text-11px font-semibold text-text-muted">
          {t("automotive.replay.seed")}
          <Input
            type="number"
            min={0}
            max={Number.MAX_SAFE_INTEGER}
            value={seed}
            onChange={(event) => setSeed(event.target.value)}
            disabled={busy !== null}
          />
        </label>
        <label className="flex flex-col gap-1 text-11px font-semibold text-text-muted">
          {t("automotive.replay.mutationCount")}
          <Input
            type="number"
            min={1}
            max={settings.limits.max_packets}
            value={mutationCount}
            onChange={(event) => setMutationCount(event.target.value)}
            disabled={busy !== null}
          />
        </label>
      </div>

      {sourcePath && (
        <div className="rounded-md bg-surface-primary px-3 py-2 text-12px font-mono text-text-secondary">
          <span title={sourcePath}>{displayPathName(sourcePath)}</span>
        </div>
      )}

      <div className="flex flex-wrap items-end gap-2">
        <Button
          variant="outline"
          loading={busy === "mutations"}
          disabled={!sourcePath || busy !== null}
          onClick={() => void generateMutations()}
        >
          <Shuffle size={14} />
          {t("automotive.replay.generateMutations")}
        </Button>
        <Select
          value={selectedInterface}
          onChange={setRequestedInterface}
          options={settings.virtual_interfaces.map((interfaceName) => ({
            value: interfaceName,
            label: interfaceName,
          }))}
          disabled={!virtualReady || busy !== null}
          className="min-w-32"
        />
        <Button
          variant="outline"
          loading={busy === "plan"}
          disabled={!sourcePath || !virtualReady || busy !== null}
          onClick={() => void buildPlan()}
        >
          <Waypoints size={14} />
          {t("automotive.replay.buildPlan")}
        </Button>
        <Button
          variant="danger"
          loading={busy === "replay"}
          disabled={!planOutcome || !virtualReady || busy !== null}
          onClick={() => void executeVirtualReplay()}
        >
          <Play size={14} />
          {t("automotive.replay.execute")}
        </Button>
      </div>

      {error && <div role="alert" className="text-12px text-error">{error}</div>}

      <div className="flex flex-wrap gap-2 text-11px text-text-secondary">
        {mutationOutcome && (
          <Badge variant="success">
            {t("automotive.replay.mutationResult", {
              count: mutationOutcome.result.data.generated,
            })}
          </Badge>
        )}
        {planOutcome && (
          <Badge variant="accent">
            {t("automotive.replay.planResult", {
              count: planOutcome.result.data.steps.length,
            })}
          </Badge>
        )}
        {replayOutcome && (
          <Badge variant={replayOutcome.result.data.completed ? "success" : "error"}>
            {t("automotive.replay.executionResult", {
              executed: replayOutcome.result.data.executed_events,
              planned: replayOutcome.result.data.planned_events,
            })}
          </Badge>
        )}
      </div>
    </section>
  );
}
