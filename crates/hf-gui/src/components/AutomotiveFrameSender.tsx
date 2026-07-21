import { useState } from "react";
import { Send, ShieldAlert } from "lucide-react";
import { useI18n } from "../i18nContext";
import {
  executeAutomotiveReplay,
  type AutomotiveReplayPlan,
  type AutomotiveReplayStep,
  type AutomotiveSettings,
} from "../lib/automotive";
import { useConfirm } from "../providers/confirm";
import { useToast } from "./ui/toastContext";
import { Badge, Button, Input, Select } from "./ui";

interface AutomotiveFrameSenderProps {
  projectRoot: string;
  settings: AutomotiveSettings;
  onOperation: () => void;
}

/** Normalize a hex payload to lowercase, even-length bytes, or null if invalid. */
function normalizeHex(input: string): string | null {
  const cleaned = input.replace(/[\s_]/g, "").toLowerCase();
  if (cleaned.length === 0 || cleaned.length % 2 !== 0 || !/^[0-9a-f]+$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

/**
 * Periodic frame sender: transmit one CAN frame repeatedly on an allowlisted
 * virtual CAN interface. It builds a replay plan and executes it through the
 * existing replay path, so it inherits the peak-rate guard, guardrails, and the
 * human transmit confirmation. Physical bench is not offered here.
 */
export function AutomotiveFrameSender({
  projectRoot,
  settings,
  onOperation,
}: AutomotiveFrameSenderProps) {
  const { t } = useI18n();
  const { toast } = useToast();
  const confirm = useConfirm();
  const interfaces = settings.virtual_interfaces;
  const [iface, setIface] = useState(interfaces[0] ?? "vcan0");
  const [arbId, setArbId] = useState("0x123");
  const [payload, setPayload] = useState("00");
  const [intervalMs, setIntervalMs] = useState(100);
  const [count, setCount] = useState(10);
  const [busy, setBusy] = useState(false);
  const ready =
    settings.enabled && settings.allowed_modes.includes("virtual_can") && interfaces.length > 0;

  async function send() {
    if (!ready || busy) return;
    const hex = normalizeHex(payload);
    const id = arbId.trim();
    if (!hex || !id || count < 1 || intervalMs < 0) {
      toast({ title: t("automotive.sender.invalid"), variant: "error" });
      return;
    }
    const plan: AutomotiveReplayPlan = {
      protocol: "can",
      mode: "virtual_can",
      deterministic_seed: 0,
      steps: Array.from(
        { length: count },
        (_, index): AutomotiveReplayStep => ({
          sequence: index,
          delay_micros: index === 0 ? 0 : intervalMs * 1000,
          action: "send",
          message: { protocol: "can", payload_hex: hex, fields: { arbitration_id: id } },
        }),
      ),
    };
    const approved = await confirm({
      title: t("automotive.sender.title"),
      message: t("automotive.sender.confirm", { count, interface: iface }),
      confirmLabel: t("automotive.sender.send"),
      danger: true,
    });
    if (!approved) return;
    setBusy(true);
    try {
      const outcome = await executeAutomotiveReplay({
        projectRoot,
        mode: { mode: "virtual_can", interface: iface },
        plan,
      });
      toast({
        title: t("automotive.sender.sent"),
        description: t("automotive.evidenceRetained", { path: outcome.artifact_dir }),
        variant: "success",
      });
      onOperation();
    } catch (reason) {
      toast({ title: t("automotive.sender.failed"), description: String(reason), variant: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center gap-2">
        <Send size={17} className="text-accent" />
        <h2 className="text-sm font-semibold">{t("automotive.sender.title")}</h2>
        <Badge variant="warning">{t("automotive.sender.virtualOnly")}</Badge>
      </div>
      <p className="text-12px text-text-secondary">{t("automotive.sender.description")}</p>

      <div className="flex flex-wrap items-end gap-3">
        <Select
          value={iface}
          onChange={setIface}
          options={interfaces.map((name) => ({ value: name, label: name }))}
          disabled={!ready}
          className="min-w-24"
        />
        <label className="flex flex-col gap-1 text-11px text-text-muted">
          {t("automotive.sender.arbitrationId")}
          <Input
            mono
            value={arbId}
            disabled={!ready}
            onChange={(event) => setArbId(event.target.value)}
            placeholder="0x123"
            className="w-28"
          />
        </label>
        <label className="flex flex-col gap-1 text-11px text-text-muted">
          {t("automotive.sender.payload")}
          <Input
            mono
            value={payload}
            disabled={!ready}
            onChange={(event) => setPayload(event.target.value)}
            placeholder="00 11 22"
            className="w-40"
          />
        </label>
        <label className="flex flex-col gap-1 text-11px text-text-muted">
          {t("automotive.sender.interval")}
          <Input
            mono
            type="number"
            min={0}
            value={intervalMs}
            disabled={!ready}
            onChange={(event) => setIntervalMs(Math.max(0, Number(event.target.value) || 0))}
            className="w-24"
          />
        </label>
        <label className="flex flex-col gap-1 text-11px text-text-muted">
          {t("automotive.sender.count")}
          <Input
            mono
            type="number"
            min={1}
            value={count}
            disabled={!ready}
            onChange={(event) => setCount(Math.max(1, Number(event.target.value) || 1))}
            className="w-20"
          />
        </label>
        <Button variant="primary" loading={busy} disabled={!ready || busy} onClick={() => void send()}>
          {t("automotive.sender.send")}
        </Button>
      </div>

      {!ready && (
        <div className="flex items-start gap-2 text-11px text-text-muted">
          <ShieldAlert size={14} className="shrink-0 text-warning" />
          <span>{t("automotive.sender.gated")}</span>
        </div>
      )}
    </section>
  );
}
